package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/bbbkawaii/GrokSwitch/internal/accounts"
	"github.com/bbbkawaii/GrokSwitch/internal/billing"
	"github.com/bbbkawaii/GrokSwitch/internal/filelock"
	"github.com/bbbkawaii/GrokSwitch/internal/fsutil"
	"github.com/bbbkawaii/GrokSwitch/internal/grokauth"
)

var (
	ErrNoCurrentAuth = errors.New("no active Grok login found")
	ErrNoAccounts    = errors.New("no saved accounts")
	ErrNotFound      = errors.New("account not found")
	ErrAmbiguous     = errors.New("account query is ambiguous")
)

type App struct {
	Paths             accounts.Paths
	Store             *accounts.Store
	In                io.Reader
	Out               io.Writer
	ErrOut            io.Writer
	Now               func() time.Time
	HTTPClient        *http.Client
	BillingURL        string
	UserURL           string
	GrokClientVersion string
}

func New(paths accounts.Paths, in io.Reader, out, errOut io.Writer) *App {
	return &App{
		Paths:      paths,
		Store:      accounts.New(paths),
		In:         in,
		Out:        out,
		ErrOut:     errOut,
		Now:        time.Now,
		HTTPClient: &http.Client{Timeout: 15 * time.Second},
		BillingURL: billing.DefaultURL,
		UserURL:    billing.DefaultUserURL,
	}
}

type AccountList struct {
	Registry        *accounts.Registry
	CurrentAccount  string
	CurrentIdentity *grokauth.Identity
	CurrentError    error
}

func (a *App) List() (*AccountList, error) {
	reg, err := a.Store.Load()
	if err != nil {
		return nil, err
	}
	result := &AccountList{Registry: reg}
	current, err := a.readAuth(a.Paths.ActiveAuth)
	if err == nil {
		result.CurrentIdentity = &current.Identity
		if accounts.IndexByID(reg, current.Identity.ID) >= 0 {
			result.CurrentAccount = current.Identity.ID
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		result.CurrentError = err
	}
	return result, nil
}

// FetchQuotas reads each saved account's current bearer and fetches its live
// subscription tier plus the credits data used by Grok Build's /usage view.
// Failures are isolated per account and endpoint so a network or auth problem
// never prevents listing or switching.
func (a *App) FetchQuotas(list *AccountList) map[string]billing.Quota {
	results := make(map[string]billing.Quota, len(list.Registry.Accounts))
	if len(list.Registry.Accounts) == 0 {
		return results
	}
	clientVersion := strings.TrimSpace(a.GrokClientVersion)
	if clientVersion == "" {
		clientVersion = installedGrokVersion()
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)
	for _, account := range list.Registry.Accounts {
		account := account
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			authFile, err := a.quotaAuthFile(account.ID, list.CurrentAccount)
			if err != nil {
				mu.Lock()
				results[account.ID] = billing.Quota{Error: err.Error()}
				mu.Unlock()
				return
			}
			credential, ok := authFile.XAIRequestCredential()
			if !ok {
				mu.Lock()
				results[account.ID] = billing.Quota{Error: "quota requires a first-party xAI OIDC login"}
				mu.Unlock()
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			type quotaResult struct {
				quota billing.Quota
				err   error
			}
			type tierResult struct {
				tier string
				err  error
			}
			quotaCh := make(chan quotaResult, 1)
			tierCh := make(chan tierResult, 1)
			go func() {
				quota, err := billing.Fetch(ctx, a.HTTPClient, a.BillingURL, clientVersion, credential.AccessToken, credential.UserID)
				quotaCh <- quotaResult{quota: quota, err: err}
			}()
			go func() {
				tier, err := billing.FetchTier(ctx, a.HTTPClient, a.UserURL, clientVersion, credential.AccessToken)
				tierCh <- tierResult{tier: tier, err: err}
			}()
			quotaFetch := <-quotaCh
			tierFetch := <-tierCh
			cancel()
			quota := quotaFetch.quota
			if quotaFetch.err != nil {
				quota.Error = quotaFetch.err.Error()
			}
			if tierFetch.err != nil {
				quota.TierError = tierFetch.err.Error()
			} else {
				quota.Tier = tierFetch.tier
			}
			mu.Lock()
			results[account.ID] = quota
			mu.Unlock()
		}()
	}
	wg.Wait()
	return results
}

func (a *App) quotaAuthFile(accountID, currentID string) (*grokauth.File, error) {
	if accountID == currentID {
		current, err := a.readAuth(a.Paths.ActiveAuth)
		if err == nil && current.Identity.ID == accountID {
			return current, nil
		}
	}
	data, err := a.Store.ReadSnapshot(accountID)
	if err != nil {
		return nil, err
	}
	authFile, err := grokauth.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("parse quota credential: %w", err)
	}
	if authFile.Identity.ID != accountID {
		return nil, errors.New("quota credential identity does not match registry")
	}
	return authFile, nil
}

func installedGrokVersion() string {
	grokBin, err := findGrok()
	if err != nil {
		return ""
	}
	output, err := CommandOutput(grokBin, "--version")
	if err != nil {
		return ""
	}
	fields := strings.Fields(output)
	if len(fields) >= 2 && strings.EqualFold(fields[0], "grok") {
		return fields[1]
	}
	return ""
}

func (a *App) CaptureCurrent(alias string) (*accounts.Account, bool, error) {
	var saved *accounts.Account
	var created bool
	err := a.withManagerLock(func(reg *accounts.Registry) error {
		current, err := a.readAuth(a.Paths.ActiveAuth)
		if errors.Is(err, os.ErrNotExist) {
			return ErrNoCurrentAuth
		}
		if err != nil {
			return err
		}
		sessionLock, err := a.acquireSessionLock(current.Identity.ID)
		if err != nil {
			return err
		}
		defer sessionLock.Release()
		var account *accounts.Account
		var wasCreated bool
		if err := a.withAccountLock(current.Identity.ID, func() error {
			var upsertErr error
			account, wasCreated, upsertErr = a.Store.Upsert(reg, current, alias, a.Now())
			return upsertErr
		}); err != nil {
			return err
		}
		a.setActive(reg, account.ID)
		reg.Accounts[accounts.IndexByID(reg, account.ID)].LastUsedAt = a.Now().UTC().Format(time.RFC3339)
		if err := a.Store.Save(reg); err != nil {
			return err
		}
		copyOf := *account
		saved = &copyOf
		created = wasCreated
		return nil
	})
	return saved, created, err
}

func (a *App) Import(path, alias string, activate bool) (*accounts.Account, bool, error) {
	data, err := readImportFile(path)
	if err != nil {
		return nil, false, err
	}
	authFile, err := grokauth.Parse(data)
	if err != nil {
		return nil, false, fmt.Errorf("validate imported auth file: %w", err)
	}
	return a.importValidated(authFile, alias, activate)
}

func (a *App) ImportCPA(path, alias string, activate bool) (*accounts.Account, bool, grokauth.CPAInfo, error) {
	data, err := readImportFile(path)
	if err != nil {
		return nil, false, grokauth.CPAInfo{}, err
	}
	authFile, info, err := grokauth.ConvertCPA(data, a.Now())
	if err != nil {
		return nil, false, info, fmt.Errorf("convert CPA auth file: %w", err)
	}
	account, created, err := a.importValidated(authFile, alias, activate)
	return account, created, info, err
}

func (a *App) importValidated(authFile *grokauth.File, alias string, activate bool) (*accounts.Account, bool, error) {
	var saved *accounts.Account
	var created bool
	err := a.withManagerLock(func(reg *accounts.Registry) error {
		if activate {
			if _, err := a.syncCurrent(reg); err != nil && !errors.Is(err, ErrNoCurrentAuth) {
				return err
			}
		}
		sessionLock, err := a.acquireSessionLock(authFile.Identity.ID)
		if err != nil {
			return err
		}
		defer sessionLock.Release()
		var account *accounts.Account
		var wasCreated bool
		if err := a.withAccountLock(authFile.Identity.ID, func() error {
			var upsertErr error
			account, wasCreated, upsertErr = a.Store.Upsert(reg, authFile, alias, a.Now())
			if upsertErr != nil {
				return upsertErr
			}
			if activate {
				return a.activateFile(reg, account.ID, authFile.Raw)
			}
			return nil
		}); err != nil {
			return err
		}
		if err := a.Store.Save(reg); err != nil {
			return err
		}
		idx := accounts.IndexByID(reg, account.ID)
		copyOf := reg.Accounts[idx]
		saved = &copyOf
		created = wasCreated
		return nil
	})
	return saved, created, err
}

func (a *App) Login(alias string, deviceAuth bool) (*accounts.Account, bool, error) {
	if err := a.Store.Ensure(); err != nil {
		return nil, false, err
	}
	tempDir, err := os.MkdirTemp(a.Paths.StoreRoot, ".login-")
	if err != nil {
		return nil, false, fmt.Errorf("create isolated login directory: %w", err)
	}
	_ = os.Chmod(tempDir, 0o700)
	defer os.RemoveAll(tempDir)
	scratchAuth := filepath.Join(tempDir, "auth.json")

	grokBin, err := findGrok()
	if err != nil {
		return nil, false, err
	}
	args := []string{"login"}
	if deviceAuth {
		args = append(args, "--device-auth")
	}
	command := exec.Command(grokBin, args...)
	command.Stdin = a.In
	command.Stdout = a.Out
	command.Stderr = a.ErrOut
	command.Env = selectedAccountEnv(os.Environ(), scratchAuth)
	if err := command.Run(); err != nil {
		return nil, false, fmt.Errorf("grok login failed: %w", err)
	}

	data, err := fsutil.ReadPrivateFile(scratchAuth)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, errors.New("grok login completed without creating an auth file")
	}
	if err != nil {
		return nil, false, fmt.Errorf("read isolated login result: %w", err)
	}
	authFile, err := grokauth.Parse(data)
	if err != nil {
		return nil, false, fmt.Errorf("validate login result: %w", err)
	}
	return a.importValidated(authFile, alias, true)
}

func (a *App) Switch(query string) (*accounts.Account, error) {
	if strings.TrimSpace(os.Getenv("GROK_AUTH")) != "" {
		return nil, errors.New("GROK_AUTH is set and overrides auth.json; unset it before switching accounts")
	}
	var selected *accounts.Account
	err := a.withManagerLock(func(reg *accounts.Registry) error {
		if _, err := a.syncCurrent(reg); err != nil && !errors.Is(err, ErrNoCurrentAuth) {
			return err
		}
		idx, err := resolveOne(reg, query)
		if err != nil {
			return err
		}
		target := reg.Accounts[idx]
		sessionLock, err := a.acquireSessionLock(target.ID)
		if err != nil {
			return err
		}
		defer sessionLock.Release()
		if err := a.withAccountLock(target.ID, func() error {
			data, err := a.Store.ReadSnapshot(target.ID)
			if err != nil {
				return err
			}
			parsed, err := grokauth.Parse(data)
			if err != nil {
				return fmt.Errorf("saved auth for %s is invalid: %w", target.Alias, err)
			}
			if parsed.Identity.ID != target.ID {
				return fmt.Errorf("saved auth identity mismatch for %s", target.Alias)
			}
			if reg.ActiveAccountID != target.ID || !a.activeFileMatches(target.ID) {
				return a.activateFile(reg, target.ID, data)
			}
			return nil
		}); err != nil {
			return err
		}
		idx = accounts.IndexByID(reg, target.ID)
		reg.Accounts[idx].LastUsedAt = a.Now().UTC().Format(time.RFC3339)
		if err := a.Store.Save(reg); err != nil {
			return fmt.Errorf("account switched but registry update failed: %w", err)
		}
		copyOf := reg.Accounts[idx]
		selected = &copyOf
		return nil
	})
	return selected, err
}

func (a *App) Previous() (*accounts.Account, error) {
	var selected *accounts.Account
	err := a.withManagerLock(func(reg *accounts.Registry) error {
		if _, err := a.syncCurrent(reg); err != nil && !errors.Is(err, ErrNoCurrentAuth) {
			return err
		}
		previousID := reg.PreviousAccountID
		if previousID == "" || previousID == reg.ActiveAccountID {
			return errors.New("no previous account is available")
		}
		idx := accounts.IndexByID(reg, previousID)
		if idx < 0 {
			return errors.New("the previous account is no longer saved")
		}
		sessionLock, err := a.acquireSessionLock(previousID)
		if err != nil {
			return err
		}
		defer sessionLock.Release()
		if err := a.withAccountLock(previousID, func() error {
			data, err := a.Store.ReadSnapshot(previousID)
			if err != nil {
				return err
			}
			return a.activateFile(reg, previousID, data)
		}); err != nil {
			return err
		}
		idx = accounts.IndexByID(reg, previousID)
		reg.Accounts[idx].LastUsedAt = a.Now().UTC().Format(time.RFC3339)
		if err := a.Store.Save(reg); err != nil {
			return fmt.Errorf("account switched but registry update failed: %w", err)
		}
		copyOf := reg.Accounts[idx]
		selected = &copyOf
		return nil
	})
	return selected, err
}

func (a *App) Rename(query, alias string) (*accounts.Account, error) {
	if err := accounts.ValidateAlias(alias); err != nil {
		return nil, err
	}
	var renamed *accounts.Account
	err := a.withManagerLock(func(reg *accounts.Registry) error {
		idx, err := resolveOne(reg, query)
		if err != nil {
			return err
		}
		if conflict := accounts.IndexByAlias(reg, alias); conflict >= 0 && conflict != idx {
			return fmt.Errorf("alias %q is already used by another account", alias)
		}
		reg.Accounts[idx].Alias = strings.TrimSpace(alias)
		reg.Accounts[idx].UpdatedAt = a.Now().UTC().Format(time.RFC3339)
		if err := a.Store.Save(reg); err != nil {
			return err
		}
		copyOf := reg.Accounts[idx]
		renamed = &copyOf
		return nil
	})
	return renamed, err
}

func (a *App) Remove(query string) (*accounts.Account, string, error) {
	var removed *accounts.Account
	var activatedAlias string
	err := a.withManagerLock(func(reg *accounts.Registry) error {
		if _, err := a.syncCurrent(reg); err != nil && !errors.Is(err, ErrNoCurrentAuth) {
			return err
		}
		idx, err := resolveOne(reg, query)
		if err != nil {
			return err
		}
		target := reg.Accounts[idx]
		copyOf := target
		removed = &copyOf
		sessionLock, err := a.acquireSessionLock(target.ID)
		if err != nil {
			return err
		}
		defer sessionLock.Release()

		snapshotLockPath, err := a.Store.AuthLockPath(target.ID)
		if err != nil {
			return err
		}
		snapshotLock, err := filelock.Acquire(snapshotLockPath, 2*time.Second, true)
		if err != nil {
			return fmt.Errorf("account %s is in use; close its Grok process and retry: %w", target.Alias, err)
		}
		defer snapshotLock.Release()

		wasActive := reg.ActiveAccountID == target.ID || a.activeFileMatches(target.ID)
		reg.Accounts = append(reg.Accounts[:idx], reg.Accounts[idx+1:]...)
		if reg.PreviousAccountID == target.ID {
			reg.PreviousAccountID = ""
		}

		if wasActive {
			nextID := ""
			if reg.PreviousAccountID != "" && accounts.IndexByID(reg, reg.PreviousAccountID) >= 0 {
				nextID = reg.PreviousAccountID
			} else if len(reg.Accounts) > 0 {
				nextID = reg.Accounts[0].ID
			}
			if nextID == "" {
				if err := a.clearActiveFile(); err != nil {
					return err
				}
				reg.ActiveAccountID = ""
				reg.PreviousAccountID = ""
			} else {
				fallbackSessionLock, err := a.acquireSessionLock(nextID)
				if err != nil {
					return err
				}
				defer fallbackSessionLock.Release()
				data, err := a.Store.ReadSnapshot(nextID)
				if err != nil {
					return err
				}
				if err := a.activateFileWithoutCapture(reg, nextID, data); err != nil {
					return err
				}
				nextIdx := accounts.IndexByID(reg, nextID)
				reg.Accounts[nextIdx].LastUsedAt = a.Now().UTC().Format(time.RFC3339)
				activatedAlias = reg.Accounts[nextIdx].Alias
			}
		}

		if err := a.Store.Save(reg); err != nil {
			return err
		}
		if err := snapshotLock.Release(); err != nil {
			return err
		}
		if err := sessionLock.Release(); err != nil {
			return err
		}
		if err := a.Store.RemoveSnapshot(target.ID); err != nil {
			return fmt.Errorf("registry updated but failed to remove account files: %w", err)
		}
		return nil
	})
	return removed, activatedAlias, err
}

func (a *App) RunAccount(query string, grokArgs []string) error {
	var snapshot string
	var accountID string
	var sessionLock *filelock.Lock
	err := a.withManagerLock(func(reg *accounts.Registry) error {
		idx, err := resolveOne(reg, query)
		if err != nil {
			return err
		}
		accountID = reg.Accounts[idx].ID
		if current, currentErr := a.readAuth(a.Paths.ActiveAuth); currentErr == nil && current.Identity.ID == accountID {
			return fmt.Errorf("account %s is already globally active; run 'grok' directly", reg.Accounts[idx].Alias)
		} else if currentErr != nil && !errors.Is(currentErr, os.ErrNotExist) {
			return currentErr
		}
		var lockErr error
		sessionLock, lockErr = a.acquireSessionLock(accountID)
		if lockErr != nil {
			return lockErr
		}
		path, err := a.Store.SnapshotPath(accountID)
		if err != nil {
			return err
		}
		data, err := a.Store.ReadSnapshot(accountID)
		if err != nil {
			return err
		}
		parsed, err := grokauth.Parse(data)
		if err != nil || parsed.Identity.ID != accountID {
			return fmt.Errorf("saved auth for %s is invalid", reg.Accounts[idx].Alias)
		}
		snapshot = path
		reg.Accounts[idx].LastUsedAt = a.Now().UTC().Format(time.RFC3339)
		return a.Store.Save(reg)
	})
	if err != nil {
		if sessionLock != nil {
			_ = sessionLock.Release()
		}
		return err
	}
	defer sessionLock.Release()

	grokBin, err := findGrok()
	if err != nil {
		return err
	}
	command := exec.Command(grokBin, grokArgs...)
	command.Stdin = a.In
	command.Stdout = a.Out
	command.Stderr = a.ErrOut
	command.Env = selectedAccountEnv(os.Environ(), snapshot)
	runErr := command.Run()

	// Grok may refresh or enrich auth.json while it runs. Refresh only the
	// public registry metadata after the child exits; token bytes stay private.
	_ = a.withManagerLock(func(reg *accounts.Registry) error {
		data, err := a.Store.ReadSnapshot(accountID)
		if err != nil {
			return err
		}
		parsed, err := grokauth.Parse(data)
		if err != nil || parsed.Identity.ID != accountID {
			return nil
		}
		if err := a.withAccountLock(accountID, func() error {
			_, _, upsertErr := a.Store.Upsert(reg, parsed, "", a.Now())
			return upsertErr
		}); err != nil {
			return err
		}
		idx := accounts.IndexByID(reg, accountID)
		reg.Accounts[idx].LastUsedAt = a.Now().UTC().Format(time.RFC3339)
		return a.Store.Save(reg)
	})
	return runErr
}

func (a *App) syncCurrent(reg *accounts.Registry) (*accounts.Account, error) {
	current, err := a.readAuth(a.Paths.ActiveAuth)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoCurrentAuth
	}
	if err != nil {
		return nil, err
	}
	var account *accounts.Account
	if err := a.withAccountLock(current.Identity.ID, func() error {
		var upsertErr error
		account, _, upsertErr = a.Store.Upsert(reg, current, "", a.Now())
		return upsertErr
	}); err != nil {
		return nil, err
	}
	a.setActive(reg, account.ID)
	return account, nil
}

func (a *App) activateFile(reg *accounts.Registry, accountID string, data []byte) error {
	return a.activateFileWithCapture(reg, accountID, data, true)
}

func (a *App) activateFileWithoutCapture(reg *accounts.Registry, accountID string, data []byte) error {
	return a.activateFileWithCapture(reg, accountID, data, false)
}

func (a *App) activateFileWithCapture(reg *accounts.Registry, accountID string, data []byte, captureCurrent bool) error {
	if inline := strings.TrimSpace(os.Getenv("GROK_AUTH")); inline != "" {
		return errors.New("GROK_AUTH is set and overrides auth.json; unset it before switching accounts")
	}
	if a.activeInsideStore() {
		return errors.New("GROK_AUTH_PATH points inside GrokSwitch's managed account store; unset it before global switching")
	}
	lockPath := filepath.Join(filepath.Dir(a.Paths.ActiveAuth), "auth.json.lock")
	lock, err := filelock.Acquire(lockPath, 5*time.Second, true)
	if err != nil {
		return fmt.Errorf("Grok is refreshing credentials; retry shortly or close running Grok sessions: %w", err)
	}
	defer lock.Release()
	// Re-capture the current file while holding Grok's own auth lock. This
	// closes the race where a running Grok process rotates a refresh token
	// between the earlier registry sync and this replacement.
	if captureCurrent {
		if current, currentErr := a.readAuth(a.Paths.ActiveAuth); currentErr == nil {
			// Callers hold the target account's snapshot lock. If the active
			// file is already that identity, do not recursively take the same
			// lock; the caller's selected source remains authoritative.
			if current.Identity.ID != accountID {
				if err := a.withAccountLock(current.Identity.ID, func() error {
					_, _, upsertErr := a.Store.Upsert(reg, current, "", a.Now())
					return upsertErr
				}); err != nil {
					return err
				}
				a.setActive(reg, current.Identity.ID)
			}
		} else if !errors.Is(currentErr, os.ErrNotExist) {
			return currentErr
		}
	}
	if err := fsutil.AtomicWrite(a.Paths.ActiveAuth, data, 0o600); err != nil {
		return fmt.Errorf("replace active Grok auth: %w", err)
	}
	a.setActive(reg, accountID)
	return nil
}

func (a *App) clearActiveFile() error {
	if a.activeInsideStore() {
		return errors.New("GROK_AUTH_PATH points inside GrokSwitch's managed account store; unset it before removing the active account")
	}
	lockPath := filepath.Join(filepath.Dir(a.Paths.ActiveAuth), "auth.json.lock")
	lock, err := filelock.Acquire(lockPath, 5*time.Second, true)
	if err != nil {
		return fmt.Errorf("Grok is refreshing credentials; retry shortly or close running Grok sessions: %w", err)
	}
	defer lock.Release()
	err = os.Remove(a.Paths.ActiveAuth)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (a *App) setActive(reg *accounts.Registry, accountID string) {
	if reg.ActiveAccountID != "" && reg.ActiveAccountID != accountID {
		reg.PreviousAccountID = reg.ActiveAccountID
	}
	reg.ActiveAccountID = accountID
}

func (a *App) activeFileMatches(accountID string) bool {
	current, err := a.readAuth(a.Paths.ActiveAuth)
	return err == nil && current.Identity.ID == accountID
}

func (a *App) activeInsideStore() bool {
	rel, err := filepath.Rel(a.Paths.StoreRoot, a.Paths.ActiveAuth)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)))
}

func (a *App) readAuth(path string) (*grokauth.File, error) {
	data, err := fsutil.ReadPrivateFile(path)
	if err != nil {
		return nil, err
	}
	authFile, err := grokauth.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return authFile, nil
}

func (a *App) withManagerLock(fn func(*accounts.Registry) error) error {
	if err := a.Store.Ensure(); err != nil {
		return err
	}
	lock, err := filelock.Acquire(a.Paths.ManagerLock, 5*time.Second, false)
	if err != nil {
		return fmt.Errorf("another GrokSwitch operation is running: %w", err)
	}
	defer lock.Release()
	reg, err := a.Store.Load()
	if err != nil {
		return err
	}
	return fn(reg)
}

func (a *App) withAccountLock(accountID string, fn func() error) error {
	lockPath, err := a.Store.AuthLockPath(accountID)
	if err != nil {
		return err
	}
	lock, err := filelock.Acquire(lockPath, 5*time.Second, true)
	if err != nil {
		return fmt.Errorf("account credentials are being refreshed; retry shortly: %w", err)
	}
	defer lock.Release()
	return fn()
}

func (a *App) acquireSessionLock(accountID string) (*filelock.Lock, error) {
	path, err := a.Store.SessionLockPath(accountID)
	if err != nil {
		return nil, err
	}
	lock, err := filelock.Acquire(path, 250*time.Millisecond, false)
	if err != nil {
		return nil, fmt.Errorf("account is in use by 'grok-switch run'; close that process and retry: %w", err)
	}
	return lock, nil
}

func resolveOne(reg *accounts.Registry, query string) (int, error) {
	if len(reg.Accounts) == 0 {
		return -1, ErrNoAccounts
	}
	resolution := accounts.Resolve(reg, query)
	if resolution.Index >= 0 {
		return resolution.Index, nil
	}
	if len(resolution.Matches) > 1 {
		aliases := make([]string, 0, len(resolution.Matches))
		for _, idx := range resolution.Matches {
			aliases = append(aliases, reg.Accounts[idx].Alias)
		}
		return -1, fmt.Errorf("%w: %q matches %s", ErrAmbiguous, query, strings.Join(aliases, ", "))
	}
	return -1, fmt.Errorf("%w: %q", ErrNotFound, query)
}

func readImportFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open import file: %w", err)
	}
	defer file.Close()
	const max = 8 << 20
	data, err := io.ReadAll(io.LimitReader(file, max+1))
	if err != nil {
		return nil, fmt.Errorf("read import file: %w", err)
	}
	if len(data) > max {
		return nil, errors.New("import file exceeds 8 MiB")
	}
	return data, nil
}

func findGrok() (string, error) {
	if configured := strings.TrimSpace(os.Getenv("GROK_SWITCH_GROK_BIN")); configured != "" {
		return configured, nil
	}
	path, err := exec.LookPath("grok")
	if err != nil {
		return "", errors.New("grok executable was not found in PATH; install Grok Build first")
	}
	return path, nil
}

func selectedAccountEnv(current []string, authPath string) []string {
	remove := map[string]bool{
		"grok_auth":             true,
		"grok_auth_path":        true,
		"xai_api_key":           true,
		"grok_code_xai_api_key": true,
	}
	env := make([]string, 0, len(current)+1)
	for _, entry := range current {
		key, _, ok := strings.Cut(entry, "=")
		if ok && remove[strings.ToLower(key)] {
			continue
		}
		env = append(env, entry)
	}
	return append(env, "GROK_AUTH_PATH="+authPath)
}

// CommandOutput returns a bounded command output for doctor/status checks.
func CommandOutput(name string, args ...string) (string, error) {
	command := exec.Command(name, args...)
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	err := command.Run()
	value := strings.TrimSpace(output.String())
	if len(value) > 4096 {
		value = value[:4096]
	}
	return value, err
}
