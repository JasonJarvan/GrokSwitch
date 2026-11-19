package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/JasonJarvan/GrokSwitch/internal/accounts"
	"github.com/JasonJarvan/GrokSwitch/internal/filelock"
	"github.com/JasonJarvan/GrokSwitch/internal/fsutil"
	"github.com/JasonJarvan/GrokSwitch/internal/grokauth"
)

type RefreshStatus string

const (
	RefreshStatusRefreshed RefreshStatus = "refreshed"
	RefreshStatusSynced    RefreshStatus = "synced"
	RefreshStatusSkipped   RefreshStatus = "skipped"
	RefreshStatusFailed    RefreshStatus = "failed"
)

// RefreshResult describes the non-secret outcome of refreshing one account.
type RefreshResult struct {
	AccountID         string        `json:"accountId"`
	Alias             string        `json:"alias"`
	Email             string        `json:"email,omitempty"`
	Status            RefreshStatus `json:"status"`
	PreviousExpiresAt string        `json:"previousExpiresAt,omitempty"`
	ExpiresAt         string        `json:"expiresAt,omitempty"`
	RefreshRotated    bool          `json:"refreshRotated,omitempty"`
	ReauthRequired    bool          `json:"reauthRequired,omitempty"`
	Error             string        `json:"error,omitempty"`
}

func (a *App) refreshSkew() time.Duration {
	if a.RefreshSkew > 0 {
		return a.RefreshSkew
	}
	return grokauth.DefaultRefreshSkew
}

// Refresh renews one saved account (when query is non-empty) or all saved
// accounts (when query is empty). By default only expired or soon-expiring
// credentials are exchanged; set force to refresh unconditionally.
func (a *App) Refresh(ctx context.Context, query string, force bool) ([]RefreshResult, error) {
	reg, err := a.Store.Load()
	if err != nil {
		return nil, err
	}
	if len(reg.Accounts) == 0 {
		return nil, ErrNoAccounts
	}

	var targets []accounts.Account
	if strings.TrimSpace(query) != "" {
		idx, err := resolveOne(reg, query)
		if err != nil {
			return nil, err
		}
		targets = []accounts.Account{reg.Accounts[idx]}
	} else {
		targets = append([]accounts.Account(nil), reg.Accounts...)
	}

	results := make([]RefreshResult, len(targets))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)
	for i, account := range targets {
		i, account := i, account
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			_, res, _ := a.RefreshAccount(ctx, account.ID, force)
			results[i] = res
		}()
	}
	wg.Wait()
	return results, nil
}

// RefreshAccount renews a single saved account's OIDC access token when it is
// expired, expiring within RefreshSkew, or force is true. It coordinates with
// Grok Build's auth.json.lock so running Grok sessions are not disrupted.
func (a *App) RefreshAccount(ctx context.Context, accountID string, force bool) (*grokauth.File, RefreshResult, error) {
	reg, err := a.Store.Load()
	if err != nil {
		return nil, RefreshResult{AccountID: accountID, Status: RefreshStatusFailed, Error: err.Error()}, err
	}
	idx := accounts.IndexByID(reg, accountID)
	if idx < 0 {
		err := fmt.Errorf("%w: %q", ErrNotFound, accountID)
		return nil, RefreshResult{AccountID: accountID, Status: RefreshStatusFailed, Error: err.Error()}, err
	}
	account := reg.Accounts[idx]
	result := RefreshResult{
		AccountID:         account.ID,
		Alias:             account.Alias,
		Email:             account.Email,
		PreviousExpiresAt: account.ExpiresAt,
		ExpiresAt:         account.ExpiresAt,
	}

	var updated *grokauth.File
	var status RefreshStatus
	var rotated bool

	if !a.activeInsideStore() && a.activeFileMatches(accountID) {
		updated, status, rotated, err = a.refreshActiveAccount(ctx, accountID, force)
	} else {
		updated, status, rotated, err = a.refreshSnapshotAccount(ctx, accountID, force)
	}
	if err != nil {
		result.Status = RefreshStatusFailed
		result.Error = err.Error()
		result.ReauthRequired = errors.Is(err, grokauth.ErrRefreshReauthRequired)
		return nil, result, err
	}

	result.Status = status
	result.RefreshRotated = rotated
	if updated != nil {
		result.ExpiresAt = updated.Identity.ExpiresAt
		if status == RefreshStatusRefreshed || status == RefreshStatusSynced {
			if syncErr := a.syncRefreshedMetadata(accountID, updated); syncErr != nil {
				result.Status = RefreshStatusFailed
				result.Error = syncErr.Error()
				return updated, result, syncErr
			}
		}
	}
	return updated, result, nil
}

func (a *App) refreshActiveAccount(ctx context.Context, accountID string, force bool) (*grokauth.File, RefreshStatus, bool, error) {
	sessionLock, err := a.acquireSessionLock(accountID)
	if err != nil {
		return nil, RefreshStatusFailed, false, err
	}
	defer sessionLock.Release()

	var resultFile *grokauth.File
	var status RefreshStatus
	var rotated bool

	err = a.withAccountLock(accountID, func() error {
		activeLockPath := filepath.Join(filepath.Dir(a.Paths.ActiveAuth), "auth.json.lock")
		activeLock, lockErr := filelock.Acquire(activeLockPath, 5*time.Second, true)
		if lockErr != nil {
			return fmt.Errorf("Grok is refreshing credentials; retry shortly: %w", lockErr)
		}
		defer activeLock.Release()

		current, readErr := a.readAuth(a.Paths.ActiveAuth)
		if readErr != nil {
			return readErr
		}
		if current.Identity.ID != accountID {
			return errors.New("active account changed during refresh; retry")
		}

		now := a.Now()
		if !force && !current.NeedsRefresh(now, a.refreshSkew()) {
			snapshotBytes, snapErr := a.Store.ReadSnapshot(accountID)
			if snapErr == nil && bytes.Equal(snapshotBytes, current.Raw) {
				resultFile = current
				status = RefreshStatusSkipped
				return nil
			}
			if writeErr := a.Store.WriteSnapshot(accountID, current.Raw); writeErr != nil {
				return writeErr
			}
			resultFile = current
			status = RefreshStatusSynced
			return nil
		}

		updated, didRotate, exchangeErr := a.exchangeAndUpdate(ctx, current, now)
		if exchangeErr != nil {
			return exchangeErr
		}
		if writeErr := fsutil.AtomicWrite(a.Paths.ActiveAuth, updated.Raw, 0o600); writeErr != nil {
			return fmt.Errorf("write refreshed active auth: %w", writeErr)
		}
		if writeErr := a.Store.WriteSnapshot(accountID, updated.Raw); writeErr != nil {
			return fmt.Errorf("write refreshed snapshot: %w", writeErr)
		}
		resultFile = updated
		status = RefreshStatusRefreshed
		rotated = didRotate
		return nil
	})
	if err != nil {
		return nil, RefreshStatusFailed, false, err
	}
	return resultFile, status, rotated, nil
}

func (a *App) refreshSnapshotAccount(ctx context.Context, accountID string, force bool) (*grokauth.File, RefreshStatus, bool, error) {
	sessionLock, err := a.acquireSessionLock(accountID)
	if err != nil {
		return nil, RefreshStatusFailed, false, err
	}
	defer sessionLock.Release()

	var resultFile *grokauth.File
	var status RefreshStatus
	var rotated bool

	err = a.withAccountLock(accountID, func() error {
		data, readErr := a.Store.ReadSnapshot(accountID)
		if readErr != nil {
			return readErr
		}
		authFile, parseErr := grokauth.Parse(data)
		if parseErr != nil {
			return fmt.Errorf("parse saved auth: %w", parseErr)
		}
		if authFile.Identity.ID != accountID {
			return errors.New("saved auth identity does not match registry")
		}
		now := a.Now()
		if !force && !authFile.NeedsRefresh(now, a.refreshSkew()) {
			resultFile = authFile
			status = RefreshStatusSkipped
			return nil
		}
		updated, didRotate, exchangeErr := a.exchangeAndUpdate(ctx, authFile, now)
		if exchangeErr != nil {
			return exchangeErr
		}
		if writeErr := a.Store.WriteSnapshot(accountID, updated.Raw); writeErr != nil {
			return fmt.Errorf("write refreshed snapshot: %w", writeErr)
		}
		resultFile = updated
		status = RefreshStatusRefreshed
		rotated = didRotate
		return nil
	})
	if err != nil {
		return nil, RefreshStatusFailed, false, err
	}
	return resultFile, status, rotated, nil
}

func (a *App) exchangeAndUpdate(ctx context.Context, authFile *grokauth.File, now time.Time) (*grokauth.File, bool, error) {
	cred, ok := authFile.XAIRefreshCredential()
	if !ok {
		return nil, false, grokauth.ErrNoRefreshToken
	}
	tokenURL := strings.TrimSpace(a.TokenURL)
	if tokenURL == "" {
		tokenURL = cred.TokenURL
	}
	reqCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	update, err := grokauth.ExchangeRefreshToken(reqCtx, a.HTTPClient, tokenURL, cred.ClientID, cred.RefreshToken)
	if err != nil {
		return nil, false, err
	}
	updated, err := authFile.ApplyTokenUpdate(update, now)
	if err != nil {
		return nil, false, err
	}
	rotated := update.RefreshToken != "" && update.RefreshToken != cred.RefreshToken
	return updated, rotated, nil
}

func (a *App) syncRefreshedMetadata(accountID string, fallback *grokauth.File) error {
	return a.withManagerLock(func(reg *accounts.Registry) error {
		if accounts.IndexByID(reg, accountID) < 0 {
			return nil
		}
		var latest *grokauth.File
		err := a.withAccountLock(accountID, func() error {
			data, readErr := a.Store.ReadSnapshot(accountID)
			if readErr != nil {
				latest = fallback
				return nil
			}
			parsed, parseErr := grokauth.Parse(data)
			if parseErr != nil || parsed.Identity.ID != accountID {
				latest = fallback
				return nil
			}
			latest = parsed
			return nil
		})
		if err != nil {
			return err
		}
		if latest == nil {
			return nil
		}
		idx := accounts.IndexByID(reg, accountID)
		if idx < 0 {
			return nil
		}
		reg.Accounts[idx].Email = latest.Identity.Email
		reg.Accounts[idx].DisplayName = latest.Identity.DisplayName
		reg.Accounts[idx].UserID = latest.Identity.UserID
		reg.Accounts[idx].AuthMode = latest.Identity.AuthMode
		reg.Accounts[idx].Scope = latest.Identity.Scope
		reg.Accounts[idx].TeamID = latest.Identity.TeamID
		reg.Accounts[idx].TeamName = latest.Identity.TeamName
		reg.Accounts[idx].OrganizationID = latest.Identity.OrganizationID
		reg.Accounts[idx].OrganizationName = latest.Identity.OrganizationName
		reg.Accounts[idx].ExpiresAt = latest.Identity.ExpiresAt
		reg.Accounts[idx].UpdatedAt = a.Now().UTC().Format(time.RFC3339)
		return a.Store.Save(reg)
	})
}
