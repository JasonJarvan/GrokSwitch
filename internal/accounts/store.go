package accounts

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/bbbkawaii/GrokSwitch/internal/fsutil"
	"github.com/bbbkawaii/GrokSwitch/internal/grokauth"
)

const SchemaVersion = 1

var accountIDPattern = regexp.MustCompile(`^acc_[0-9a-f]{20}$`)

type Paths struct {
	GrokHome     string `json:"grokHome"`
	StoreRoot    string `json:"storeRoot"`
	RegistryPath string `json:"registryPath"`
	ActiveAuth   string `json:"activeAuth"`
	ManagerLock  string `json:"managerLock"`
}

func ResolvePaths() (Paths, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Paths{}, fmt.Errorf("resolve user home: %w", err)
	}
	grokHome := strings.TrimSpace(os.Getenv("GROK_HOME"))
	if grokHome == "" {
		grokHome = filepath.Join(home, ".grok")
	}
	grokHome, err = filepath.Abs(grokHome)
	if err != nil {
		return Paths{}, fmt.Errorf("resolve GROK_HOME: %w", err)
	}

	storeRoot := strings.TrimSpace(os.Getenv("GROK_SWITCH_HOME"))
	if storeRoot == "" {
		storeRoot = filepath.Join(grokHome, "accounts")
	}
	storeRoot, err = filepath.Abs(storeRoot)
	if err != nil {
		return Paths{}, fmt.Errorf("resolve GROK_SWITCH_HOME: %w", err)
	}

	activeAuth := strings.TrimSpace(os.Getenv("GROK_AUTH_PATH"))
	if activeAuth == "" {
		activeAuth = filepath.Join(grokHome, "auth.json")
	}
	activeAuth, err = filepath.Abs(activeAuth)
	if err != nil {
		return Paths{}, fmt.Errorf("resolve GROK_AUTH_PATH: %w", err)
	}

	return Paths{
		GrokHome:     grokHome,
		StoreRoot:    storeRoot,
		RegistryPath: filepath.Join(storeRoot, "registry.json"),
		ActiveAuth:   activeAuth,
		ManagerLock:  filepath.Join(storeRoot, ".grok-switch.lock"),
	}, nil
}

type Account struct {
	ID               string `json:"id"`
	Alias            string `json:"alias"`
	Email            string `json:"email,omitempty"`
	DisplayName      string `json:"displayName,omitempty"`
	UserID           string `json:"userId,omitempty"`
	AuthMode         string `json:"authMode"`
	Scope            string `json:"scope"`
	TeamID           string `json:"teamId,omitempty"`
	TeamName         string `json:"teamName,omitempty"`
	OrganizationID   string `json:"organizationId,omitempty"`
	OrganizationName string `json:"organizationName,omitempty"`
	ExpiresAt        string `json:"expiresAt,omitempty"`
	CreatedAt        string `json:"createdAt"`
	UpdatedAt        string `json:"updatedAt"`
	LastUsedAt       string `json:"lastUsedAt,omitempty"`
}

func (a Account) Identity() grokauth.Identity {
	return grokauth.Identity{
		ID:               a.ID,
		Email:            a.Email,
		DisplayName:      a.DisplayName,
		UserID:           a.UserID,
		AuthMode:         a.AuthMode,
		Scope:            a.Scope,
		TeamID:           a.TeamID,
		TeamName:         a.TeamName,
		OrganizationID:   a.OrganizationID,
		OrganizationName: a.OrganizationName,
		ExpiresAt:        a.ExpiresAt,
	}
}

type Registry struct {
	SchemaVersion     int       `json:"schemaVersion"`
	ActiveAccountID   string    `json:"activeAccountId,omitempty"`
	PreviousAccountID string    `json:"previousAccountId,omitempty"`
	Accounts          []Account `json:"accounts"`
}

type Store struct {
	Paths Paths
}

func New(paths Paths) *Store {
	return &Store{Paths: paths}
}

func (s *Store) Ensure() error {
	return fsutil.EnsurePrivateDir(s.Paths.StoreRoot)
}

func (s *Store) Load() (*Registry, error) {
	data, err := os.ReadFile(s.Paths.RegistryPath)
	if errors.Is(err, os.ErrNotExist) {
		return &Registry{SchemaVersion: SchemaVersion, Accounts: []Account{}}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read account registry: %w", err)
	}
	var reg Registry
	if err := json.Unmarshal(data, &reg); err != nil {
		return nil, fmt.Errorf("parse account registry: %w", err)
	}
	if reg.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("unsupported registry schema %d (expected %d)", reg.SchemaVersion, SchemaVersion)
	}
	if reg.Accounts == nil {
		reg.Accounts = []Account{}
	}
	if err := validateRegistry(&reg); err != nil {
		return nil, err
	}
	if runtime.GOOS != "windows" {
		_ = os.Chmod(s.Paths.RegistryPath, 0o600)
	}
	return &reg, nil
}

func validateRegistry(reg *Registry) error {
	seenID := map[string]bool{}
	seenAlias := map[string]bool{}
	for _, account := range reg.Accounts {
		if !ValidID(account.ID) {
			return fmt.Errorf("registry contains invalid account id %q", account.ID)
		}
		if seenID[account.ID] {
			return fmt.Errorf("registry contains duplicate account id %q", account.ID)
		}
		seenID[account.ID] = true
		aliasKey := strings.ToLower(strings.TrimSpace(account.Alias))
		if aliasKey == "" {
			return fmt.Errorf("registry account %s has an empty alias", account.ID)
		}
		if seenAlias[aliasKey] {
			return fmt.Errorf("registry contains duplicate alias %q", account.Alias)
		}
		seenAlias[aliasKey] = true
	}
	return nil
}

func (s *Store) Save(reg *Registry) error {
	if err := s.Ensure(); err != nil {
		return err
	}
	if err := validateRegistry(reg); err != nil {
		return err
	}
	data, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return fmt.Errorf("encode account registry: %w", err)
	}
	data = append(data, '\n')
	return fsutil.AtomicWrite(s.Paths.RegistryPath, data, 0o600)
}

func ValidID(id string) bool {
	return accountIDPattern.MatchString(id)
}

func (s *Store) AccountDir(id string) (string, error) {
	if !ValidID(id) {
		return "", fmt.Errorf("invalid account id %q", id)
	}
	return filepath.Join(s.Paths.StoreRoot, id), nil
}

func (s *Store) SnapshotPath(id string) (string, error) {
	dir, err := s.AccountDir(id)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "auth.json"), nil
}

func (s *Store) AuthLockPath(id string) (string, error) {
	dir, err := s.AccountDir(id)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "auth.json.lock"), nil
}

func (s *Store) SessionLockPath(id string) (string, error) {
	dir, err := s.AccountDir(id)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, ".grok-switch.session.lock"), nil
}

func (s *Store) WriteSnapshot(id string, data []byte) error {
	path, err := s.SnapshotPath(id)
	if err != nil {
		return err
	}
	return fsutil.AtomicWrite(path, data, 0o600)
}

func (s *Store) ReadSnapshot(id string) ([]byte, error) {
	path, err := s.SnapshotPath(id)
	if err != nil {
		return nil, err
	}
	data, err := fsutil.ReadPrivateFile(path)
	if err != nil {
		return nil, fmt.Errorf("read snapshot for %s: %w", id, err)
	}
	return data, nil
}

func (s *Store) RemoveSnapshot(id string) error {
	dir, err := s.AccountDir(id)
	if err != nil {
		return err
	}
	cleanRoot := filepath.Clean(s.Paths.StoreRoot) + string(os.PathSeparator)
	cleanDir := filepath.Clean(dir)
	if !strings.HasPrefix(cleanDir+string(os.PathSeparator), cleanRoot) {
		return fmt.Errorf("refusing to remove path outside account store: %s", dir)
	}
	return os.RemoveAll(cleanDir)
}

func (s *Store) Upsert(reg *Registry, authFile *grokauth.File, requestedAlias string, now time.Time) (*Account, bool, error) {
	identity := authFile.Identity
	idx := IndexByID(reg, identity.ID)
	created := idx < 0
	alias := strings.TrimSpace(requestedAlias)
	if alias != "" {
		if err := ValidateAlias(alias); err != nil {
			return nil, false, err
		}
		if conflict := IndexByAlias(reg, alias); conflict >= 0 && reg.Accounts[conflict].ID != identity.ID {
			return nil, false, fmt.Errorf("alias %q is already used by another account", alias)
		}
	} else if idx >= 0 {
		alias = reg.Accounts[idx].Alias
	} else {
		alias = UniqueAlias(reg, SuggestedAlias(identity))
	}

	createdAt := now.UTC().Format(time.RFC3339)
	lastUsedAt := ""
	if idx >= 0 {
		createdAt = reg.Accounts[idx].CreatedAt
		lastUsedAt = reg.Accounts[idx].LastUsedAt
	}
	account := Account{
		ID:               identity.ID,
		Alias:            alias,
		Email:            identity.Email,
		DisplayName:      identity.DisplayName,
		UserID:           identity.UserID,
		AuthMode:         identity.AuthMode,
		Scope:            identity.Scope,
		TeamID:           identity.TeamID,
		TeamName:         identity.TeamName,
		OrganizationID:   identity.OrganizationID,
		OrganizationName: identity.OrganizationName,
		ExpiresAt:        identity.ExpiresAt,
		CreatedAt:        createdAt,
		UpdatedAt:        now.UTC().Format(time.RFC3339),
		LastUsedAt:       lastUsedAt,
	}

	if err := s.WriteSnapshot(identity.ID, authFile.Raw); err != nil {
		return nil, false, err
	}
	if idx >= 0 {
		reg.Accounts[idx] = account
		return &reg.Accounts[idx], false, nil
	}
	reg.Accounts = append(reg.Accounts, account)
	return &reg.Accounts[len(reg.Accounts)-1], created, nil
}

func ValidateAlias(alias string) error {
	alias = strings.TrimSpace(alias)
	if alias == "" {
		return errors.New("alias cannot be empty")
	}
	if len([]rune(alias)) > 64 {
		return errors.New("alias cannot exceed 64 characters")
	}
	if strings.HasPrefix(alias, "-") {
		return errors.New("alias cannot start with '-' because it would be parsed as an option")
	}
	for _, r := range alias {
		if unicode.IsControl(r) {
			return errors.New("alias cannot contain control characters")
		}
	}
	return nil
}

func SuggestedAlias(identity grokauth.Identity) string {
	if identity.Email != "" {
		if local, _, ok := strings.Cut(identity.Email, "@"); ok && strings.TrimSpace(local) != "" {
			return sanitizeAlias(local)
		}
	}
	if identity.DisplayName != "" {
		return sanitizeAlias(identity.DisplayName)
	}
	if identity.TeamName != "" {
		return sanitizeAlias(identity.TeamName)
	}
	return "account-" + strings.TrimPrefix(identity.ID, "acc_")[:6]
}

func sanitizeAlias(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var builder strings.Builder
	lastDash := false
	for _, r := range value {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '.' {
			builder.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			builder.WriteByte('-')
			lastDash = true
		}
	}
	result := strings.Trim(builder.String(), "-")
	if result == "" {
		return "account"
	}
	return result
}

func UniqueAlias(reg *Registry, base string) string {
	if IndexByAlias(reg, base) < 0 {
		return base
	}
	for n := 2; ; n++ {
		candidate := fmt.Sprintf("%s-%d", base, n)
		if IndexByAlias(reg, candidate) < 0 {
			return candidate
		}
	}
}

func IndexByID(reg *Registry, id string) int {
	for i := range reg.Accounts {
		if reg.Accounts[i].ID == id {
			return i
		}
	}
	return -1
}

func IndexByAlias(reg *Registry, alias string) int {
	alias = strings.ToLower(strings.TrimSpace(alias))
	for i := range reg.Accounts {
		if strings.ToLower(reg.Accounts[i].Alias) == alias {
			return i
		}
	}
	return -1
}

type Resolution struct {
	Index   int
	Matches []int
}

func Resolve(reg *Registry, query string) Resolution {
	query = strings.TrimSpace(query)
	if query == "" {
		return Resolution{Index: -1}
	}
	if row, err := parseRow(query); err == nil && row >= 1 && row <= len(reg.Accounts) {
		return Resolution{Index: row - 1}
	}
	lower := strings.ToLower(query)
	for i, account := range reg.Accounts {
		if strings.ToLower(account.Alias) == lower ||
			strings.ToLower(account.Email) == lower ||
			account.ID == lower {
			return Resolution{Index: i}
		}
	}
	idMatches := []int{}
	if strings.HasPrefix(lower, "acc_") || len(lower) >= 4 {
		for i, account := range reg.Accounts {
			if strings.HasPrefix(account.ID, lower) || strings.HasPrefix(strings.TrimPrefix(account.ID, "acc_"), lower) {
				idMatches = append(idMatches, i)
			}
		}
		if len(idMatches) == 1 {
			return Resolution{Index: idMatches[0]}
		}
	}
	matches := []int{}
	for i, account := range reg.Accounts {
		haystack := strings.ToLower(strings.Join([]string{
			account.Alias, account.Email, account.DisplayName, account.TeamName,
			account.OrganizationName, account.UserID,
		}, "\x00"))
		if strings.Contains(haystack, lower) {
			matches = append(matches, i)
		}
	}
	if len(matches) == 1 {
		return Resolution{Index: matches[0]}
	}
	if len(matches) == 0 && len(idMatches) > 1 {
		matches = idMatches
	}
	return Resolution{Index: -1, Matches: matches}
}

func parseRow(value string) (int, error) {
	return strconv.Atoi(value)
}

func SortedCopy(accounts []Account) []Account {
	copyOf := append([]Account(nil), accounts...)
	sort.SliceStable(copyOf, func(i, j int) bool {
		return strings.ToLower(copyOf[i].Alias) < strings.ToLower(copyOf[j].Alias)
	})
	return copyOf
}
