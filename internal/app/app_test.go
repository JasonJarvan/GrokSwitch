package app_test

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bbbkawaii/GrokSwitch/internal/accounts"
	"github.com/bbbkawaii/GrokSwitch/internal/app"
	"github.com/bbbkawaii/GrokSwitch/internal/filelock"
	"github.com/bbbkawaii/GrokSwitch/internal/fsutil"
	"github.com/bbbkawaii/GrokSwitch/internal/grokauth"
)

func TestMain(m *testing.M) {
	switch os.Getenv("GROKSWITCH_TEST_HELPER") {
	case "login":
		path := os.Getenv("GROK_AUTH_PATH")
		_ = os.MkdirAll(filepath.Dir(path), 0o700)
		_ = os.WriteFile(path, fakeAuth("login-user", "login@example.com", "login-token"), 0o600)
		os.Exit(0)
	case "run":
		path := os.Getenv("GROK_AUTH_PATH")
		data, err := os.ReadFile(path)
		if err != nil {
			os.Exit(21)
		}
		if os.Getenv("GROK_AUTH") != "" || os.Getenv("XAI_API_KEY") != "" {
			os.Exit(22)
		}
		data = bytes.ReplaceAll(data, []byte("run-token"), []byte("refreshed-token"))
		if err := os.WriteFile(path, data, 0o600); err != nil {
			os.Exit(23)
		}
		if result := os.Getenv("GROKSWITCH_TEST_RESULT"); result != "" {
			_ = os.WriteFile(result, []byte(path), 0o600)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestEndToEndSaveImportSwitchPreviousAndRemove(t *testing.T) {
	application := newTestApp(t)
	one := fakeAuth("user-one", "one@example.com", "token-one")
	two := fakeAuth("user-two", "two@example.com", "token-two")
	if err := fsutil.AtomicWrite(application.Paths.ActiveAuth, one, 0o600); err != nil {
		t.Fatal(err)
	}
	savedOne, created, err := application.CaptureCurrent("one")
	if err != nil || !created {
		t.Fatalf("capture current: account=%+v created=%v err=%v", savedOne, created, err)
	}

	importPath := filepath.Join(t.TempDir(), "two.json")
	if err := os.WriteFile(importPath, two, 0o600); err != nil {
		t.Fatal(err)
	}
	savedTwo, created, err := application.Import(importPath, "two", false)
	if err != nil || !created {
		t.Fatalf("import: account=%+v created=%v err=%v", savedTwo, created, err)
	}
	selected, err := application.Switch("two")
	if err != nil || selected.ID != savedTwo.ID {
		t.Fatalf("switch: account=%+v err=%v", selected, err)
	}
	assertActiveUser(t, application.Paths.ActiveAuth, "user-two")

	previous, err := application.Previous()
	if err != nil || previous.ID != savedOne.ID {
		t.Fatalf("previous: account=%+v err=%v", previous, err)
	}
	assertActiveUser(t, application.Paths.ActiveAuth, "user-one")

	removed, fallback, err := application.Remove("one")
	if err != nil {
		t.Fatal(err)
	}
	if removed.ID != savedOne.ID || fallback != "two" {
		t.Fatalf("unexpected removal: removed=%+v fallback=%q", removed, fallback)
	}
	assertActiveUser(t, application.Paths.ActiveAuth, "user-two")
	list, err := application.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Registry.Accounts) != 1 || list.Registry.Accounts[0].ID != savedTwo.ID {
		t.Fatalf("unexpected registry after removal: %+v", list.Registry.Accounts)
	}
}

func TestLoginUsesIsolatedAuthAndPreservesCurrentAccount(t *testing.T) {
	application := newTestApp(t)
	if err := fsutil.AtomicWrite(application.Paths.ActiveAuth, fakeAuth("old-user", "old@example.com", "old-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GROK_SWITCH_GROK_BIN", os.Args[0])
	t.Setenv("GROKSWITCH_TEST_HELPER", "login")
	account, created, err := application.Login("new", true)
	if err != nil {
		t.Fatal(err)
	}
	if !created || account.Email != "login@example.com" {
		t.Fatalf("unexpected login result: created=%v account=%+v", created, account)
	}
	assertActiveUser(t, application.Paths.ActiveAuth, "login-user")
	list, err := application.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Registry.Accounts) != 2 {
		t.Fatalf("login did not preserve old account: %+v", list.Registry.Accounts)
	}
}

func TestReimportingActiveAccountDoesNotRelockItsOwnSnapshot(t *testing.T) {
	application := newTestApp(t)
	original := fakeAuth("same-user", "same@example.com", "old-token")
	if err := fsutil.AtomicWrite(application.Paths.ActiveAuth, original, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := application.CaptureCurrent("same"); err != nil {
		t.Fatal(err)
	}
	updatedPath := filepath.Join(t.TempDir(), "updated.json")
	if err := os.WriteFile(updatedPath, fakeAuth("same-user", "same@example.com", "new-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, created, err := application.Import(updatedPath, "", true); err != nil {
		t.Fatal(err)
	} else if created {
		t.Fatal("same stable identity was unexpectedly added as a new account")
	}
	active, err := os.ReadFile(application.Paths.ActiveAuth)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(active), "new-token") || strings.Contains(string(active), "old-token") {
		t.Fatal("active account was not replaced with the reimported credentials")
	}
}

func TestSwitchRejectsInlineAuthOverride(t *testing.T) {
	application := newTestApp(t)
	if err := fsutil.AtomicWrite(application.Paths.ActiveAuth, fakeAuth("inline-user", "inline@example.com", "file-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := application.CaptureCurrent("inline"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GROK_AUTH", `{"key":"inline-token"}`)
	if _, err := application.Switch("inline"); err == nil || !strings.Contains(err.Error(), "GROK_AUTH") {
		t.Fatalf("switch error = %v, want GROK_AUTH override error", err)
	}
}

func TestRunRejectsGlobalAccountAndLeaseBlocksSwitch(t *testing.T) {
	application := newTestApp(t)
	if err := fsutil.AtomicWrite(application.Paths.ActiveAuth, fakeAuth("active-user", "active@example.com", "active-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := application.CaptureCurrent("active"); err != nil {
		t.Fatal(err)
	}
	if err := application.RunAccount("active", nil); err == nil || !strings.Contains(err.Error(), "globally active") {
		t.Fatalf("run error = %v, want globally active rejection", err)
	}

	otherPath := filepath.Join(t.TempDir(), "other.json")
	if err := os.WriteFile(otherPath, fakeAuth("leased-user", "leased@example.com", "leased-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	other, _, err := application.Import(otherPath, "leased", false)
	if err != nil {
		t.Fatal(err)
	}
	leasePath, err := application.Store.SessionLockPath(other.ID)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := filelock.Acquire(leasePath, time.Second, false)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	if _, err := application.Switch("leased"); err == nil || !strings.Contains(err.Error(), "grok-switch run") {
		t.Fatalf("switch error = %v, want active run lease rejection", err)
	}
}

func TestRunUsesManagedAuthPathAndPersistsRefresh(t *testing.T) {
	application := newTestApp(t)
	importPath := filepath.Join(t.TempDir(), "run.json")
	if err := os.WriteFile(importPath, fakeAuth("run-user", "run@example.com", "run-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	account, _, err := application.Import(importPath, "runner", false)
	if err != nil {
		t.Fatal(err)
	}
	resultPath := filepath.Join(t.TempDir(), "result")
	t.Setenv("GROK_SWITCH_GROK_BIN", os.Args[0])
	t.Setenv("GROKSWITCH_TEST_HELPER", "run")
	t.Setenv("GROKSWITCH_TEST_RESULT", resultPath)
	t.Setenv("GROK_AUTH", "must-be-scrubbed")
	t.Setenv("XAI_API_KEY", "must-be-scrubbed")
	if err := application.RunAccount("runner", nil); err != nil {
		t.Fatal(err)
	}
	usedPathBytes, err := os.ReadFile(resultPath)
	if err != nil {
		t.Fatal(err)
	}
	expectedPath, _ := application.Store.SnapshotPath(account.ID)
	if string(usedPathBytes) != expectedPath {
		t.Fatalf("GROK_AUTH_PATH = %q, want %q", usedPathBytes, expectedPath)
	}
	refreshed, err := os.ReadFile(expectedPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(refreshed), "refreshed-token") || strings.Contains(string(refreshed), "run-token") {
		t.Fatal("refreshed credentials were not persisted to the account snapshot")
	}
}

func TestFetchQuotasUsesSavedAccountCredentials(t *testing.T) {
	application := newTestApp(t)
	importPath := filepath.Join(t.TempDir(), "quota.json")
	if err := os.WriteFile(importPath, fakeAuth("quota-user", "quota@example.com", "quota-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	account, _, err := application.Import(importPath, "quota", false)
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer quota-token" {
			t.Errorf("unexpected authorization header")
		}
		if r.URL.Path == "/user" {
			_, _ = w.Write([]byte(`{"userId":"quota-user","subscriptionTier":"GrokPro"}`))
			return
		}
		if got := r.Header.Get("x-userid"); got != "quota-user" {
			t.Errorf("x-userid = %q", got)
		}
		_, _ = w.Write([]byte(`{"config":{"creditUsagePercent":99,"currentPeriod":{"type":"USAGE_PERIOD_TYPE_WEEKLY","end":"2026-08-14T19:00:12Z"}}}`))
	}))
	defer server.Close()
	application.HTTPClient = server.Client()
	application.BillingURL = server.URL + "/billing"
	application.UserURL = server.URL + "/user?include=subscription"
	application.GrokClientVersion = "test-version"

	list, err := application.List()
	if err != nil {
		t.Fatal(err)
	}
	quotas := application.FetchQuotas(list)
	quota, ok := quotas[account.ID]
	if !ok || quota.Error != "" {
		t.Fatalf("unexpected quota result: %+v", quota)
	}
	if quota.RemainingPercent == nil || *quota.RemainingPercent != 1 {
		t.Fatalf("unexpected remaining quota: %+v", quota)
	}
	if quota.ResetAt != "2026-08-14T19:00:12Z" {
		t.Fatalf("unexpected reset time: %+v", quota)
	}
	if quota.Tier != "GrokPro" || quota.TierError != "" {
		t.Fatalf("unexpected tier: %+v", quota)
	}
}

func TestFetchQuotasKeepsTierWhenBillingEndpointFails(t *testing.T) {
	application := newTestApp(t)
	importPath := filepath.Join(t.TempDir(), "quota.json")
	if err := os.WriteFile(importPath, fakeAuth("tier-user", "tier@example.com", "tier-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	account, _, err := application.Import(importPath, "tier", false)
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/user" {
			_, _ = w.Write([]byte(`{"subscriptionTier":"XPremium"}`))
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	application.HTTPClient = server.Client()
	application.BillingURL = server.URL + "/billing"
	application.UserURL = server.URL + "/user?include=subscription"

	list, err := application.List()
	if err != nil {
		t.Fatal(err)
	}
	result := application.FetchQuotas(list)[account.ID]
	if result.Tier != "XPremium" || result.TierError != "" {
		t.Fatalf("tier was lost after an independent billing failure: %+v", result)
	}
	if result.Error == "" || result.RemainingPercent != nil {
		t.Fatalf("billing failure was not isolated: %+v", result)
	}
}

func newTestApp(t *testing.T) *app.App {
	t.Helper()
	root := t.TempDir()
	grokHome := filepath.Join(root, ".grok")
	paths := accounts.Paths{
		GrokHome:     grokHome,
		StoreRoot:    filepath.Join(grokHome, "accounts"),
		RegistryPath: filepath.Join(grokHome, "accounts", "registry.json"),
		ActiveAuth:   filepath.Join(grokHome, "auth.json"),
		ManagerLock:  filepath.Join(grokHome, "accounts", ".grok-switch.lock"),
	}
	t.Setenv("GROK_AUTH", "")
	t.Setenv("GROK_AUTH_PATH", "")
	t.Setenv("XAI_API_KEY", "")
	application := app.New(paths, bytes.NewBuffer(nil), bytes.NewBuffer(nil), bytes.NewBuffer(nil))
	fixed := time.Date(2026, 8, 12, 0, 0, 0, 0, time.UTC)
	application.Now = func() time.Time { return fixed }
	return application
}

func fakeAuth(userID, email, token string) []byte {
	return []byte(fmt.Sprintf(`{"https://auth.x.ai::client":{"key":%q,"auth_mode":"oidc","create_time":"2026-08-01T00:00:00Z","user_id":%q,"email":%q,"refresh_token":"refresh-%s","expires_at":"2030-01-01T00:00:00Z","oidc_issuer":"https://auth.x.ai","oidc_client_id":"client"}}`, token, userID, email, userID))
}

func assertActiveUser(t *testing.T, path, want string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := grokauth.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Identity.UserID != want {
		t.Fatalf("active user = %q, want %q", parsed.Identity.UserID, want)
	}
}
