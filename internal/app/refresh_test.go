package app_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JasonJarvan/GrokSwitch/internal/app"
	"github.com/JasonJarvan/GrokSwitch/internal/fsutil"
	"github.com/JasonJarvan/GrokSwitch/internal/grokauth"
)

func fakeAuthWithExpiry(userID, email, token, refreshToken, expiresAt string) []byte {
	return []byte(fmt.Sprintf(`{"https://auth.x.ai::client":{"key":%q,"auth_mode":"oidc","create_time":"2026-08-01T00:00:00Z","user_id":%q,"email":%q,"refresh_token":%q,"expires_at":%q,"oidc_issuer":"https://auth.x.ai","oidc_client_id":"client","custom_field":"keep"}}`, token, userID, email, refreshToken, expiresAt))
}

func TestFetchQuotasAutoRefreshesExpiredSnapshot(t *testing.T) {
	application := newTestApp(t)
	now := time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC)
	application.Now = func() time.Time { return now }

	importPath := filepath.Join(t.TempDir(), "expired.json")
	expiredRaw := fakeAuthWithExpiry("exp-user", "exp@example.com", "expired-access", "old-refresh", "2026-11-16T10:00:00Z")
	if err := os.WriteFile(importPath, expiredRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	account, _, err := application.Import(importPath, "exp", false)
	if err != nil {
		t.Fatal(err)
	}

	var tokenCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2/token":
			tokenCalls.Add(1)
			if err := r.ParseForm(); err != nil {
				t.Errorf("parse form: %v", err)
			}
			if r.Form.Get("refresh_token") != "old-refresh" {
				t.Errorf("unexpected refresh_token")
			}
			_, _ = w.Write([]byte(`{"access_token":"fresh-access","refresh_token":"rotated-refresh","expires_in":21600}`))
		case "/user":
			if r.Header.Get("Authorization") != "Bearer fresh-access" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte(`{"subscriptionTier":"GrokPro"}`))
		case "/billing":
			if r.Header.Get("Authorization") != "Bearer fresh-access" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte(`{"config":{"creditUsagePercent":25,"currentPeriod":{"type":"USAGE_PERIOD_TYPE_WEEKLY","end":"2026-11-24T00:00:00Z"}}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	application.HTTPClient = server.Client()
	application.TokenURL = server.URL + "/oauth2/token"
	application.BillingURL = server.URL + "/billing"
	application.UserURL = server.URL + "/user?include=subscription"

	list, err := application.List()
	if err != nil {
		t.Fatal(err)
	}
	quotas := application.FetchQuotas(list)
	if tokenCalls.Load() != 1 {
		t.Fatalf("token calls = %d, want 1", tokenCalls.Load())
	}
	quota := quotas[account.ID]
	if quota.Error != "" || quota.TierError != "" || quota.Tier != "GrokPro" {
		t.Fatalf("unexpected quota after auto-refresh: %+v", quota)
	}
	if quota.RemainingPercent == nil || *quota.RemainingPercent != 75 {
		t.Fatalf("unexpected remaining percent: %+v", quota)
	}
	wantExpires := "2026-11-19T16:00:00Z"
	if list.Registry.Accounts[0].ExpiresAt != wantExpires {
		t.Fatalf("in-memory expiresAt = %q, want %q", list.Registry.Accounts[0].ExpiresAt, wantExpires)
	}

	snapBytes, err := application.Store.ReadSnapshot(account.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(snapBytes), "fresh-access") ||
		!strings.Contains(string(snapBytes), "rotated-refresh") ||
		!strings.Contains(string(snapBytes), `"custom_field": "keep"`) {
		t.Fatal("snapshot did not persist refreshed credentials and unknown fields")
	}
	reloaded, err := application.Store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Accounts[0].ExpiresAt != wantExpires {
		t.Fatalf("persisted registry expiresAt = %q, want %q", reloaded.Accounts[0].ExpiresAt, wantExpires)
	}
}

func TestFetchQuotasAutoRefreshesOnHTTP401(t *testing.T) {
	application := newTestApp(t)
	now := time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC)
	application.Now = func() time.Time { return now }

	importPath := filepath.Join(t.TempDir(), "revoked-access.json")
	raw := fakeAuthWithExpiry("user-401", "u401@example.com", "stale-access", "rt-401", "2026-11-19T20:00:00Z")
	if err := os.WriteFile(importPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	account, _, err := application.Import(importPath, "u401", false)
	if err != nil {
		t.Fatal(err)
	}

	var tokenCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2/token":
			tokenCalls.Add(1)
			_, _ = w.Write([]byte(`{"access_token":"renewed-access","refresh_token":"rt-401-new","expires_in":21600}`))
		case "/user":
			if r.Header.Get("Authorization") != "Bearer renewed-access" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte(`{"subscriptionTier":"SuperGrok"}`))
		case "/billing":
			if r.Header.Get("Authorization") != "Bearer renewed-access" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte(`{"config":{"creditUsagePercent":10,"currentPeriod":{"type":"USAGE_PERIOD_TYPE_WEEKLY","end":"2026-11-24T00:00:00Z"}}}`))
		}
	}))
	defer server.Close()

	application.HTTPClient = server.Client()
	application.TokenURL = server.URL + "/oauth2/token"
	application.BillingURL = server.URL + "/billing"
	application.UserURL = server.URL + "/user?include=subscription"

	list, err := application.List()
	if err != nil {
		t.Fatal(err)
	}
	quota := application.FetchQuotas(list)[account.ID]
	if tokenCalls.Load() != 1 {
		t.Fatalf("token calls = %d, want 1", tokenCalls.Load())
	}
	if quota.Error != "" || quota.Tier != "SuperGrok" || quota.RemainingPercent == nil || *quota.RemainingPercent != 90 {
		t.Fatalf("unexpected quota after 401 retry: %+v", quota)
	}
}

func TestRefreshActiveAccountSyncsFreshAndRotatesWhenForced(t *testing.T) {
	application := newTestApp(t)
	now := time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC)
	application.Now = func() time.Time { return now }

	// Save an older snapshot first.
	oldActive := fakeAuthWithExpiry("act-user", "act@example.com", "old-access", "rt-1", "2026-11-16T10:00:00Z")
	if err := fsutil.AtomicWrite(application.Paths.ActiveAuth, oldActive, 0o600); err != nil {
		t.Fatal(err)
	}
	account, _, err := application.CaptureCurrent("act")
	if err != nil {
		t.Fatal(err)
	}

	// Simulate running grok CLI renewing ~/.grok/auth.json while snapshot lags behind.
	liveFresh := fakeAuthWithExpiry("act-user", "act@example.com", "live-fresh-access", "rt-2", "2026-11-19T15:00:00Z")
	if err := fsutil.AtomicWrite(application.Paths.ActiveAuth, liveFresh, 0o600); err != nil {
		t.Fatal(err)
	}

	var tokenCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenCalls.Add(1)
		_, _ = w.Write([]byte(`{"access_token":"forced-access","refresh_token":"rt-3","expires_in":21600}`))
	}))
	defer server.Close()
	application.HTTPClient = server.Client()
	application.TokenURL = server.URL + "/oauth2/token"

	// Non-forced refresh should sync live -> snapshot without calling xAI.
	results, err := application.Refresh(context.Background(), "act", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Status != app.RefreshStatusSynced {
		t.Fatalf("unexpected non-forced result: %+v", results)
	}
	if tokenCalls.Load() != 0 {
		t.Fatalf("expected 0 token calls when live active auth is fresh, got %d", tokenCalls.Load())
	}
	snapBytes, err := application.Store.ReadSnapshot(account.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(snapBytes), "live-fresh-access") {
		t.Fatal("snapshot was not synced from fresh active auth")
	}

	// Forced refresh should call xAI and update both live active auth and snapshot.
	results, err = application.Refresh(context.Background(), "act", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Status != app.RefreshStatusRefreshed || !results[0].RefreshRotated {
		t.Fatalf("unexpected forced result: %+v", results)
	}
	if tokenCalls.Load() != 1 {
		t.Fatalf("token calls = %d, want 1", tokenCalls.Load())
	}
	activeBytes, err := os.ReadFile(application.Paths.ActiveAuth)
	if err != nil {
		t.Fatal(err)
	}
	snapBytes, err = application.Store.ReadSnapshot(account.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(activeBytes), "forced-access") || !strings.Contains(string(snapBytes), "forced-access") {
		t.Fatal("forced refresh did not update both active auth and snapshot")
	}
}

func TestRefreshReauthErrorDoesNotLeakTokens(t *testing.T) {
	application := newTestApp(t)
	now := time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC)
	application.Now = func() time.Time { return now }

	secretRT := "super-secret-revoked-refresh-token"
	importPath := filepath.Join(t.TempDir(), "revoked.json")
	raw := fakeAuthWithExpiry("rev-user", "rev@example.com", "old-access", secretRT, "2026-11-16T10:00:00Z")
	if err := os.WriteFile(importPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := application.Import(importPath, "rev", false); err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"bad token ` + secretRT + `"}`))
	}))
	defer server.Close()
	application.HTTPClient = server.Client()
	application.TokenURL = server.URL + "/oauth2/token"

	results, err := application.Refresh(context.Background(), "rev", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Status != app.RefreshStatusFailed || !results[0].ReauthRequired {
		t.Fatalf("unexpected refresh result: %+v", results)
	}
	if strings.Contains(results[0].Error, secretRT) {
		t.Fatalf("secret leaked in refresh error: %s", results[0].Error)
	}
	if !strings.Contains(results[0].Error, grokauth.ErrRefreshReauthRequired.Error()) {
		t.Fatalf("expected reauth error message, got %q", results[0].Error)
	}
}
