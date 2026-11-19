package grokauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestXAIRefreshCredentialAndNeedsRefresh(t *testing.T) {
	raw := []byte(`{
  "https://auth.x.ai::client-abc": {
    "key": "access-old",
    "auth_mode": "oidc",
    "create_time": "2026-08-01T00:00:00Z",
    "user_id": "user-123",
    "email": "owner@example.com",
    "refresh_token": "refresh-old",
    "expires_at": "2026-11-19T12:00:00Z",
    "oidc_issuer": "https://auth.x.ai",
    "oidc_client_id": "client-abc",
    "custom_flag": true
  }
}`)
	parsed, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	cred, ok := parsed.XAIRefreshCredential()
	if !ok {
		t.Fatal("expected first-party xAI refresh credential")
	}
	if cred.ClientID != "client-abc" || cred.TokenURL != DefaultTokenURL || cred.RefreshToken != "refresh-old" {
		t.Fatalf("unexpected refresh credential: client=%q url=%q", cred.ClientID, cred.TokenURL)
	}

	at1150 := time.Date(2026, 11, 19, 11, 50, 0, 0, time.UTC)
	at1156 := time.Date(2026, 11, 19, 11, 56, 0, 0, time.UTC)
	at1205 := time.Date(2026, 11, 19, 12, 5, 0, 0, time.UTC)
	if parsed.NeedsRefresh(at1150, DefaultRefreshSkew) {
		t.Fatal("should not need refresh 10m before expiry")
	}
	if !parsed.NeedsRefresh(at1156, DefaultRefreshSkew) {
		t.Fatal("should need refresh inside 5m skew window")
	}
	if !parsed.NeedsRefresh(at1205, DefaultRefreshSkew) {
		t.Fatal("should need refresh after expiry")
	}
}

func TestApplyTokenUpdatePreservesUnknownFieldsAndOtherScopes(t *testing.T) {
	raw := []byte(`{
  "xai::api_key": {
    "key": "api-secret",
    "auth_mode": "api_key"
  },
  "https://auth.x.ai::client-abc": {
    "key": "access-old",
    "auth_mode": "oidc",
    "user_id": "user-123",
    "email": "owner@example.com",
    "refresh_token": "refresh-old",
    "expires_at": "2026-11-16T12:00:00Z",
    "oidc_issuer": "https://auth.x.ai",
    "oidc_client_id": "client-abc",
    "coding_data_team": "keep-me",
    "team_zero_data_retention": false
  }
}`)
	parsed, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC)
	updated, err := parsed.ApplyTokenUpdate(TokenUpdate{
		AccessToken:  "access-new",
		RefreshToken: "refresh-rotated",
		ExpiresIn:    21600,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Identity.ID != parsed.Identity.ID {
		t.Fatalf("identity changed: %s != %s", updated.Identity.ID, parsed.Identity.ID)
	}
	if updated.Identity.ExpiresAt != "2026-11-19T16:00:00Z" {
		t.Fatalf("unexpected expiresAt: %q", updated.Identity.ExpiresAt)
	}
	reqCred, ok := updated.XAIRequestCredential()
	if !ok || reqCred.AccessToken != "access-new" {
		t.Fatalf("updated access token missing")
	}
	refCred, ok := updated.XAIRefreshCredential()
	if !ok || refCred.RefreshToken != "refresh-rotated" {
		t.Fatalf("rotated refresh token missing")
	}
	var doc map[string]map[string]any
	if err := json.Unmarshal(updated.Raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["xai::api_key"]["key"] != "api-secret" {
		t.Fatal("other scope was not preserved")
	}
	if doc["https://auth.x.ai::client-abc"]["coding_data_team"] != "keep-me" {
		t.Fatal("unknown field was not preserved")
	}
}

func TestExchangeRefreshTokenSuccessAndReauthErrorsNeverLeakSecret(t *testing.T) {
	secretRefresh := "secret-refresh-token-xyz"
	secretAccess := "secret-access-token-abc"

	t.Run("success", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				t.Errorf("method = %s", r.Method)
			}
			if err := r.ParseForm(); err != nil {
				t.Errorf("parse form: %v", err)
			}
			if r.Form.Get("grant_type") != "refresh_token" ||
				r.Form.Get("refresh_token") != secretRefresh ||
				r.Form.Get("client_id") != "client-1" {
				t.Errorf("unexpected form values")
			}
			_, _ = w.Write([]byte(`{"access_token":"` + secretAccess + `","refresh_token":"rotated-rt","expires_in":21600}`))
		}))
		defer server.Close()

		update, err := ExchangeRefreshToken(context.Background(), server.Client(), server.URL, "client-1", secretRefresh)
		if err != nil {
			t.Fatal(err)
		}
		if update.AccessToken != secretAccess || update.RefreshToken != "rotated-rt" || update.ExpiresIn != 21600 {
			t.Fatalf("unexpected token update: expiresIn=%d", update.ExpiresIn)
		}
	})

	t.Run("invalid_grant", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"revoked ` + secretRefresh + `"}`))
		}))
		defer server.Close()

		_, err := ExchangeRefreshToken(context.Background(), server.Client(), server.URL, "client-1", secretRefresh)
		if !errors.Is(err, ErrRefreshReauthRequired) {
			t.Fatalf("err = %v, want ErrRefreshReauthRequired", err)
		}
		if strings.Contains(err.Error(), secretRefresh) {
			t.Fatalf("secret leaked in error: %v", err)
		}
	})
}
