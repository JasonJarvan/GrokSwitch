package grokauth

import (
	"strings"
	"testing"
	"time"
)

func TestParsePrefersOAuthAndKeepsIdentityStableAfterEnrichment(t *testing.T) {
	before := []byte(`{
  "xai::api_key": {
    "key": "xai-test-api-key",
    "auth_mode": "api_key",
    "create_time": "2026-08-01T00:00:00Z",
    "user_id": ""
  },
  "https://auth.x.ai::client": {
    "key": "oauth-access-token",
    "auth_mode": "oidc",
    "create_time": "2026-08-01T00:00:00Z",
    "user_id": "user-123",
    "email": "owner@example.com",
    "refresh_token": "oauth-refresh-token",
    "expires_at": "2030-01-01T00:00:00Z",
    "future_field": "preserve-me"
  }
}`)
	after := []byte(`{
  "https://auth.x.ai::client": {
    "key": "rotated-access-token",
    "auth_mode": "oidc",
    "create_time": "2026-08-01T00:00:00Z",
    "user_id": "user-123",
    "email": "owner@example.com",
    "principal_id": "principal-later",
    "team_id": "team-later",
    "team_name": "Example Team",
    "refresh_token": "rotated-refresh-token",
    "expires_at": "2031-01-01T00:00:00Z"
  }
}`)

	parsedBefore, err := Parse(before)
	if err != nil {
		t.Fatal(err)
	}
	parsedAfter, err := Parse(after)
	if err != nil {
		t.Fatal(err)
	}
	if parsedBefore.Identity.AuthMode != "oidc" {
		t.Fatalf("expected oidc primary credential, got %q", parsedBefore.Identity.AuthMode)
	}
	if parsedBefore.Identity.Email != "owner@example.com" {
		t.Fatalf("unexpected email: %q", parsedBefore.Identity.Email)
	}
	if parsedBefore.Identity.ID != parsedAfter.Identity.ID {
		t.Fatalf("identity changed after enrichment: %s != %s", parsedBefore.Identity.ID, parsedAfter.Identity.ID)
	}
	if string(parsedBefore.Raw) != string(before) {
		t.Fatal("raw auth bytes were not preserved")
	}
	requestCredential, ok := parsedBefore.XAIRequestCredential()
	if !ok || requestCredential.AccessToken != "oauth-access-token" || requestCredential.UserID != "user-123" {
		t.Fatalf("unexpected request credential: ok=%v user=%q", ok, requestCredential.UserID)
	}
	for _, secret := range []string{"oauth-access-token", "oauth-refresh-token", "xai-test-api-key"} {
		if strings.Contains(parsedBefore.Identity.ID, secret) || strings.Contains(parsedBefore.Identity.Email, secret) {
			t.Fatalf("secret leaked into identity: %q", secret)
		}
	}
}

func TestParseRejectsInvalidDocuments(t *testing.T) {
	tests := [][]byte{
		{},
		[]byte(`{}`),
		[]byte(`{"scope":{"auth_mode":"oidc"}}`),
		[]byte(`{"scope":{"key":"token"}}`),
		[]byte(`{"scope":{"key":"token","auth_mode":"oidc"}} trailing`),
	}
	for _, input := range tests {
		if _, err := Parse(input); err == nil {
			t.Fatalf("expected parse error for %q", input)
		}
	}
}

func TestIdentityExpiry(t *testing.T) {
	now := time.Date(2026, 8, 12, 0, 0, 0, 0, time.UTC)
	if got := (Identity{}).Expiry(now); got != "unknown" {
		t.Fatalf("got %q", got)
	}
	if got := (Identity{ExpiresAt: "2026-08-11T00:00:00Z"}).Expiry(now); got != "expired" {
		t.Fatalf("got %q", got)
	}
	if got := (Identity{ExpiresAt: "2026-08-15T00:00:00Z"}).Expiry(now); got != "3d" {
		t.Fatalf("got %q", got)
	}
}
