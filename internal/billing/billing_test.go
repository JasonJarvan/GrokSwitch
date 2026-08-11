package billing

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFetchUsesOfficialHeadersAndParsesCredits(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "format=credits" {
			t.Fatalf("unexpected query: %q", r.URL.RawQuery)
		}
		wantHeaders := map[string]string{
			"Authorization":         "Bearer access-secret",
			"X-XAI-Token-Auth":      "xai-grok-cli",
			"x-userid":              "user-123",
			"x-grok-client-version": "1.2.3",
			"x-grok-client-mode":    "headless",
		}
		for name, want := range wantHeaders {
			if got := r.Header.Get(name); got != want {
				t.Errorf("header %s = %q, want %q", name, got, want)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"config":{"creditUsagePercent":22,"currentPeriod":{"type":"USAGE_PERIOD_TYPE_WEEKLY","end":"2026-08-15T08:23:37Z"}}}`))
	}))
	defer server.Close()

	quota, err := Fetch(context.Background(), server.Client(), server.URL+"?format=credits", "1.2.3", "access-secret", "user-123")
	if err != nil {
		t.Fatal(err)
	}
	if quota.RemainingPercent == nil || *quota.RemainingPercent != 78 {
		t.Fatalf("unexpected remaining quota: %+v", quota)
	}
	if quota.UsedPercent == nil || *quota.UsedPercent != 22 {
		t.Fatalf("unexpected used quota: %+v", quota)
	}
	if quota.ResetAt != "2026-08-15T08:23:37Z" || quota.PeriodType != "USAGE_PERIOD_TYPE_WEEKLY" {
		t.Fatalf("unexpected period: %+v", quota)
	}
}

func TestFetchSupportsLegacyLimitAndNeverEchoesSecretsOnError(t *testing.T) {
	t.Run("legacy", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"config":{"monthlyLimit":{"val":10000},"used":{"val":2500},"billingPeriodEnd":"2026-09-01T00:00:00Z"}}`))
		}))
		defer server.Close()
		quota, err := Fetch(context.Background(), server.Client(), server.URL, "", "secret", "user")
		if err != nil {
			t.Fatal(err)
		}
		if quota.RemainingPercent == nil || *quota.RemainingPercent != 75 || quota.ResetAt != "2026-09-01T00:00:00Z" {
			t.Fatalf("unexpected legacy quota: %+v", quota)
		}
	})

	t.Run("http error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"access-secret"}`))
		}))
		defer server.Close()
		_, err := Fetch(context.Background(), server.Client(), server.URL, "", "access-secret", "user")
		if err == nil {
			t.Fatal("expected HTTP error")
		}
		if strings.Contains(err.Error(), "access-secret") {
			t.Fatalf("error leaked secret: %v", err)
		}
	})
}

func TestFetchTierParsesLiveSubscription(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("include"); got != "subscription" {
			t.Fatalf("include = %q", got)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer tier-secret" {
			t.Fatalf("unexpected authorization header")
		}
		if got := r.Header.Get("x-userid"); got != "" {
			t.Fatalf("tier request unexpectedly sent x-userid: %q", got)
		}
		_, _ = w.Write([]byte(`{"userId":"user-123","subscriptionTier":"XPremium"}`))
	}))
	defer server.Close()
	tier, err := FetchTier(context.Background(), server.Client(), server.URL+"?include=subscription", "1.2.3", "tier-secret")
	if err != nil {
		t.Fatal(err)
	}
	if tier != "XPremium" {
		t.Fatalf("tier = %q", tier)
	}
}

func TestFetchTierRejectsInvalidResponsesWithoutLeakingSecrets(t *testing.T) {
	t.Run("HTTP error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"tier-secret"}`))
		}))
		defer server.Close()
		_, err := FetchTier(context.Background(), server.Client(), server.URL, "", "tier-secret")
		if err == nil || strings.Contains(err.Error(), "tier-secret") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("control characters", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("{\"subscriptionTier\":\"bad\\nvalue\"}"))
		}))
		defer server.Close()
		if _, err := FetchTier(context.Background(), server.Client(), server.URL, "", "token"); err == nil {
			t.Fatal("expected invalid subscriptionTier error")
		}
	})
}
