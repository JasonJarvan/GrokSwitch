package cli

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bbbkawaii/GrokSwitch/internal/accounts"
	"github.com/bbbkawaii/GrokSwitch/internal/billing"
)

func TestImportAndListJSONNeverExposeToken(t *testing.T) {
	root := t.TempDir()
	t.Setenv("GROK_HOME", filepath.Join(root, ".grok"))
	t.Setenv("GROK_SWITCH_HOME", filepath.Join(root, ".grok", "accounts"))
	t.Setenv("GROK_AUTH_PATH", "")
	t.Setenv("GROK_AUTH", "")

	authPath := filepath.Join(root, "import.json")
	secret := "super-secret-test-token"
	auth := `{"https://auth.x.ai::client":{"key":"` + secret + `","auth_mode":"oidc","create_time":"2026-08-01T00:00:00Z","user_id":"cli-user","email":"cli@example.com","refresh_token":"secret-refresh","expires_at":"2030-01-01T00:00:00Z"}}`
	if err := os.WriteFile(authPath, []byte(auth), 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"import", authPath, "--alias", "cli", "--switch", "--json"}, strings.NewReader(""), &out, &errOut)
	if code != 0 {
		t.Fatalf("import exit=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	if strings.Contains(out.String(), secret) || strings.Contains(out.String(), "secret-refresh") {
		t.Fatalf("secret leaked in import JSON: %s", out.String())
	}

	out.Reset()
	errOut.Reset()
	code = Run([]string{"list", "--json", "--offline"}, strings.NewReader(""), &out, &errOut)
	if code != 0 {
		t.Fatalf("list exit=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	if strings.Contains(out.String(), secret) || strings.Contains(out.String(), "secret-refresh") {
		t.Fatalf("secret leaked in list JSON: %s", out.String())
	}
	if !strings.Contains(out.String(), `"alias": "cli"`) || !strings.Contains(out.String(), `"email": "cli@example.com"`) {
		t.Fatalf("expected account metadata in JSON: %s", out.String())
	}
}

func TestPrintAccountsShowsQuotaAndResetInsteadOfInternalMetadata(t *testing.T) {
	oldLocal := time.Local
	time.Local = time.FixedZone("CST", 8*60*60)
	defer func() { time.Local = oldLocal }()

	remaining := 78.0
	reg := &accounts.Registry{Accounts: []accounts.Account{
		{
			ID: "acc_11111111111111111111", Alias: "personal", Email: "owner@example.com",
			AuthMode: "oidc", TeamName: "internal-team", ExpiresAt: "2030-01-01T00:00:00Z",
		},
	}}
	quotas := map[string]billing.Quota{
		reg.Accounts[0].ID: {
			RemainingPercent: &remaining,
			ResetAt:          "2026-08-15T08:23:37Z",
			Tier:             "GrokPro",
		},
	}
	var out bytes.Buffer
	printAccounts(&out, reg, reg.Accounts[0].ID, quotas)
	value := out.String()
	for _, want := range []string{"TIER", "GrokPro", "QUOTA LEFT", "RESETS AT", "78%", "08-15 16:23"} {
		if !strings.Contains(value, want) {
			t.Fatalf("list output missing %q: %s", want, value)
		}
	}
	for _, removed := range []string{"MODE", "TEAM / ORG", "EXPIRES", "internal-team", "11111111"} {
		if strings.Contains(value, removed) {
			t.Fatalf("list output still contains removed field %q: %s", removed, value)
		}
	}
}

func TestCPAImportNeverExposesTokensAndReportsDisabledSource(t *testing.T) {
	root := t.TempDir()
	t.Setenv("GROK_HOME", filepath.Join(root, ".grok"))
	t.Setenv("GROK_SWITCH_HOME", filepath.Join(root, ".grok", "accounts"))
	t.Setenv("GROK_AUTH_PATH", "")
	t.Setenv("GROK_AUTH", "")

	issuedAt := time.Date(2026, 8, 12, 8, 0, 0, 0, time.UTC)
	expiresAt := issuedAt.Add(time.Hour)
	accessToken := cliTestJWT(t, map[string]any{
		"iss": "https://auth.x.ai", "sub": "cpa-user", "client_id": "client-123",
		"iat": issuedAt.Unix(), "exp": expiresAt.Unix(),
	})
	idToken := cliTestJWT(t, map[string]any{
		"iss": "https://auth.x.ai", "sub": "cpa-user", "aud": "client-123",
		"email": "cpa@example.com", "iat": issuedAt.Unix(), "exp": expiresAt.Add(time.Hour).Unix(),
	})
	refreshToken := "cli-cpa-refresh-secret"
	document, err := json.Marshal(map[string]any{
		"type": "xai", "auth_kind": "oauth", "disabled": true,
		"access_token": accessToken, "id_token": idToken, "refresh_token": refreshToken,
		"sub": "cpa-user", "email": "cpa@example.com",
		"last_refresh": issuedAt.Format(time.RFC3339), "expired": expiresAt.Format(time.RFC3339),
	})
	if err != nil {
		t.Fatal(err)
	}
	cpaPath := filepath.Join(root, "cpa.json")
	if err := os.WriteFile(cpaPath, document, 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"import", "--cpa", cpaPath, "--alias", "cpa", "--json"}, strings.NewReader(""), &out, &errOut)
	if code != 0 {
		t.Fatalf("CPA import exit=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	for _, secret := range []string{accessToken, idToken, refreshToken} {
		if strings.Contains(out.String(), secret) || strings.Contains(errOut.String(), secret) {
			t.Fatalf("CPA token leaked in command output")
		}
	}
	if !strings.Contains(out.String(), `"format": "CPA"`) || !strings.Contains(out.String(), `"sourceDisabled": true`) {
		t.Fatalf("CPA metadata missing from output: %s", out.String())
	}
	if !strings.Contains(out.String(), `"email": "cpa@example.com"`) {
		t.Fatalf("account metadata missing from output: %s", out.String())
	}
}

func TestSwitchJSONRequiresExplicitQuery(t *testing.T) {
	root := t.TempDir()
	t.Setenv("GROK_HOME", filepath.Join(root, ".grok"))
	t.Setenv("GROK_SWITCH_HOME", filepath.Join(root, ".grok", "accounts"))
	t.Setenv("GROK_AUTH_PATH", "")
	t.Setenv("GROK_AUTH", "")
	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"switch", "--json"}, strings.NewReader(""), &out, &errOut)
	if code == 0 || !strings.Contains(errOut.String(), "requires an explicit account query") {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
}

func TestVersionDoesNotNeedFilesystemState(t *testing.T) {
	old := Version
	Version = "test-version"
	defer func() { Version = old }()
	var out bytes.Buffer
	code := Run([]string{"version"}, strings.NewReader(""), &out, &bytes.Buffer{})
	if code != 0 || out.String() != "grok-switch test-version\n" {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
}

func TestCommandHelpDoesNotNeedFilesystemState(t *testing.T) {
	t.Setenv("HOME", filepath.Join(t.TempDir(), "missing"))
	for _, args := range [][]string{{"list", "--help"}, {"import", "-h"}} {
		var out bytes.Buffer
		var errOut bytes.Buffer
		code := Run(args, strings.NewReader(""), &out, &errOut)
		if code != 0 || !strings.Contains(out.String(), "Usage:") || errOut.Len() != 0 {
			t.Fatalf("args=%v exit=%d stdout=%q stderr=%q", args, code, out.String(), errOut.String())
		}
	}
}

func TestRunPassesHelpAfterSeparatorToGrok(t *testing.T) {
	if hasHelpFlag([]string{"account", "--", "--help"}) {
		t.Fatal("--help after the passthrough separator must be handled by Grok")
	}
}

func cliTestJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return header + "." + base64.RawURLEncoding.EncodeToString(payload) + ".test-signature"
}
