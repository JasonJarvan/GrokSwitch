package grokauth

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

const testCPAClientID = "b1a00492-073a-47ea-816f-4c329264a828"

func TestConvertCPAProducesGrokOIDCSnapshot(t *testing.T) {
	issuedAt := time.Date(2026, 8, 12, 8, 0, 0, 0, time.UTC)
	expiresAt := issuedAt.Add(time.Hour)
	data, accessToken, idToken, refreshToken := fakeCPA(t, issuedAt, expiresAt, true, nil)

	converted, info, err := ConvertCPA(data, issuedAt.Add(10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if !info.SourceDisabled || info.AccessTokenExpired {
		t.Fatalf("unexpected CPA info: %+v", info)
	}
	if converted.Identity.Email != "owner@example.com" || converted.Identity.UserID != "user-123" {
		t.Fatalf("unexpected identity: %+v", converted.Identity)
	}
	if converted.Identity.DisplayName != "Grok Owner" {
		t.Fatalf("unexpected display name: %q", converted.Identity.DisplayName)
	}
	wantScope := "https://auth.x.ai::" + testCPAClientID
	if converted.Identity.Scope != wantScope || converted.Identity.AuthMode != "oidc" {
		t.Fatalf("unexpected scope/mode: %+v", converted.Identity)
	}
	if !strings.Contains(string(converted.Raw), accessToken) || !strings.Contains(string(converted.Raw), refreshToken) {
		t.Fatal("converted snapshot is missing the access or refresh token")
	}
	if strings.Contains(string(converted.Raw), idToken) || strings.Contains(string(converted.Raw), `"disabled"`) {
		t.Fatal("converted snapshot retained CPA-only fields")
	}

	var raw map[string]Credential
	if err := json.Unmarshal(converted.Raw, &raw); err != nil {
		t.Fatal(err)
	}
	credential := raw[wantScope]
	if credential.OIDCIssuer != "https://auth.x.ai" || credential.OIDCClientID != testCPAClientID {
		t.Fatalf("unexpected OIDC metadata: %+v", credential)
	}
	if credential.PrincipalID != "principal-123" || credential.TeamID != "team-123" {
		t.Fatalf("principal metadata was not copied: %+v", credential)
	}
	if credential.CodingDataRetentionOpt == nil || !*credential.CodingDataRetentionOpt {
		t.Fatal("privacy-safe retention default was not set")
	}
}

func TestConvertCPAReportsExpiredAccessToken(t *testing.T) {
	issuedAt := time.Date(2026, 8, 12, 8, 0, 0, 0, time.UTC)
	expiresAt := issuedAt.Add(time.Hour)
	data, _, _, _ := fakeCPA(t, issuedAt, expiresAt, false, nil)
	_, info, err := ConvertCPA(data, expiresAt)
	if err != nil {
		t.Fatal(err)
	}
	if !info.AccessTokenExpired || info.SourceDisabled {
		t.Fatalf("unexpected CPA info: %+v", info)
	}
}

func TestConvertCPARejectsMismatchedOrInvalidClaimsWithoutLeakingTokens(t *testing.T) {
	issuedAt := time.Date(2026, 8, 12, 8, 0, 0, 0, time.UTC)
	expiresAt := issuedAt.Add(time.Hour)
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{
			name: "wrong provider type",
			mutate: func(doc map[string]any) {
				doc["type"] = "openai"
			},
		},
		{
			name: "malformed access token",
			mutate: func(doc map[string]any) {
				doc["access_token"] = "not-a-jwt"
			},
		},
		{
			name: "wrong issuer",
			mutate: func(doc map[string]any) {
				doc["access_token"] = testJWT(t, map[string]any{
					"iss": "https://example.com", "sub": "user-123", "client_id": testCPAClientID,
					"iat": issuedAt.Unix(), "exp": expiresAt.Unix(),
				})
			},
		},
		{
			name: "mismatched subject",
			mutate: func(doc map[string]any) {
				doc["sub"] = "another-user"
			},
		},
		{
			name: "mismatched client",
			mutate: func(doc map[string]any) {
				doc["id_token"] = testJWT(t, map[string]any{
					"iss": "https://auth.x.ai", "sub": "user-123", "aud": "different-client",
					"email": "owner@example.com", "iat": issuedAt.Unix(), "exp": expiresAt.Unix(),
				})
			},
		},
		{
			name: "mismatched expiry",
			mutate: func(doc map[string]any) {
				doc["expired"] = expiresAt.Add(time.Hour).Format(time.RFC3339)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data, accessToken, idToken, refreshToken := fakeCPA(t, issuedAt, expiresAt, false, test.mutate)
			_, _, err := ConvertCPA(data, issuedAt)
			if err == nil {
				t.Fatal("expected conversion error")
			}
			for _, secret := range []string{accessToken, idToken, refreshToken} {
				if strings.Contains(err.Error(), secret) {
					t.Fatalf("conversion error leaked a token: %v", err)
				}
			}
		})
	}
}

func fakeCPA(t *testing.T, issuedAt, expiresAt time.Time, disabled bool, mutate func(map[string]any)) ([]byte, string, string, string) {
	t.Helper()
	accessToken := testJWT(t, map[string]any{
		"iss":            "https://auth.x.ai",
		"sub":            "user-123",
		"aud":            "https://api.x.ai",
		"client_id":      testCPAClientID,
		"iat":            issuedAt.Unix(),
		"exp":            expiresAt.Unix(),
		"principal_type": "user",
		"principal_id":   "principal-123",
		"team_id":        "team-123",
	})
	idToken := testJWT(t, map[string]any{
		"iss":         "https://auth.x.ai",
		"sub":         "user-123",
		"aud":         testCPAClientID,
		"email":       "owner@example.com",
		"given_name":  "Grok",
		"family_name": "Owner",
		"iat":         issuedAt.Unix(),
		"exp":         expiresAt.Add(time.Hour).Unix(),
	})
	refreshToken := "refresh-token-secret"
	doc := map[string]any{
		"type":          "xai",
		"auth_kind":     "oauth",
		"access_token":  accessToken,
		"id_token":      idToken,
		"refresh_token": refreshToken,
		"email":         "owner@example.com",
		"sub":           "user-123",
		"expired":       expiresAt.Format(time.RFC3339),
		"last_refresh":  issuedAt.Format(time.RFC3339),
		"disabled":      disabled,
	}
	if mutate != nil {
		mutate(doc)
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return data, accessToken, idToken, refreshToken
}

func testJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return header + "." + base64.RawURLEncoding.EncodeToString(payload) + ".test-signature"
}
