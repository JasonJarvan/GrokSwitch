package grokauth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultOIDCIssuer   = "https://auth.x.ai"
	DefaultTokenURL     = DefaultOIDCIssuer + "/oauth2/token"
	DefaultOIDCClientID = "b1a00492-073a-47ea-816f-4c329264a828"
	DefaultRefreshSkew  = 5 * time.Minute
)

var (
	// ErrNoRefreshToken indicates the saved credential cannot be refreshed via xAI OIDC.
	ErrNoRefreshToken = errors.New("account does not have an xAI OIDC refresh token")
	// ErrRefreshReauthRequired indicates xAI rejected the refresh grant and the user must sign in again.
	ErrRefreshReauthRequired = errors.New("refresh token was rejected by xAI; re-login required")
)

// RefreshCredential holds the minimal material needed to renew a first-party
// xAI OIDC session. Callers must never log, print, or serialize RefreshToken.
type RefreshCredential struct {
	RefreshToken string
	ClientID     string
	TokenURL     string
	Scope        string
}

// TokenUpdate is the token bundle returned by xAI's OIDC token endpoint.
// Callers must never log or print AccessToken or RefreshToken.
type TokenUpdate struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int64
}

// XAIRefreshCredential returns the refresh material only for first-party
// xAI OIDC credentials that include a refresh token.
func (f *File) XAIRefreshCredential() (RefreshCredential, bool) {
	mode := strings.ToLower(strings.TrimSpace(f.primary.AuthMode))
	issuer := strings.TrimRight(strings.TrimSpace(f.primary.OIDCIssuer), "/")
	issuerLower := strings.ToLower(issuer)
	scopeLower := strings.ToLower(strings.TrimSpace(f.primaryScope))
	firstPartyScope := strings.HasPrefix(scopeLower, DefaultOIDCIssuer+"::")
	if mode != "oidc" || (issuerLower != DefaultOIDCIssuer && !firstPartyScope) {
		return RefreshCredential{}, false
	}
	refreshToken := strings.TrimSpace(f.primary.RefreshToken)
	if refreshToken == "" {
		return RefreshCredential{}, false
	}
	clientID := strings.TrimSpace(f.primary.OIDCClientID)
	if clientID == "" {
		if _, after, ok := strings.Cut(strings.TrimSpace(f.primaryScope), "::"); ok && strings.TrimSpace(after) != "" {
			clientID = strings.TrimSpace(after)
		} else {
			clientID = DefaultOIDCClientID
		}
	}
	tokenURL := DefaultTokenURL
	if issuer != "" {
		tokenURL = issuer + "/oauth2/token"
	}
	return RefreshCredential{
		RefreshToken: refreshToken,
		ClientID:     clientID,
		TokenURL:     tokenURL,
		Scope:        f.primaryScope,
	}, true
}

// NeedsRefresh reports whether the primary access token is expired or will
// expire within skew of now.
func (f *File) NeedsRefresh(now time.Time, skew time.Duration) bool {
	if skew < 0 {
		skew = 0
	}
	if expStr := strings.TrimSpace(f.Identity.ExpiresAt); expStr != "" {
		if exp, err := time.Parse(time.RFC3339Nano, expStr); err == nil {
			return exp.Sub(now) <= skew
		}
	}
	if exp, ok := jwtExpiry(f.primary.Key); ok {
		return exp.Sub(now) <= skew
	}
	return false
}

// ExchangeRefreshToken calls xAI's OAuth2 token endpoint with grant_type=refresh_token.
// Returned errors never contain credentials or raw response payloads.
func ExchangeRefreshToken(ctx context.Context, client *http.Client, tokenURL, clientID, refreshToken string) (TokenUpdate, error) {
	if client == nil {
		return TokenUpdate{}, errors.New("token refresh HTTP client is not configured")
	}
	tokenURL = strings.TrimSpace(tokenURL)
	clientID = strings.TrimSpace(clientID)
	refreshToken = strings.TrimSpace(refreshToken)
	if tokenURL == "" || clientID == "" || refreshToken == "" {
		return TokenUpdate{}, errors.New("token refresh credential is incomplete")
	}

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {clientID},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return TokenUpdate{}, fmt.Errorf("create token refresh request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return TokenUpdate{}, fmt.Errorf("request xAI token refresh: %w", err)
	}
	defer resp.Body.Close()

	const maxResponse = 1 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return TokenUpdate{}, fmt.Errorf("read xAI token refresh response: %w", err)
	}
	if len(body) > maxResponse {
		return TokenUpdate{}, errors.New("xAI token refresh response exceeds 1 MiB")
	}

	payload, parseErr := decodeTokenObject(body)
	if parseErr == nil {
		if code := safeOAuthErrorCode(payload["error"]); code != "" {
			if isReauthOAuthError(code) {
				return TokenUpdate{}, fmt.Errorf("%w (%s)", ErrRefreshReauthRequired, code)
			}
			return TokenUpdate{}, fmt.Errorf("xAI token refresh failed (%s)", code)
		}
	}

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return TokenUpdate{}, fmt.Errorf("%w (HTTP %d)", ErrRefreshReauthRequired, resp.StatusCode)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return TokenUpdate{}, fmt.Errorf("xAI token refresh returned HTTP %d", resp.StatusCode)
	}
	if parseErr != nil {
		return TokenUpdate{}, errors.New("xAI token refresh returned malformed JSON")
	}

	accessToken := stringField(payload["access_token"])
	if accessToken == "" {
		return TokenUpdate{}, errors.New("xAI token refresh response omitted access_token")
	}
	update := TokenUpdate{
		AccessToken:  accessToken,
		RefreshToken: stringField(payload["refresh_token"]),
		ExpiresIn:    int64Field(payload["expires_in"]),
	}
	return update, nil
}

// ApplyTokenUpdate merges a refreshed token bundle into the primary scope while
// preserving all other scopes and unknown credential fields.
func (f *File) ApplyTokenUpdate(update TokenUpdate, now time.Time) (*File, error) {
	accessToken := strings.TrimSpace(update.AccessToken)
	if accessToken == "" {
		return nil, errors.New("refreshed access token is empty")
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(f.Raw, &root); err != nil {
		return nil, fmt.Errorf("decode auth document for refresh: %w", err)
	}
	scopePayload, ok := root[f.primaryScope]
	if !ok {
		return nil, fmt.Errorf("primary scope %q missing from auth document", f.primaryScope)
	}
	var cred map[string]any
	if err := json.Unmarshal(scopePayload, &cred); err != nil {
		return nil, fmt.Errorf("decode credential for refresh: %w", err)
	}

	cred["key"] = accessToken
	if rotated := strings.TrimSpace(update.RefreshToken); rotated != "" {
		cred["refresh_token"] = rotated
	}
	if update.ExpiresIn > 0 {
		cred["expires_at"] = now.UTC().Add(time.Duration(update.ExpiresIn) * time.Second).Format(time.RFC3339Nano)
	} else if exp, ok := jwtExpiry(accessToken); ok {
		cred["expires_at"] = exp.UTC().Format(time.RFC3339Nano)
	}

	encodedCred, err := json.Marshal(cred)
	if err != nil {
		return nil, fmt.Errorf("encode refreshed credential: %w", err)
	}
	root[f.primaryScope] = encodedCred
	encodedRoot, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode refreshed auth document: %w", err)
	}
	encodedRoot = append(encodedRoot, '\n')

	updated, err := Parse(encodedRoot)
	if err != nil {
		return nil, fmt.Errorf("validate refreshed auth document: %w", err)
	}
	if updated.Identity.ID != f.Identity.ID {
		return nil, errors.New("refreshed auth document changed account identity")
	}
	return updated, nil
}

func decodeTokenObject(body []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var obj map[string]any
	if err := dec.Decode(&obj); err != nil {
		return nil, err
	}
	if obj == nil {
		return nil, errors.New("empty JSON object")
	}
	return obj, nil
}

func stringField(v any) string {
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(s)
}

func int64Field(v any) int64 {
	switch value := v.(type) {
	case json.Number:
		if n, err := value.Int64(); err == nil {
			return n
		}
		if f, err := value.Float64(); err == nil && f > 0 {
			return int64(f)
		}
	case float64:
		if value > 0 {
			return int64(value)
		}
	case string:
		if n, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64); err == nil {
			return n
		}
	}
	return 0
}

func safeOAuthErrorCode(v any) string {
	code := strings.ToLower(stringField(v))
	if code == "" || len(code) > 64 {
		return ""
	}
	for _, r := range code {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			continue
		}
		return ""
	}
	return code
}

func isReauthOAuthError(code string) bool {
	switch code {
	case "invalid_grant", "invalid_token", "access_denied", "unauthorized_client":
		return true
	default:
		return false
	}
}

func jwtExpiry(token string) (time.Time, bool) {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 {
		return time.Time{}, false
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, false
	}
	obj, err := decodeTokenObject(payloadBytes)
	if err != nil {
		return time.Time{}, false
	}
	exp := int64Field(obj["exp"])
	if exp <= 0 {
		return time.Time{}, false
	}
	return time.Unix(exp, 0).UTC(), true
}
