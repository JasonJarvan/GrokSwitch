package grokauth

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	maxJWTPayloadSize = 64 << 10
	clockTolerance    = 5 * time.Minute
)

// CPAInfo contains non-secret state carried by CLIProxyAPI's flat xAI token
// document. A disabled CPA pool entry can still contain a valid token bundle,
// so the flag is reported to callers rather than treated as an auth failure.
type CPAInfo struct {
	SourceDisabled     bool `json:"sourceDisabled,omitempty"`
	AccessTokenExpired bool `json:"accessTokenExpired,omitempty"`
}

type cpaDocument struct {
	Type         string `json:"type"`
	AuthKind     string `json:"auth_kind"`
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	Email        string `json:"email"`
	Subject      string `json:"sub"`
	Expired      string `json:"expired"`
	LastRefresh  string `json:"last_refresh"`
	Disabled     bool   `json:"disabled"`
}

type jwtClaims struct {
	Issuer        string          `json:"iss"`
	Subject       string          `json:"sub"`
	Audience      json.RawMessage `json:"aud"`
	ClientID      string          `json:"client_id"`
	Email         string          `json:"email"`
	GivenName     string          `json:"given_name"`
	FamilyName    string          `json:"family_name"`
	PrincipalType string          `json:"principal_type"`
	PrincipalID   string          `json:"principal_id"`
	TeamID        string          `json:"team_id"`
	IssuedAt      json.Number     `json:"iat"`
	ExpiresAt     json.Number     `json:"exp"`
}

// ConvertCPA converts a flat CLIProxyAPI xAI OAuth token file into Grok
// Build's auth.json format. JWT signatures are not treated as locally trusted:
// the claims are used only to construct and cross-check the snapshot, while
// xAI still validates the bearer and refresh tokens when Grok uses them.
func ConvertCPA(data []byte, now time.Time) (*File, CPAInfo, error) {
	var info CPAInfo
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, info, errors.New("CPA file is empty")
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var doc cpaDocument
	if err := dec.Decode(&doc); err != nil {
		return nil, info, fmt.Errorf("invalid CPA JSON: %w", err)
	}
	if err := ensureEOF(dec); err != nil {
		return nil, info, fmt.Errorf("invalid CPA JSON: %w", err)
	}
	info.SourceDisabled = doc.Disabled

	if value := strings.TrimSpace(doc.Type); value != "" && !strings.EqualFold(value, "xai") {
		return nil, info, fmt.Errorf("CPA file type is %q, expected xai", value)
	}
	if value := strings.TrimSpace(doc.AuthKind); value != "" && !strings.EqualFold(value, "oauth") {
		return nil, info, fmt.Errorf("CPA auth_kind is %q, expected oauth", value)
	}
	if err := cleanSecretField(doc.AccessToken, "access_token", true); err != nil {
		return nil, info, err
	}
	if err := cleanSecretField(doc.IDToken, "id_token", true); err != nil {
		return nil, info, err
	}
	if err := cleanSecretField(doc.RefreshToken, "refresh_token", false); err != nil {
		return nil, info, err
	}

	access, err := decodeJWTClaims(doc.AccessToken, "access_token")
	if err != nil {
		return nil, info, err
	}
	id, err := decodeJWTClaims(doc.IDToken, "id_token")
	if err != nil {
		return nil, info, err
	}

	issuer, err := normalizeXAIIssuer(access.Issuer)
	if err != nil {
		return nil, info, fmt.Errorf("access_token issuer: %w", err)
	}
	idIssuer, err := normalizeXAIIssuer(id.Issuer)
	if err != nil {
		return nil, info, fmt.Errorf("id_token issuer: %w", err)
	}
	if issuer != idIssuer {
		return nil, info, errors.New("access_token and id_token issuers do not match")
	}

	clientID := strings.TrimSpace(access.ClientID)
	if clientID == "" {
		return nil, info, errors.New("access_token has no client_id claim")
	}
	audiences, err := parseAudiences(id.Audience)
	if err != nil {
		return nil, info, fmt.Errorf("id_token aud claim: %w", err)
	}
	if !containsString(audiences, clientID) {
		return nil, info, errors.New("access_token client_id is not an id_token audience")
	}

	userID := strings.TrimSpace(access.Subject)
	if userID == "" {
		return nil, info, errors.New("access_token has no sub claim")
	}
	if err := matchingOptionalField("sub", userID, id.Subject, doc.Subject, false); err != nil {
		return nil, info, err
	}

	email := strings.TrimSpace(doc.Email)
	if email == "" {
		email = strings.TrimSpace(id.Email)
	}
	if email != "" {
		if err := matchingOptionalField("email", email, id.Email, "", true); err != nil {
			return nil, info, err
		}
	}

	issuedAt, err := unixTimeClaim(access.IssuedAt, "access_token iat")
	if err != nil {
		return nil, info, err
	}
	expiresAt, err := unixTimeClaim(access.ExpiresAt, "access_token exp")
	if err != nil {
		return nil, info, err
	}
	if !expiresAt.After(issuedAt) {
		return nil, info, errors.New("access_token exp must be after iat")
	}
	if err := matchingTimestamp("last_refresh", doc.LastRefresh, issuedAt); err != nil {
		return nil, info, err
	}
	if err := matchingTimestamp("expired", doc.Expired, expiresAt); err != nil {
		return nil, info, err
	}
	info.AccessTokenExpired = !now.IsZero() && !now.Before(expiresAt)

	credential := map[string]any{
		"key":                           doc.AccessToken,
		"auth_mode":                     "oidc",
		"create_time":                   issuedAt.UTC().Format(time.RFC3339),
		"user_id":                       userID,
		"expires_at":                    expiresAt.UTC().Format(time.RFC3339),
		"oidc_issuer":                   issuer,
		"oidc_client_id":                clientID,
		"coding_data_retention_opt_out": true,
	}
	putNonEmpty(credential, "email", email)
	putNonEmpty(credential, "first_name", id.GivenName)
	putNonEmpty(credential, "last_name", id.FamilyName)
	putNonEmpty(credential, "principal_type", access.PrincipalType)
	putNonEmpty(credential, "principal_id", access.PrincipalID)
	putNonEmpty(credential, "team_id", access.TeamID)
	if doc.RefreshToken != "" {
		credential["refresh_token"] = doc.RefreshToken
	}

	scope := issuer + "::" + clientID
	converted, err := json.MarshalIndent(map[string]any{scope: credential}, "", "  ")
	if err != nil {
		return nil, info, fmt.Errorf("encode converted Grok auth: %w", err)
	}
	converted = append(converted, '\n')
	authFile, err := Parse(converted)
	if err != nil {
		return nil, info, fmt.Errorf("validate converted Grok auth: %w", err)
	}
	return authFile, info, nil
}

func cleanSecretField(value, name string, required bool) error {
	if value == "" {
		if required {
			return fmt.Errorf("CPA file has no %s", name)
		}
		return nil
	}
	if strings.TrimSpace(value) != value {
		return fmt.Errorf("CPA %s contains leading or trailing whitespace", name)
	}
	return nil
}

func decodeJWTClaims(token, label string) (jwtClaims, error) {
	var claims jwtClaims
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return claims, fmt.Errorf("CPA %s is not a three-part JWT", label)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return claims, fmt.Errorf("CPA %s has an invalid JWT payload", label)
	}
	if len(payload) > maxJWTPayloadSize {
		return claims, fmt.Errorf("CPA %s JWT payload exceeds 64 KiB", label)
	}
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	if err := dec.Decode(&claims); err != nil {
		return claims, fmt.Errorf("CPA %s has invalid JWT claims: %w", label, err)
	}
	if err := ensureEOF(dec); err != nil {
		return claims, fmt.Errorf("CPA %s has invalid JWT claims: %w", label, err)
	}
	return claims, nil
}

func normalizeXAIIssuer(value string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil {
		return "", errors.New("is not a valid URL")
	}
	if parsed.Scheme != "https" || !strings.EqualFold(parsed.Hostname(), "auth.x.ai") || parsed.Port() != "" {
		return "", errors.New("must be https://auth.x.ai")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return "", errors.New("must be the https://auth.x.ai origin")
	}
	return "https://auth.x.ai", nil
}

func parseAudiences(raw json.RawMessage) ([]string, error) {
	if len(bytes.TrimSpace(raw)) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, errors.New("is missing")
	}
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		if strings.TrimSpace(single) == "" {
			return nil, errors.New("is empty")
		}
		return []string{strings.TrimSpace(single)}, nil
	}
	var multiple []string
	if err := json.Unmarshal(raw, &multiple); err != nil {
		return nil, errors.New("must be a string or string array")
	}
	result := make([]string, 0, len(multiple))
	for _, value := range multiple {
		if value = strings.TrimSpace(value); value != "" {
			result = append(result, value)
		}
	}
	if len(result) == 0 {
		return nil, errors.New("is empty")
	}
	return result, nil
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func matchingOptionalField(name, canonical string, first, second string, foldCase bool) error {
	equal := func(left, right string) bool {
		left = strings.TrimSpace(left)
		right = strings.TrimSpace(right)
		if foldCase {
			return strings.EqualFold(left, right)
		}
		return left == right
	}
	for _, value := range []string{first, second} {
		if strings.TrimSpace(value) != "" && !equal(canonical, value) {
			return fmt.Errorf("CPA %s fields do not match", name)
		}
	}
	return nil
}

func unixTimeClaim(number json.Number, label string) (time.Time, error) {
	if number == "" {
		return time.Time{}, fmt.Errorf("%s claim is missing", label)
	}
	seconds, err := number.Int64()
	if err != nil {
		return time.Time{}, fmt.Errorf("%s claim must be an integer", label)
	}
	return time.Unix(seconds, 0).UTC(), nil
}

func matchingTimestamp(name, value string, tokenTime time.Time) error {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(value))
	if err != nil {
		return fmt.Errorf("CPA %s is not RFC3339", name)
	}
	delta := parsed.Sub(tokenTime)
	if delta < -clockTolerance || delta > clockTolerance {
		return fmt.Errorf("CPA %s does not match the access_token", name)
	}
	return nil
}

func putNonEmpty(target map[string]any, key, value string) {
	if value = strings.TrimSpace(value); value != "" {
		target[key] = value
	}
}
