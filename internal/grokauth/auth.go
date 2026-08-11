package grokauth

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

// Credential mirrors the public, non-secret metadata in Grok Build's
// auth.json format. Key and RefreshToken are parsed only so the file can be
// validated; callers must never print them.
type Credential struct {
	Key                    string   `json:"key"`
	AuthMode               string   `json:"auth_mode"`
	CreateTime             string   `json:"create_time"`
	UserID                 string   `json:"user_id"`
	Email                  string   `json:"email"`
	FirstName              string   `json:"first_name"`
	LastName               string   `json:"last_name"`
	PrincipalType          string   `json:"principal_type"`
	PrincipalID            string   `json:"principal_id"`
	TeamID                 string   `json:"team_id"`
	TeamName               string   `json:"team_name"`
	OrganizationID         string   `json:"organization_id"`
	OrganizationName       string   `json:"organization_name"`
	ExpiresAt              string   `json:"expires_at"`
	OIDCIssuer             string   `json:"oidc_issuer"`
	OIDCClientID           string   `json:"oidc_client_id"`
	RefreshToken           string   `json:"refresh_token"`
	TeamBlockedReasons     []string `json:"team_blocked_reasons"`
	CodingDataRetentionOpt *bool    `json:"coding_data_retention_opt_out"`
}

// Identity is safe to display and persist in GrokSwitch's registry. It never
// contains access keys or refresh tokens.
type Identity struct {
	ID               string `json:"id"`
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
	CredentialCount  int    `json:"credentialCount"`
}

// RequestCredential is the minimal secret material needed for authenticated
// read-only Grok endpoints. Callers must never log or serialize it.
type RequestCredential struct {
	AccessToken string
	UserID      string
}

// File is a validated auth.json document.
type File struct {
	Identity     Identity
	Raw          []byte
	primary      Credential
	primaryScope string
}

// Parse validates an auth.json document and derives a stable account identity.
// Unknown fields are deliberately preserved by retaining the original bytes.
func Parse(data []byte) (*File, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, errors.New("auth file is empty")
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	var raw map[string]json.RawMessage
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("invalid auth JSON: %w", err)
	}
	if err := ensureEOF(dec); err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, errors.New("auth file contains no credentials")
	}

	type candidate struct {
		scope string
		cred  Credential
		score int
	}
	candidates := make([]candidate, 0, len(raw))
	for scope, payload := range raw {
		if strings.TrimSpace(scope) == "" {
			return nil, errors.New("auth file contains an empty credential scope")
		}
		var cred Credential
		if err := json.Unmarshal(payload, &cred); err != nil {
			return nil, fmt.Errorf("invalid credential at scope %q: %w", scope, err)
		}
		if strings.TrimSpace(cred.Key) == "" {
			return nil, fmt.Errorf("credential at scope %q has no key", scope)
		}
		if strings.TrimSpace(cred.AuthMode) == "" {
			return nil, fmt.Errorf("credential at scope %q has no auth_mode", scope)
		}
		candidates = append(candidates, candidate{
			scope: scope,
			cred:  cred,
			score: candidateScore(scope, cred),
		})
	}

	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].score != candidates[j].score {
			return candidates[i].score > candidates[j].score
		}
		return candidates[i].scope < candidates[j].scope
	})
	primary := candidates[0]
	identity := identityFrom(primary.scope, primary.cred, len(candidates))

	return &File{
		Identity:     identity,
		Raw:          append([]byte(nil), data...),
		primary:      primary.cred,
		primaryScope: primary.scope,
	}, nil
}

// XAIRequestCredential returns the bearer and user ID only for first-party
// xAI OIDC credentials. It deliberately excludes refresh tokens.
func (f *File) XAIRequestCredential() (RequestCredential, bool) {
	mode := strings.ToLower(strings.TrimSpace(f.primary.AuthMode))
	issuer := strings.TrimRight(strings.ToLower(strings.TrimSpace(f.primary.OIDCIssuer)), "/")
	firstPartyScope := strings.HasPrefix(strings.ToLower(strings.TrimSpace(f.primaryScope)), "https://auth.x.ai::")
	if mode != "oidc" || (issuer != "https://auth.x.ai" && !firstPartyScope) {
		return RequestCredential{}, false
	}
	accessToken := strings.TrimSpace(f.primary.Key)
	userID := strings.TrimSpace(f.primary.UserID)
	if accessToken == "" || userID == "" {
		return RequestCredential{}, false
	}
	return RequestCredential{AccessToken: accessToken, UserID: userID}, true
}

func ensureEOF(dec *json.Decoder) error {
	var extra any
	err := dec.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("auth file contains more than one JSON value")
	}
	return fmt.Errorf("invalid trailing auth JSON: %w", err)
}

func candidateScore(scope string, cred Credential) int {
	score := 0
	switch strings.ToLower(cred.AuthMode) {
	case "oidc":
		score += 100
	case "external":
		score += 80
	case "web_login", "grok":
		score += 60
	case "api_key":
		score += 10
	}
	if cred.Email != "" {
		score += 30
	}
	if cred.UserID != "" {
		score += 20
	}
	if cred.PrincipalID != "" || cred.TeamID != "" {
		score += 10
	}
	if strings.Contains(strings.ToLower(scope), "auth.x.ai") ||
		strings.Contains(strings.ToLower(cred.OIDCIssuer), "auth.x.ai") {
		score += 10
	}
	return score
}

func identityFrom(scope string, cred Credential, count int) Identity {
	displayName := strings.TrimSpace(strings.TrimSpace(cred.FirstName) + " " + strings.TrimSpace(cred.LastName))
	seed := identitySeed(scope, cred)
	digest := sha256.Sum256([]byte(seed))
	id := "acc_" + hex.EncodeToString(digest[:])[:20]

	return Identity{
		ID:               id,
		Email:            strings.TrimSpace(cred.Email),
		DisplayName:      displayName,
		UserID:           strings.TrimSpace(cred.UserID),
		AuthMode:         strings.TrimSpace(cred.AuthMode),
		Scope:            scope,
		TeamID:           strings.TrimSpace(cred.TeamID),
		TeamName:         strings.TrimSpace(cred.TeamName),
		OrganizationID:   strings.TrimSpace(cred.OrganizationID),
		OrganizationName: strings.TrimSpace(cred.OrganizationName),
		ExpiresAt:        strings.TrimSpace(cred.ExpiresAt),
		CredentialCount:  count,
	}
}

func identitySeed(scope string, cred Credential) string {
	base := strings.ToLower(strings.TrimSpace(cred.AuthMode)) + "\x00" + strings.TrimSpace(scope) + "\x00"
	// user_id is present before optional /user enrichment and survives token
	// refreshes. Team/principal metadata can arrive later, so including it would
	// make one account appear to change identity after its first Grok run.
	if cred.UserID != "" {
		return base + "user\x00" + strings.TrimSpace(cred.UserID)
	}
	if cred.PrincipalID != "" {
		return base + "principal\x00" + strings.TrimSpace(cred.PrincipalID)
	}
	if cred.Email != "" {
		return base + "email\x00" + strings.ToLower(strings.TrimSpace(cred.Email))
	}

	// API-key records may not contain user metadata. Hashing the key creates a
	// stable opaque identity without ever storing or displaying the key itself.
	keyDigest := sha256.Sum256([]byte(cred.Key))
	return base + "key\x00" + hex.EncodeToString(keyDigest[:])
}

// Expiry classifies the selected credential's server-provided expiry.
func (i Identity) Expiry(now time.Time) string {
	if i.ExpiresAt == "" {
		return "unknown"
	}
	expires, err := time.Parse(time.RFC3339, i.ExpiresAt)
	if err != nil {
		return "unknown"
	}
	remaining := expires.Sub(now)
	if remaining <= 0 {
		return "expired"
	}
	if remaining < time.Hour {
		return fmt.Sprintf("%dm", int(remaining.Minutes()))
	}
	if remaining < 48*time.Hour {
		return fmt.Sprintf("%dh", int(remaining.Hours()))
	}
	return fmt.Sprintf("%dd", int(remaining.Hours()/24))
}
