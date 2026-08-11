package billing

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
)

const (
	DefaultURL     = "https://cli-chat-proxy.grok.com/v1/billing?format=credits"
	DefaultUserURL = "https://cli-chat-proxy.grok.com/v1/user?include=subscription"
)

type Cent struct {
	Val int64 `json:"val"`
}

type UsagePeriod struct {
	Type  string `json:"type"`
	Start string `json:"start"`
	End   string `json:"end"`
}

type Config struct {
	CreditUsagePercent *float64     `json:"creditUsagePercent"`
	CurrentPeriod      *UsagePeriod `json:"currentPeriod"`
	MonthlyLimit       *Cent        `json:"monthlyLimit"`
	Used               *Cent        `json:"used"`
	BillingPeriodEnd   string       `json:"billingPeriodEnd"`
}

type response struct {
	Config *Config `json:"config"`
}

type userResponse struct {
	SubscriptionTier string `json:"subscriptionTier"`
}

// Quota is the non-secret portion of Grok Build's billing response that helps
// choose an account. RemainingPercent is nil when the backend does not expose
// a usable allowance.
type Quota struct {
	RemainingPercent *float64 `json:"remainingPercent,omitempty"`
	UsedPercent      *float64 `json:"usedPercent,omitempty"`
	ResetAt          string   `json:"resetAt,omitempty"`
	PeriodType       string   `json:"periodType,omitempty"`
	Tier             string   `json:"tier,omitempty"`
	Error            string   `json:"error,omitempty"`
	TierError        string   `json:"tierError,omitempty"`
}

// Fetch calls the same credits endpoint used by Grok Build's /usage view.
// Access tokens are used only in the Authorization header and never included
// in returned errors.
func Fetch(ctx context.Context, client *http.Client, endpoint, clientVersion, accessToken, userID string) (Quota, error) {
	if client == nil {
		return Quota{}, errors.New("billing HTTP client is not configured")
	}
	if strings.TrimSpace(endpoint) == "" {
		return Quota{}, errors.New("billing endpoint is not configured")
	}
	if strings.TrimSpace(accessToken) == "" || strings.TrimSpace(userID) == "" {
		return Quota{}, errors.New("billing credential is incomplete")
	}

	request, err := authenticatedRequest(ctx, endpoint, clientVersion, accessToken, userID)
	if err != nil {
		return Quota{}, fmt.Errorf("create billing request: %w", err)
	}

	resp, err := client.Do(request)
	if err != nil {
		return Quota{}, fmt.Errorf("fetch Grok quota: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Quota{}, fmt.Errorf("Grok quota service returned HTTP %d", resp.StatusCode)
	}

	const maxResponse = 1 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return Quota{}, fmt.Errorf("read Grok quota response: %w", err)
	}
	if len(body) > maxResponse {
		return Quota{}, errors.New("Grok quota response exceeds 1 MiB")
	}
	var payload response
	if err := json.Unmarshal(body, &payload); err != nil {
		return Quota{}, fmt.Errorf("parse Grok quota response: %w", err)
	}
	if payload.Config == nil {
		return Quota{}, errors.New("Grok quota response has no config")
	}
	return quotaFromConfig(*payload.Config), nil
}

// FetchTier calls Grok Build's live subscription endpoint. It is kept
// separate from Fetch so either column can still render when the other
// endpoint is temporarily unavailable.
func FetchTier(ctx context.Context, client *http.Client, endpoint, clientVersion, accessToken string) (string, error) {
	if client == nil {
		return "", errors.New("tier HTTP client is not configured")
	}
	if strings.TrimSpace(endpoint) == "" {
		return "", errors.New("tier endpoint is not configured")
	}
	if strings.TrimSpace(accessToken) == "" {
		return "", errors.New("tier credential is incomplete")
	}
	request, err := authenticatedRequest(ctx, endpoint, clientVersion, accessToken, "")
	if err != nil {
		return "", fmt.Errorf("create tier request: %w", err)
	}
	resp, err := client.Do(request)
	if err != nil {
		return "", fmt.Errorf("fetch Grok tier: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("Grok tier service returned HTTP %d", resp.StatusCode)
	}
	const maxResponse = 1 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return "", fmt.Errorf("read Grok tier response: %w", err)
	}
	if len(body) > maxResponse {
		return "", errors.New("Grok tier response exceeds 1 MiB")
	}
	var payload userResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", fmt.Errorf("parse Grok tier response: %w", err)
	}
	tier := strings.TrimSpace(payload.SubscriptionTier)
	if tier == "" {
		return "", errors.New("Grok tier response has no subscriptionTier")
	}
	if len([]rune(tier)) > 64 || strings.IndexFunc(tier, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return "", errors.New("Grok tier response contains an invalid subscriptionTier")
	}
	return tier, nil
}

func authenticatedRequest(ctx context.Context, endpoint, clientVersion, accessToken, userID string) (*http.Request, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+accessToken)
	request.Header.Set("X-XAI-Token-Auth", "xai-grok-cli")
	request.Header.Set("x-grok-client-mode", "headless")
	if value := strings.TrimSpace(userID); value != "" {
		request.Header.Set("x-userid", value)
	}
	if value := strings.TrimSpace(clientVersion); value != "" {
		request.Header.Set("x-grok-client-version", value)
	}
	return request, nil
}

func quotaFromConfig(config Config) Quota {
	quota := Quota{}
	var used float64
	hasUsage := false
	if config.CreditUsagePercent != nil {
		used = *config.CreditUsagePercent
		hasUsage = true
	} else if config.MonthlyLimit != nil && config.Used != nil && config.MonthlyLimit.Val > 0 {
		used = float64(config.Used.Val) / float64(config.MonthlyLimit.Val) * 100
		hasUsage = true
	}
	if hasUsage {
		used = math.Max(0, math.Min(100, used))
		remaining := 100 - used
		quota.UsedPercent = floatPtr(used)
		quota.RemainingPercent = floatPtr(remaining)
	}
	if config.CurrentPeriod != nil {
		quota.ResetAt = strings.TrimSpace(config.CurrentPeriod.End)
		quota.PeriodType = strings.TrimSpace(config.CurrentPeriod.Type)
	}
	if quota.ResetAt == "" {
		quota.ResetAt = strings.TrimSpace(config.BillingPeriodEnd)
	}
	return quota
}

func floatPtr(value float64) *float64 {
	return &value
}
