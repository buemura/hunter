package api

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/buemura/hunter/internal/scanner"
	"github.com/buemura/hunter/pkg/types"
)

// defaultCredentials is the list of common default credential pairs to test.
var defaultCredentials = []struct {
	Username string
	Password string
}{
	{"admin", "admin"},
	{"admin", "password"},
}

// loginPaths are common login/authentication endpoints.
var loginPaths = []string{
	"/login",
	"/api/login",
	"/api/v1/login",
	"/auth/login",
	"/api/auth/login",
	"/signin",
	"/api/signin",
}

// bypassPayloads are Authorization header values used to test auth bypass.
var bypassPayloads = []struct {
	Name  string
	Value string
}{
	{"empty header", ""},
	{"Bearer null", "Bearer null"},
	{"Bearer undefined", "Bearer undefined"},
	{"Bearer empty", "Bearer "},
	{"Basic empty", "Basic " + base64.StdEncoding.EncodeToString([]byte(":"))},
}

// AuthScanner tests API endpoints for authentication weaknesses.
type AuthScanner struct{}

// NewAuthScanner creates a new API authentication scanner.
func NewAuthScanner() *AuthScanner {
	return &AuthScanner{}
}

func (s *AuthScanner) Name() string        { return "api-auth" }
func (s *AuthScanner) Description() string { return "API authentication testing" }

func (s *AuthScanner) Run(ctx context.Context, target types.Target, opts scanner.Options) (*types.ScanResult, error) {
	result := &types.ScanResult{
		ScannerName: s.Name(),
		Target:      target,
		StartedAt:   time.Now(),
	}

	baseURL := resolveURL(target)
	if baseURL == "" {
		return nil, fmt.Errorf("cannot determine URL for target %q", target.Host)
	}

	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Determine which endpoints to test.
	endpoints := endpointsFromOpts(baseURL, opts)

	// Phase 1: Test endpoints without credentials (missing auth check).
	for _, ep := range endpoints {
		if finding := testNoAuth(ctx, client, ep); finding != nil {
			result.Findings = append(result.Findings, *finding)
		}
	}

	// Phase 2: Test authentication bypass techniques on endpoints.
	for _, ep := range endpoints {
		findings := testAuthBypass(ctx, client, ep)
		result.Findings = append(result.Findings, findings...)
	}

	// Phase 3: Test default credentials on login endpoints.
	loginEndpoints := discoverLoginEndpoints(ctx, client, baseURL)
	for _, ep := range loginEndpoints {
		findings := testDefaultCredentials(ctx, client, ep)
		result.Findings = append(result.Findings, findings...)
	}

	result.CompletedAt = time.Now()
	return result, nil
}

// endpointsFromOpts returns the list of endpoint URLs to test.
// If the target has a URL path (not just root), it uses that single endpoint.
// Otherwise it uses commonPaths from the discover module.
func endpointsFromOpts(baseURL string, opts scanner.Options) []string {
	parsed, err := url.Parse(baseURL)
	if err == nil && parsed.Path != "" && parsed.Path != "/" {
		return []string{baseURL}
	}

	base := strings.TrimRight(baseURL, "/")
	endpoints := make([]string, 0, len(commonPaths))
	for _, p := range commonPaths {
		endpoints = append(endpoints, base+p)
	}
	return endpoints
}

// testNoAuth sends a GET request without credentials and checks if the endpoint
// returns 200 OK instead of 401/403 (indicating missing authentication).
func testNoAuth(ctx context.Context, client *http.Client, endpoint string) *types.Finding {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	// Skip non-existent endpoints.
	if resp.StatusCode == http.StatusNotFound {
		return nil
	}

	// An endpoint returning 200 without any credentials is a concern.
	if resp.StatusCode == http.StatusOK {
		return &types.Finding{
			Title:       fmt.Sprintf("Endpoint accessible without authentication: %s", endpoint),
			Description: "The endpoint returned HTTP 200 without any credentials, which may indicate missing authentication.",
			Severity:    types.SeverityHigh,
			Evidence:    fmt.Sprintf("GET %s → %d (no credentials)", endpoint, resp.StatusCode),
			Remediation: "Ensure all sensitive API endpoints require proper authentication before granting access.",
			Metadata: map[string]string{
				"endpoint": endpoint,
				"status":   fmt.Sprintf("%d", resp.StatusCode),
				"check":    "no-auth",
			},
		}
	}

	return nil
}

// testAuthBypass attempts various authentication bypass techniques on the endpoint.
func testAuthBypass(ctx context.Context, client *http.Client, endpoint string) []types.Finding {
	var findings []types.Finding

	// First check if the endpoint actually requires auth (expects 401/403).
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	// Only test bypass if endpoint requires authentication.
	if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
		return nil
	}

	for _, payload := range bypassPayloads {
		bypassReq, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			continue
		}
		bypassReq.Header.Set("Authorization", payload.Value)

		bypassResp, err := client.Do(bypassReq)
		if err != nil {
			continue
		}
		io.Copy(io.Discard, bypassResp.Body)
		bypassResp.Body.Close()

		if bypassResp.StatusCode == http.StatusOK {
			findings = append(findings, types.Finding{
				Title:       fmt.Sprintf("Authentication bypass via %s: %s", payload.Name, endpoint),
				Description: fmt.Sprintf("The endpoint returned HTTP 200 when using Authorization header value %q, bypassing authentication.", payload.Name),
				Severity:    types.SeverityHigh,
				Evidence:    fmt.Sprintf("GET %s with Authorization: %q → %d", endpoint, payload.Value, bypassResp.StatusCode),
				Remediation: "Validate authentication tokens server-side. Reject null, empty, or malformed tokens.",
				Metadata: map[string]string{
					"endpoint":       endpoint,
					"bypass_method":  payload.Name,
					"bypass_value":   payload.Value,
					"status":         fmt.Sprintf("%d", bypassResp.StatusCode),
					"check":          "auth-bypass",
				},
			})
		}
	}

	return findings
}

// discoverLoginEndpoints probes common login paths and returns those that exist.
func discoverLoginEndpoints(ctx context.Context, client *http.Client, baseURL string) []string {
	base := strings.TrimRight(baseURL, "/")
	var found []string

	for _, path := range loginPaths {
		ep := base + path
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, ep, nil)
		if err != nil {
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		if resp.StatusCode != http.StatusNotFound {
			found = append(found, ep)
		}
	}

	return found
}

// testDefaultCredentials attempts to POST common default credentials to a login endpoint.
func testDefaultCredentials(ctx context.Context, client *http.Client, endpoint string) []types.Finding {
	var findings []types.Finding

	for _, cred := range defaultCredentials {
		body := fmt.Sprintf(`{"username":%q,"password":%q}`, cred.Username, cred.Password)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(body))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()

		// Consider 200 or 201 as successful login indicators.
		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
			findings = append(findings, types.Finding{
				Title:       fmt.Sprintf("Default credentials accepted: %s/%s at %s", cred.Username, cred.Password, endpoint),
				Description: fmt.Sprintf("The login endpoint accepted default credentials %s/%s, which is a critical security issue.", cred.Username, cred.Password),
				Severity:    types.SeverityCritical,
				Evidence:    fmt.Sprintf("POST %s with %s/%s → %d; body preview: %s", endpoint, cred.Username, cred.Password, resp.StatusCode, truncate(string(respBody), 200)),
				Remediation: "Change default credentials immediately. Enforce strong password policies and consider account lockout mechanisms.",
				Metadata: map[string]string{
					"endpoint": endpoint,
					"username": cred.Username,
					"status":   fmt.Sprintf("%d", resp.StatusCode),
					"check":    "default-credentials",
				},
			})
		}
	}

	return findings
}

// truncate shortens a string to maxLen characters, appending "..." if truncated.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
