package api

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/buemura/hunter/internal/scanner"
	"github.com/buemura/hunter/pkg/types"
)

// CORSScanner detects CORS misconfigurations on a target.
type CORSScanner struct{}

// NewCORSScanner creates a new CORS misconfiguration scanner.
func NewCORSScanner() *CORSScanner {
	return &CORSScanner{}
}

func (s *CORSScanner) Name() string        { return "api-cors" }
func (s *CORSScanner) Description() string { return "CORS misconfiguration detection" }

// corsCheck defines a single CORS probe.
type corsCheck struct {
	origin      string
	method      string
	description string
}

var corsChecks = []corsCheck{
	{origin: "https://evil.com", method: http.MethodGet, description: "arbitrary origin reflection (GET)"},
	{origin: "https://evil.com", method: http.MethodOptions, description: "arbitrary origin reflection (OPTIONS preflight)"},
	{origin: "null", method: http.MethodGet, description: "null origin (GET)"},
	{origin: "null", method: http.MethodOptions, description: "null origin (OPTIONS preflight)"},
}

func (s *CORSScanner) Run(ctx context.Context, target types.Target, opts scanner.Options) (*types.ScanResult, error) {
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

	url := strings.TrimRight(baseURL, "/") + "/"

	for _, check := range corsChecks {
		if ctx.Err() != nil {
			result.Error = ctx.Err().Error()
			break
		}

		findings := probeOrigin(ctx, client, url, check)
		result.Findings = append(result.Findings, findings...)
	}

	if len(result.Findings) == 0 {
		result.Findings = append(result.Findings, types.Finding{
			Title:       "No CORS misconfigurations detected",
			Description: "The target does not appear to have CORS misconfigurations.",
			Severity:    types.SeverityInfo,
		})
	}

	result.CompletedAt = time.Now()
	return result, nil
}

// probeOrigin sends a request with the given Origin header and evaluates the CORS response.
func probeOrigin(ctx context.Context, client *http.Client, url string, check corsCheck) []types.Finding {
	req, err := http.NewRequestWithContext(ctx, check.method, url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Origin", check.origin)

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	acao := resp.Header.Get("Access-Control-Allow-Origin")
	acac := resp.Header.Get("Access-Control-Allow-Credentials")

	if acao == "" {
		return nil
	}

	var findings []types.Finding

	credentialsEnabled := strings.EqualFold(acac, "true")

	// Check: credentials with wildcard or reflected origin → CRITICAL
	if credentialsEnabled && (acao == "*" || acao == check.origin) {
		findings = append(findings, types.Finding{
			Title:       fmt.Sprintf("CORS credentials with permissive origin (%s %s)", check.method, check.origin),
			Description: fmt.Sprintf("Access-Control-Allow-Credentials is true with Access-Control-Allow-Origin: %s. Attackers can make authenticated cross-origin requests.", acao),
			Severity:    types.SeverityCritical,
			Evidence:    fmt.Sprintf("%s %s Origin: %s → ACAO: %s, ACAC: %s", check.method, url, check.origin, acao, acac),
			Remediation: "Restrict Access-Control-Allow-Origin to trusted domains and avoid using it with Access-Control-Allow-Credentials: true.",
			Metadata: map[string]string{
				"method":                             check.method,
				"origin":                             check.origin,
				"access_control_allow_origin":        acao,
				"access_control_allow_credentials":   acac,
			},
		})
		return findings
	}

	// Check: reflected arbitrary origin → HIGH
	if check.origin == "https://evil.com" && acao == check.origin {
		findings = append(findings, types.Finding{
			Title:       fmt.Sprintf("CORS origin reflected (%s)", check.method),
			Description: fmt.Sprintf("The server reflects the Origin header in Access-Control-Allow-Origin: %s. Any website can read cross-origin responses.", acao),
			Severity:    types.SeverityHigh,
			Evidence:    fmt.Sprintf("%s %s Origin: %s → ACAO: %s", check.method, url, check.origin, acao),
			Remediation: "Configure Access-Control-Allow-Origin to only allow specific trusted origins instead of reflecting the request origin.",
			Metadata: map[string]string{
				"method":                           check.method,
				"origin":                           check.origin,
				"access_control_allow_origin":      acao,
			},
		})
		return findings
	}

	// Check: null origin allowed → MEDIUM
	if check.origin == "null" && acao == "null" {
		findings = append(findings, types.Finding{
			Title:       fmt.Sprintf("CORS allows null origin (%s)", check.method),
			Description: "Access-Control-Allow-Origin is set to null. Sandboxed iframes and data: URIs send a null origin, enabling potential cross-origin access.",
			Severity:    types.SeverityMedium,
			Evidence:    fmt.Sprintf("%s %s Origin: null → ACAO: null", check.method, url),
			Remediation: "Do not allow null as a permitted origin. Use specific trusted domain names.",
			Metadata: map[string]string{
				"method":                           check.method,
				"origin":                           check.origin,
				"access_control_allow_origin":      acao,
			},
		})
		return findings
	}

	return findings
}
