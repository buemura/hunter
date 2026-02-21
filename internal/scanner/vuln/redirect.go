package vuln

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/buemura/hunter/internal/scanner"
	"github.com/buemura/hunter/pkg/types"
)

// redirectParams are common parameter names used for URL redirection.
var redirectParams = []string{
	"url", "redirect", "next", "return", "goto",
	"dest", "redir", "redirect_uri", "return_to",
}

const redirectTarget = "https://evil.com"

// CheckOpenRedirect tests for open redirect vulnerabilities by injecting an
// external URL into common redirect parameters and checking if the server
// responds with a 3xx redirect to that URL. If the target URL already has
// query parameters, each redirect param name found among them is tested.
// If it has no parameters, each redirect param is appended with the evil value.
func CheckOpenRedirect(ctx context.Context, target types.Target, opts scanner.Options) []types.Finding {
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

	u, err := url.Parse(target.URL)
	if err != nil {
		return nil
	}

	var findings []types.Finding

	existingParams := u.Query()
	if len(existingParams) > 0 {
		// Test each existing parameter that matches a known redirect param name.
		for _, param := range redirectParams {
			if _, ok := existingParams[param]; !ok {
				continue
			}
			if ctx.Err() != nil {
				return findings
			}
			if f := probeRedirect(ctx, client, target.URL, param); f != nil {
				findings = append(findings, *f)
			}
		}

		// Also try appending redirect params not already present.
		for _, param := range redirectParams {
			if _, ok := existingParams[param]; ok {
				continue
			}
			if ctx.Err() != nil {
				return findings
			}
			if f := probeRedirect(ctx, client, target.URL, param); f != nil {
				findings = append(findings, *f)
			}
		}
	} else {
		// No existing params — append each redirect param.
		for _, param := range redirectParams {
			if ctx.Err() != nil {
				return findings
			}
			if f := probeRedirect(ctx, client, target.URL, param); f != nil {
				findings = append(findings, *f)
			}
		}
	}

	return findings
}

// probeRedirect sends a GET request with the given redirect param set to
// evil.com and checks if the response is a 3xx redirect to that URL.
func probeRedirect(ctx context.Context, client *http.Client, baseURL, param string) *types.Finding {
	testURL := appendQueryParam(baseURL, param, redirectTarget)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, testURL, nil)
	if err != nil {
		return nil
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	resp.Body.Close()

	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		location := resp.Header.Get("Location")
		if strings.HasPrefix(location, redirectTarget) {
			return &types.Finding{
				Title:       "Potential open redirect",
				Description: fmt.Sprintf("The server redirects to an attacker-controlled URL when the %q parameter is set to an external domain.", param),
				Severity:    types.SeverityMedium,
				Evidence:    fmt.Sprintf("GET %s → %d Location: %s", testURL, resp.StatusCode, location),
				Remediation: "Validate redirect targets against an allowlist of trusted domains. Avoid using user-supplied values directly in redirect URLs.",
				Metadata: map[string]string{
					"check":       "redirect",
					"param":       param,
					"url":         testURL,
					"location":    location,
					"status_code": fmt.Sprintf("%d", resp.StatusCode),
				},
			}
		}
	}

	return nil
}
