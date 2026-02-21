package vuln

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/buemura/hunter/internal/scanner"
	"github.com/buemura/hunter/pkg/types"
)

// CheckFunc is a vulnerability check module that inspects a target and returns findings.
type CheckFunc func(ctx context.Context, target types.Target, opts scanner.Options) []types.Finding

// checkRegistry maps short names to check functions for CLI filtering.
var checkRegistry = map[string]CheckFunc{
	"xss":      CheckReflectedXSS,
	"sqli":     CheckSQLi,
	"redirect": CheckOpenRedirect,
}

// Scanner performs basic vulnerability detection (XSS, SQLi, open redirect).
type Scanner struct{}

// New creates a new vulnerability scanner.
func New() *Scanner {
	return &Scanner{}
}

func (s *Scanner) Name() string        { return "vuln" }
func (s *Scanner) Description() string { return "Basic vulnerability detection" }

func (s *Scanner) Run(ctx context.Context, target types.Target, opts scanner.Options) (*types.ScanResult, error) {
	result := &types.ScanResult{
		ScannerName: s.Name(),
		Target:      target,
		StartedAt:   time.Now(),
	}

	targetURL := resolveURL(target)
	if targetURL == "" {
		return nil, fmt.Errorf("cannot determine URL for target %q", target.Host)
	}
	target.URL = targetURL

	checks := s.resolveChecks(opts)
	for _, check := range checks {
		if ctx.Err() != nil {
			result.Error = ctx.Err().Error()
			break
		}
		findings := check(ctx, target, opts)
		result.Findings = append(result.Findings, findings...)
	}

	result.CompletedAt = time.Now()
	return result, nil
}

// resolveChecks returns the check functions to run. If opts.ExtraArgs contains
// a "checks" key (comma-separated names), only those checks are returned.
// Otherwise all checks are returned.
func (s *Scanner) resolveChecks(opts scanner.Options) []CheckFunc {
	if raw, ok := opts.ExtraArgs["checks"]; ok {
		if names, ok := raw.(string); ok && names != "" {
			var selected []CheckFunc
			for _, name := range strings.Split(names, ",") {
				name = strings.TrimSpace(name)
				if fn, exists := checkRegistry[name]; exists {
					selected = append(selected, fn)
				}
			}
			if len(selected) > 0 {
				return selected
			}
		}
	}
	return Checks()
}

// Checks returns all vulnerability check modules.
func Checks() []CheckFunc {
	return []CheckFunc{
		CheckReflectedXSS,
		CheckSQLi,
		CheckOpenRedirect,
	}
}

// resolveURL determines the target URL from the Target struct.
func resolveURL(target types.Target) string {
	if target.URL != "" {
		return target.URL
	}
	scheme := target.Scheme
	if scheme == "" {
		scheme = "https"
	}
	if target.Host == "" {
		return ""
	}
	return scheme + "://" + target.Host
}

// appendQueryParam adds a query parameter to a URL.
func appendQueryParam(rawURL, key, value string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	q := u.Query()
	q.Set(key, value)
	u.RawQuery = q.Encode()
	return u.String()
}

// httpGet performs a GET request and returns the response body as a string.
func httpGet(ctx context.Context, targetURL string, timeout time.Duration) (string, error) {
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	client := &http.Client{Timeout: timeout}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return "", err
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MB limit
	if err != nil {
		return "", err
	}

	return string(body), nil
}
