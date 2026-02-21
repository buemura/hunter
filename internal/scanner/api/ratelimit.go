package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/buemura/hunter/internal/scanner"
	"github.com/buemura/hunter/pkg/types"
)

const defaultRequests = 50

// RateLimitScanner checks whether a target endpoint enforces rate limiting.
type RateLimitScanner struct{}

// NewRateLimitScanner creates a new rate limit scanner.
func NewRateLimitScanner() *RateLimitScanner {
	return &RateLimitScanner{}
}

func (s *RateLimitScanner) Name() string        { return "api-ratelimit" }
func (s *RateLimitScanner) Description() string { return "API rate limiting check" }

func (s *RateLimitScanner) Run(ctx context.Context, target types.Target, opts scanner.Options) (*types.ScanResult, error) {
	result := &types.ScanResult{
		ScannerName: s.Name(),
		Target:      target,
		StartedAt:   time.Now(),
	}

	baseURL := resolveURL(target)
	if baseURL == "" {
		return nil, fmt.Errorf("cannot determine URL for target %q", target.Host)
	}

	numRequests := defaultRequests
	if opts.ExtraArgs != nil {
		if v, ok := opts.ExtraArgs["requests"].(int); ok && v > 0 {
			numRequests = v
		}
	}

	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	client := &http.Client{Timeout: timeout}

	rateLimited := false
	var rateLimitHeaders map[string]string

	for i := 0; i < numRequests; i++ {
		select {
		case <-ctx.Done():
			result.CompletedAt = time.Now()
			return result, nil
		default:
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL, nil)
		if err != nil {
			return nil, fmt.Errorf("creating request: %w", err)
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		headers := extractRateLimitHeaders(resp.Header)

		if resp.StatusCode == http.StatusTooManyRequests {
			rateLimited = true
			rateLimitHeaders = headers
			break
		}

		if len(headers) > 0 && rateLimitHeaders == nil {
			rateLimitHeaders = headers
		}
	}

	if rateLimitHeaders != nil {
		headerList := formatHeaders(rateLimitHeaders)
		result.Findings = append(result.Findings, types.Finding{
			Title:       "Rate limit headers detected",
			Description: fmt.Sprintf("The endpoint includes rate-limiting headers: %s", headerList),
			Severity:    types.SeverityInfo,
			Evidence:    headerList,
			Metadata:    rateLimitHeaders,
		})
	}

	if !rateLimited {
		result.Findings = append(result.Findings, types.Finding{
			Title:       "No rate limiting detected",
			Description: fmt.Sprintf("Sent %d rapid requests to %s without receiving a 429 Too Many Requests response.", numRequests, baseURL),
			Severity:    types.SeverityMedium,
			Remediation: "Implement rate limiting to protect against brute-force attacks and API abuse. Consider using token bucket or sliding window algorithms.",
			Metadata: map[string]string{
				"requests_sent": fmt.Sprintf("%d", numRequests),
			},
		})
	}

	result.CompletedAt = time.Now()
	return result, nil
}

// extractRateLimitHeaders returns rate-limit related headers from the response.
func extractRateLimitHeaders(h http.Header) map[string]string {
	headers := make(map[string]string)

	rateLimitHeaderNames := []string{
		"X-RateLimit-Limit",
		"X-RateLimit-Remaining",
		"X-RateLimit-Reset",
		"Retry-After",
		"RateLimit-Limit",
		"RateLimit-Remaining",
		"RateLimit-Reset",
	}

	for _, name := range rateLimitHeaderNames {
		if val := h.Get(name); val != "" {
			headers[strings.ToLower(name)] = val
		}
	}

	return headers
}

// formatHeaders formats a map of headers into a readable string.
func formatHeaders(headers map[string]string) string {
	parts := make([]string, 0, len(headers))
	for k, v := range headers {
		parts = append(parts, fmt.Sprintf("%s: %s", k, v))
	}
	return strings.Join(parts, ", ")
}
