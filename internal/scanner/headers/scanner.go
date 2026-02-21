package headers

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/buemura/hunter/internal/scanner"
	"github.com/buemura/hunter/pkg/types"
)

// Scanner performs HTTP security header analysis.
type Scanner struct{}

// New creates a new headers scanner.
func New() *Scanner {
	return &Scanner{}
}

func (s *Scanner) Name() string        { return "headers" }
func (s *Scanner) Description() string { return "HTTP security header analysis" }

func (s *Scanner) Run(ctx context.Context, target types.Target, opts scanner.Options) (*types.ScanResult, error) {
	result := &types.ScanResult{
		ScannerName: s.Name(),
		Target:      target,
		StartedAt:   time.Now(),
	}

	url := resolveURL(target)
	if url == "" {
		return nil, fmt.Errorf("cannot determine URL for target %q", target.Host)
	}

	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	client := &http.Client{Timeout: timeout}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	isHTTPS := strings.HasPrefix(url, "https://")

	for _, rule := range Rules() {
		if finding := rule.Check(resp.Header, isHTTPS); finding != nil {
			result.Findings = append(result.Findings, *finding)
		}
	}

	result.CompletedAt = time.Now()
	return result, nil
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
