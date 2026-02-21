package dirs

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/buemura/hunter/internal/scanner"
	"github.com/buemura/hunter/pkg/types"
)

// Scanner performs directory and path enumeration against a target.
type Scanner struct{}

// New creates a new directory enumeration scanner.
func New() *Scanner {
	return &Scanner{}
}

func (s *Scanner) Name() string        { return "dirs" }
func (s *Scanner) Description() string { return "Directory and path enumeration" }

func (s *Scanner) Run(ctx context.Context, target types.Target, opts scanner.Options) (*types.ScanResult, error) {
	result := &types.ScanResult{
		ScannerName: s.Name(),
		Target:      target,
		StartedAt:   time.Now(),
	}

	wordlistPath := ""
	if opts.ExtraArgs != nil {
		if wl, ok := opts.ExtraArgs["wordlist"].(string); ok {
			wordlistPath = wl
		}
	}

	paths, err := LoadWordlist(wordlistPath)
	if err != nil {
		return nil, fmt.Errorf("loading wordlist: %w", err)
	}

	baseURL := buildBaseURL(target)

	concurrency := opts.Concurrency
	if concurrency < 1 {
		concurrency = 10
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

	sem := make(chan struct{}, concurrency)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, path := range paths {
		select {
		case <-ctx.Done():
			result.CompletedAt = time.Now()
			return result, nil
		default:
		}

		wg.Add(1)
		go func(p string) {
			defer wg.Done()

			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			finding, ok := probe(ctx, client, baseURL, p)
			if !ok {
				return
			}

			mu.Lock()
			result.Findings = append(result.Findings, finding)
			mu.Unlock()
		}(path)
	}

	wg.Wait()
	result.CompletedAt = time.Now()
	return result, nil
}

// probe sends an HTTP request to baseURL+path and returns a Finding if the
// response status is noteworthy (200, 301, 302, 403).
func probe(ctx context.Context, client *http.Client, baseURL, path string) (types.Finding, bool) {
	url := baseURL + path

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return types.Finding{}, false
	}

	resp, err := client.Do(req)
	if err != nil {
		return types.Finding{}, false
	}
	resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		return types.Finding{
			Title:       fmt.Sprintf("Found path: %s (200 OK)", path),
			Description: fmt.Sprintf("Path %s is accessible and returned HTTP 200", path),
			Severity:    types.SeverityInfo,
			Metadata: map[string]string{
				"path":        path,
				"status_code": "200",
				"url":         url,
			},
		}, true

	case http.StatusForbidden:
		return types.Finding{
			Title:       fmt.Sprintf("Forbidden path: %s (403)", path),
			Description: fmt.Sprintf("Path %s exists but returned HTTP 403 Forbidden", path),
			Severity:    types.SeverityLow,
			Metadata: map[string]string{
				"path":        path,
				"status_code": "403",
				"url":         url,
			},
		}, true

	case http.StatusMovedPermanently, http.StatusFound:
		location := resp.Header.Get("Location")
		return types.Finding{
			Title:       fmt.Sprintf("Redirect path: %s (%d)", path, resp.StatusCode),
			Description: fmt.Sprintf("Path %s redirects (%d) to %s", path, resp.StatusCode, location),
			Severity:    types.SeverityInfo,
			Metadata: map[string]string{
				"path":        path,
				"status_code": fmt.Sprintf("%d", resp.StatusCode),
				"url":         url,
				"location":    location,
			},
		}, true

	default:
		return types.Finding{}, false
	}
}

// buildBaseURL constructs the base URL from a target.
func buildBaseURL(target types.Target) string {
	if target.URL != "" {
		return strings.TrimRight(target.URL, "/")
	}

	scheme := target.Scheme
	if scheme == "" {
		scheme = "https"
	}

	return fmt.Sprintf("%s://%s", scheme, target.Host)
}
