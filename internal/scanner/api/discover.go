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

// commonPaths is the list of well-known API paths to probe.
var commonPaths = []string{
	"/api",
	"/api/v1",
	"/api/v2",
	"/graphql",
	"/graphiql",
	"/swagger.json",
	"/openapi.json",
	"/api-docs",
	"/.well-known/openid-configuration",
}

// graphQLPaths are endpoints where we attempt a GraphQL introspection query.
var graphQLPaths = map[string]bool{
	"/graphql":  true,
	"/graphiql": true,
}

const graphQLIntrospectionQuery = `{"query":"{ __schema { types { name } } }"}`

// Scanner discovers common API endpoints on a target.
type Scanner struct{}

// New creates a new API discovery scanner.
func New() *Scanner {
	return &Scanner{}
}

func (s *Scanner) Name() string        { return "api-discover" }
func (s *Scanner) Description() string { return "API endpoint discovery" }

func (s *Scanner) Run(ctx context.Context, target types.Target, opts scanner.Options) (*types.ScanResult, error) {
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

	for _, path := range commonPaths {
		url := strings.TrimRight(baseURL, "/") + path

		finding := probePath(ctx, client, url, path)
		if finding != nil {
			result.Findings = append(result.Findings, *finding)
		}

		if graphQLPaths[path] && finding != nil {
			if gqlFinding := probeGraphQL(ctx, client, url); gqlFinding != nil {
				result.Findings = append(result.Findings, *gqlFinding)
			}
		}
	}

	result.CompletedAt = time.Now()
	return result, nil
}

// probePath sends a GET request to the given URL and returns a finding if the
// endpoint responds with a non-404 status.
func probePath(ctx context.Context, client *http.Client, url, path string) *types.Finding {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode == http.StatusNotFound {
		return nil
	}

	return &types.Finding{
		Title:       fmt.Sprintf("API endpoint discovered: %s", path),
		Description: fmt.Sprintf("Endpoint %s responded with status %d.", path, resp.StatusCode),
		Severity:    types.SeverityInfo,
		Evidence:    fmt.Sprintf("GET %s → %d", url, resp.StatusCode),
		Metadata: map[string]string{
			"path":         path,
			"status":       fmt.Sprintf("%d", resp.StatusCode),
			"content_type": resp.Header.Get("Content-Type"),
		},
	}
}

// probeGraphQL sends a GraphQL introspection query and reports back if successful.
func probeGraphQL(ctx context.Context, client *http.Client, url string) *types.Finding {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(graphQLIntrospectionQuery))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	if !strings.Contains(string(body), "__schema") {
		return nil
	}

	return &types.Finding{
		Title:       fmt.Sprintf("GraphQL introspection enabled: %s", url),
		Description: "GraphQL introspection is enabled, exposing the full API schema to anyone.",
		Severity:    types.SeverityInfo,
		Evidence:    fmt.Sprintf("POST %s with introspection query returned schema data", url),
		Metadata: map[string]string{
			"path":         url,
			"status":       fmt.Sprintf("%d", resp.StatusCode),
			"content_type": resp.Header.Get("Content-Type"),
		},
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
