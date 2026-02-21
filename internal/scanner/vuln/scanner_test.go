package vuln

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/buemura/hunter/internal/scanner"
	"github.com/buemura/hunter/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScanner_NameAndDescription(t *testing.T) {
	s := New()
	assert.Equal(t, "vuln", s.Name())
	assert.Equal(t, "Basic vulnerability detection", s.Description())
}

func TestScanner_RunAggregatesFindings(t *testing.T) {
	// Server that reflects XSS and leaks SQL errors.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		id := r.URL.Query().Get("id")

		body := ""
		if q != "" {
			body += q // reflect XSS payload
		}
		if id != "" {
			body += " You have an error in your SQL syntax"
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, body)
	}))
	defer srv.Close()

	s := New()
	target := types.Target{URL: srv.URL + "?q=test&id=1", Host: "127.0.0.1", Scheme: "http"}
	result, err := s.Run(context.Background(), target, scanner.DefaultOptions())

	require.NoError(t, err)
	assert.Equal(t, "vuln", result.ScannerName)
	assert.False(t, result.StartedAt.IsZero())
	assert.False(t, result.CompletedAt.IsZero())

	// Should have at least XSS and SQLi findings.
	assert.GreaterOrEqual(t, len(result.Findings), 2)

	titles := findingTitles(result.Findings)
	assert.Contains(t, titles, "Potential reflected XSS")
	assert.Contains(t, titles, "Potential SQL injection")
}

func TestScanner_NoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "safe response")
	}))
	defer srv.Close()

	s := New()
	target := types.Target{URL: srv.URL, Host: "127.0.0.1", Scheme: "http"}
	result, err := s.Run(context.Background(), target, scanner.DefaultOptions())

	require.NoError(t, err)
	assert.Empty(t, result.Findings)
}

func TestScanner_EmptyHostReturnsError(t *testing.T) {
	s := New()
	target := types.Target{}
	_, err := s.Run(context.Background(), target, scanner.DefaultOptions())
	assert.Error(t, err)
}

func TestScanner_RunWithChecksFilter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, q)
	}))
	defer srv.Close()

	s := New()
	target := types.Target{URL: srv.URL + "?q=test", Host: "127.0.0.1", Scheme: "http"}
	opts := scanner.DefaultOptions()
	opts.ExtraArgs = map[string]interface{}{
		"checks": "xss",
	}
	result, err := s.Run(context.Background(), target, opts)

	require.NoError(t, err)
	// Only XSS checks should run.
	for _, f := range result.Findings {
		assert.Equal(t, "xss", f.Metadata["check"])
	}
}

func TestChecks_ReturnsAllModules(t *testing.T) {
	checks := Checks()
	assert.Len(t, checks, 3, "expected XSS, SQLi, and redirect check modules")
}

func TestResolveURL(t *testing.T) {
	tests := []struct {
		name   string
		target types.Target
		want   string
	}{
		{
			name:   "URL takes precedence",
			target: types.Target{URL: "https://example.com/path", Host: "example.com", Scheme: "https"},
			want:   "https://example.com/path",
		},
		{
			name:   "falls back to scheme+host",
			target: types.Target{Host: "example.com", Scheme: "https"},
			want:   "https://example.com",
		},
		{
			name:   "defaults scheme to https",
			target: types.Target{Host: "example.com"},
			want:   "https://example.com",
		},
		{
			name:   "empty host returns empty",
			target: types.Target{},
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, resolveURL(tt.target))
		})
	}
}

func TestAppendQueryParam(t *testing.T) {
	result := appendQueryParam("http://example.com/path", "key", "value")
	assert.Contains(t, result, "key=value")
	assert.Contains(t, result, "http://example.com/path")
}

func TestScanner_ContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	s := New()
	target := types.Target{URL: srv.URL, Host: "127.0.0.1", Scheme: "http"}
	result, err := s.Run(ctx, target, scanner.DefaultOptions())

	require.NoError(t, err)
	assert.NotEmpty(t, result.Error)
}

func findingTitles(findings []types.Finding) []string {
	titles := make([]string, len(findings))
	for i, f := range findings {
		titles[i] = f.Title
	}
	return titles
}
