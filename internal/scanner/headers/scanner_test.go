package headers

import (
	"context"
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
	assert.Equal(t, "headers", s.Name())
	assert.Equal(t, "HTTP security header analysis", s.Description())
}

func TestScanner_AllHeadersPresent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "0")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=()")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := New()
	target := types.Target{URL: srv.URL, Host: "127.0.0.1", Scheme: "http"}
	result, err := s.Run(context.Background(), target, scanner.DefaultOptions())

	require.NoError(t, err)
	assert.Empty(t, result.Findings, "expected no findings when all security headers are present")
}

func TestScanner_AllHeadersMissing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := New()
	target := types.Target{URL: srv.URL, Host: "127.0.0.1", Scheme: "http"}
	result, err := s.Run(context.Background(), target, scanner.DefaultOptions())

	require.NoError(t, err)

	// HSTS should NOT trigger on HTTP (non-HTTPS), so expect 6 findings.
	expectedTitles := []string{
		"Missing Content-Security-Policy header",
		"Missing X-Content-Type-Options header",
		"Missing X-Frame-Options header",
		"Missing X-XSS-Protection header",
		"Missing Referrer-Policy header",
		"Missing Permissions-Policy header",
	}
	assert.Len(t, result.Findings, len(expectedTitles))

	titles := make([]string, len(result.Findings))
	for i, f := range result.Findings {
		titles[i] = f.Title
	}
	for _, expected := range expectedTitles {
		assert.Contains(t, titles, expected)
	}
}

func TestScanner_PartialHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := New()
	target := types.Target{URL: srv.URL, Host: "127.0.0.1", Scheme: "http"}
	result, err := s.Run(context.Background(), target, scanner.DefaultOptions())

	require.NoError(t, err)

	// Missing: X-XSS-Protection, Referrer-Policy, Permissions-Policy (3 findings).
	// HSTS skipped because HTTP.
	assert.Len(t, result.Findings, 3)

	titles := make([]string, len(result.Findings))
	for i, f := range result.Findings {
		titles[i] = f.Title
	}
	assert.NotContains(t, titles, "Missing Content-Security-Policy header")
	assert.NotContains(t, titles, "Missing X-Content-Type-Options header")
	assert.NotContains(t, titles, "Missing X-Frame-Options header")
}

func TestScanner_HSTSOnlyOnHTTPS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return all headers except HSTS.
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "0")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=()")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := New()

	// HTTP target: HSTS check should NOT trigger.
	httpTarget := types.Target{URL: srv.URL, Host: "127.0.0.1", Scheme: "http"}
	result, err := s.Run(context.Background(), httpTarget, scanner.DefaultOptions())
	require.NoError(t, err)
	assert.Empty(t, result.Findings, "HSTS should not trigger on HTTP targets")

	// HTTPS target: simulate by using the test server URL but marking scheme as https.
	// The actual request goes to HTTP (httptest), but the URL starts with http://,
	// so we test the HSTS logic by directly checking Rules().
	rules := Rules()
	hstsRule := rules[0]
	assert.Equal(t, "Strict-Transport-Security", hstsRule.Name)

	emptyHeaders := http.Header{}
	assert.Nil(t, hstsRule.Check(emptyHeaders, false), "HSTS should not trigger when isHTTPS=false")
	assert.NotNil(t, hstsRule.Check(emptyHeaders, true), "HSTS should trigger when isHTTPS=true")
}

func TestScanner_XContentTypeOptionsMisconfigured(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("X-Content-Type-Options", "wrong-value")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "0")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "camera=()")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := New()
	target := types.Target{URL: srv.URL, Host: "127.0.0.1", Scheme: "http"}
	result, err := s.Run(context.Background(), target, scanner.DefaultOptions())

	require.NoError(t, err)
	require.Len(t, result.Findings, 1)
	assert.Equal(t, "Misconfigured X-Content-Type-Options header", result.Findings[0].Title)
	assert.Equal(t, types.SeverityLow, result.Findings[0].Severity)
}

func TestScanner_FindingSeverities(t *testing.T) {
	rules := Rules()

	emptyHeaders := http.Header{}
	expected := map[string]types.Severity{
		"Strict-Transport-Security": types.SeverityHigh,
		"Content-Security-Policy":   types.SeverityMedium,
		"X-Content-Type-Options":    types.SeverityLow,
		"X-Frame-Options":           types.SeverityLow,
		"X-XSS-Protection":          types.SeverityInfo,
		"Referrer-Policy":           types.SeverityLow,
		"Permissions-Policy":        types.SeverityLow,
	}

	for _, rule := range rules {
		isHTTPS := rule.Name == "Strict-Transport-Security"
		finding := rule.Check(emptyHeaders, isHTTPS)
		if assert.NotNil(t, finding, "expected finding for rule %s", rule.Name) {
			assert.Equal(t, expected[rule.Name], finding.Severity, "wrong severity for %s", rule.Name)
		}
	}
}

func TestScanner_ResolveURL(t *testing.T) {
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
