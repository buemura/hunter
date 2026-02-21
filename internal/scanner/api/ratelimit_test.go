package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/buemura/hunter/internal/scanner"
	"github.com/buemura/hunter/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRateLimitScanner_NameAndDescription(t *testing.T) {
	s := NewRateLimitScanner()
	assert.Equal(t, "api-ratelimit", s.Name())
	assert.Equal(t, "API rate limiting check", s.Description())
}

func TestRateLimitScanner_NoRateLimiting(t *testing.T) {
	var count atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := NewRateLimitScanner()
	target := types.Target{URL: srv.URL, Host: "127.0.0.1", Scheme: "http"}
	opts := scanner.DefaultOptions()
	opts.ExtraArgs = map[string]interface{}{"requests": 10}

	result, err := s.Run(context.Background(), target, opts)

	require.NoError(t, err)
	require.Len(t, result.Findings, 1)
	assert.Equal(t, "No rate limiting detected", result.Findings[0].Title)
	assert.Equal(t, types.SeverityMedium, result.Findings[0].Severity)
	assert.Equal(t, int32(10), count.Load())
}

func TestRateLimitScanner_RateLimitedWith429(t *testing.T) {
	var count atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := count.Add(1)
		if n >= 5 {
			w.Header().Set("Retry-After", "60")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := NewRateLimitScanner()
	target := types.Target{URL: srv.URL, Host: "127.0.0.1", Scheme: "http"}
	opts := scanner.DefaultOptions()
	opts.ExtraArgs = map[string]interface{}{"requests": 20}

	result, err := s.Run(context.Background(), target, opts)

	require.NoError(t, err)
	// Should have the rate limit headers finding but NOT the "no rate limiting" finding.
	hasRateLimitHeaders := false
	hasNoRateLimiting := false
	for _, f := range result.Findings {
		if f.Title == "Rate limit headers detected" {
			hasRateLimitHeaders = true
		}
		if f.Title == "No rate limiting detected" {
			hasNoRateLimiting = true
		}
	}
	assert.True(t, hasRateLimitHeaders, "should detect rate limit headers")
	assert.False(t, hasNoRateLimiting, "should not report missing rate limiting")
	// Should stop before sending all 20 requests.
	assert.Less(t, count.Load(), int32(20))
}

func TestRateLimitScanner_DetectsRateLimitHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Limit", "100")
		w.Header().Set("X-RateLimit-Remaining", "99")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := NewRateLimitScanner()
	target := types.Target{URL: srv.URL, Host: "127.0.0.1", Scheme: "http"}
	opts := scanner.DefaultOptions()
	opts.ExtraArgs = map[string]interface{}{"requests": 5}

	result, err := s.Run(context.Background(), target, opts)

	require.NoError(t, err)
	require.Len(t, result.Findings, 2)

	// First finding: rate limit headers detected.
	headersFinding := result.Findings[0]
	assert.Equal(t, "Rate limit headers detected", headersFinding.Title)
	assert.Equal(t, types.SeverityInfo, headersFinding.Severity)
	assert.Equal(t, "100", headersFinding.Metadata["x-ratelimit-limit"])
	assert.Equal(t, "99", headersFinding.Metadata["x-ratelimit-remaining"])

	// Second finding: no 429 received so still reports no rate limiting.
	noLimitFinding := result.Findings[1]
	assert.Equal(t, "No rate limiting detected", noLimitFinding.Title)
	assert.Equal(t, types.SeverityMedium, noLimitFinding.Severity)
}

func TestRateLimitScanner_DefaultRequestCount(t *testing.T) {
	var count atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := NewRateLimitScanner()
	target := types.Target{URL: srv.URL, Host: "127.0.0.1", Scheme: "http"}
	opts := scanner.DefaultOptions()

	result, err := s.Run(context.Background(), target, opts)

	require.NoError(t, err)
	assert.Equal(t, int32(defaultRequests), count.Load())
	require.Len(t, result.Findings, 1)
	assert.Equal(t, "50", result.Findings[0].Metadata["requests_sent"])
}

func TestRateLimitScanner_EmptyTarget(t *testing.T) {
	s := NewRateLimitScanner()
	target := types.Target{}
	_, err := s.Run(context.Background(), target, scanner.DefaultOptions())

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot determine URL")
}

func TestRateLimitScanner_ContextCancellation(t *testing.T) {
	var count atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	s := NewRateLimitScanner()
	target := types.Target{URL: srv.URL, Host: "127.0.0.1", Scheme: "http"}
	opts := scanner.DefaultOptions()
	opts.ExtraArgs = map[string]interface{}{"requests": 100}

	result, err := s.Run(ctx, target, opts)

	require.NoError(t, err)
	assert.Less(t, count.Load(), int32(100))
	assert.NotZero(t, result.CompletedAt)
}

func TestRateLimitScanner_RetryAfterHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	s := NewRateLimitScanner()
	target := types.Target{URL: srv.URL, Host: "127.0.0.1", Scheme: "http"}
	opts := scanner.DefaultOptions()
	opts.ExtraArgs = map[string]interface{}{"requests": 5}

	result, err := s.Run(context.Background(), target, opts)

	require.NoError(t, err)
	// Should have headers finding but NOT no-rate-limiting finding.
	hasHeaders := false
	hasNoLimit := false
	for _, f := range result.Findings {
		if f.Title == "Rate limit headers detected" {
			hasHeaders = true
			assert.Equal(t, "30", f.Metadata["retry-after"])
		}
		if f.Title == "No rate limiting detected" {
			hasNoLimit = true
		}
	}
	assert.True(t, hasHeaders)
	assert.False(t, hasNoLimit)
}
