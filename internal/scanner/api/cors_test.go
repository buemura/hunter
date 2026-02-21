package api

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

func TestCORSScanner_NameAndDescription(t *testing.T) {
	s := NewCORSScanner()
	assert.Equal(t, "api-cors", s.Name())
	assert.Equal(t, "CORS misconfiguration detection", s.Description())
}

func TestCORSScanner_ReflectedOrigin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := NewCORSScanner()
	target := types.Target{URL: srv.URL, Host: "127.0.0.1", Scheme: "http"}
	result, err := s.Run(context.Background(), target, scanner.DefaultOptions())

	require.NoError(t, err)
	require.NotEmpty(t, result.Findings)

	var hasHigh bool
	for _, f := range result.Findings {
		if f.Severity == types.SeverityHigh {
			hasHigh = true
			assert.Contains(t, f.Title, "CORS origin reflected")
			assert.Contains(t, f.Evidence, "https://evil.com")
		}
	}
	assert.True(t, hasHigh, "expected at least one HIGH severity finding for reflected origin")
}

func TestCORSScanner_NullOrigin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "null" {
			w.Header().Set("Access-Control-Allow-Origin", "null")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := NewCORSScanner()
	target := types.Target{URL: srv.URL, Host: "127.0.0.1", Scheme: "http"}
	result, err := s.Run(context.Background(), target, scanner.DefaultOptions())

	require.NoError(t, err)
	require.NotEmpty(t, result.Findings)

	var hasMedium bool
	for _, f := range result.Findings {
		if f.Severity == types.SeverityMedium {
			hasMedium = true
			assert.Contains(t, f.Title, "CORS allows null origin")
		}
	}
	assert.True(t, hasMedium, "expected at least one MEDIUM severity finding for null origin")
}

func TestCORSScanner_CredentialsWithReflectedOrigin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := NewCORSScanner()
	target := types.Target{URL: srv.URL, Host: "127.0.0.1", Scheme: "http"}
	result, err := s.Run(context.Background(), target, scanner.DefaultOptions())

	require.NoError(t, err)
	require.NotEmpty(t, result.Findings)

	var hasCritical bool
	for _, f := range result.Findings {
		if f.Severity == types.SeverityCritical {
			hasCritical = true
			assert.Contains(t, f.Title, "CORS credentials with permissive origin")
			assert.Contains(t, f.Metadata["access_control_allow_credentials"], "true")
		}
	}
	assert.True(t, hasCritical, "expected at least one CRITICAL severity finding for credentials + reflected origin")
}

func TestCORSScanner_CredentialsWithWildcard(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := NewCORSScanner()
	target := types.Target{URL: srv.URL, Host: "127.0.0.1", Scheme: "http"}
	result, err := s.Run(context.Background(), target, scanner.DefaultOptions())

	require.NoError(t, err)
	require.NotEmpty(t, result.Findings)

	var hasCritical bool
	for _, f := range result.Findings {
		if f.Severity == types.SeverityCritical {
			hasCritical = true
			assert.Contains(t, f.Description, "Access-Control-Allow-Credentials is true")
		}
	}
	assert.True(t, hasCritical, "expected CRITICAL finding for credentials + wildcard origin")
}

func TestCORSScanner_NoCORSHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := NewCORSScanner()
	target := types.Target{URL: srv.URL, Host: "127.0.0.1", Scheme: "http"}
	result, err := s.Run(context.Background(), target, scanner.DefaultOptions())

	require.NoError(t, err)
	require.Len(t, result.Findings, 1)
	assert.Equal(t, types.SeverityInfo, result.Findings[0].Severity)
	assert.Contains(t, result.Findings[0].Title, "No CORS misconfigurations detected")
}

func TestCORSScanner_FixedAllowedOrigin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "https://trusted.com")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := NewCORSScanner()
	target := types.Target{URL: srv.URL, Host: "127.0.0.1", Scheme: "http"}
	result, err := s.Run(context.Background(), target, scanner.DefaultOptions())

	require.NoError(t, err)
	// A fixed allowed origin that doesn't match the probe should not trigger findings.
	require.Len(t, result.Findings, 1)
	assert.Equal(t, types.SeverityInfo, result.Findings[0].Severity)
}

func TestCORSScanner_PreflightReflectedOrigin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if r.Method == http.MethodOptions && origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	s := NewCORSScanner()
	target := types.Target{URL: srv.URL, Host: "127.0.0.1", Scheme: "http"}
	result, err := s.Run(context.Background(), target, scanner.DefaultOptions())

	require.NoError(t, err)

	var hasPreflightFinding bool
	for _, f := range result.Findings {
		if f.Severity == types.SeverityHigh && f.Metadata["method"] == http.MethodOptions {
			hasPreflightFinding = true
			assert.Contains(t, f.Title, "OPTIONS")
		}
	}
	assert.True(t, hasPreflightFinding, "expected HIGH severity finding for preflight reflected origin")
}

func TestCORSScanner_EmptyTarget(t *testing.T) {
	s := NewCORSScanner()
	target := types.Target{}
	_, err := s.Run(context.Background(), target, scanner.DefaultOptions())

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot determine URL")
}

func TestCORSScanner_ContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	s := NewCORSScanner()
	target := types.Target{URL: srv.URL, Host: "127.0.0.1", Scheme: "http"}
	result, err := s.Run(ctx, target, scanner.DefaultOptions())

	require.NoError(t, err)
	assert.NotEmpty(t, result.Error)
}

func TestCORSScanner_FindingMetadata(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := NewCORSScanner()
	target := types.Target{URL: srv.URL, Host: "127.0.0.1", Scheme: "http"}
	result, err := s.Run(context.Background(), target, scanner.DefaultOptions())

	require.NoError(t, err)
	require.NotEmpty(t, result.Findings)

	// Find the first HIGH finding (reflected evil.com origin).
	for _, f := range result.Findings {
		if f.Severity == types.SeverityHigh {
			assert.Equal(t, "https://evil.com", f.Metadata["origin"])
			assert.NotEmpty(t, f.Metadata["method"])
			assert.NotEmpty(t, f.Metadata["access_control_allow_origin"])
			break
		}
	}
}
