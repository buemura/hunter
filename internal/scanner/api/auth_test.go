package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/buemura/hunter/internal/scanner"
	"github.com/buemura/hunter/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthScanner_NameAndDescription(t *testing.T) {
	s := NewAuthScanner()
	assert.Equal(t, "api-auth", s.Name())
	assert.Equal(t, "API authentication testing", s.Description())
}

func TestAuthScanner_NoAuthEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":"sensitive"}`))
	}))
	defer srv.Close()

	s := NewAuthScanner()
	target := types.Target{URL: srv.URL + "/api/v1/users", Host: "127.0.0.1", Scheme: "http"}
	result, err := s.Run(context.Background(), target, scanner.DefaultOptions())

	require.NoError(t, err)
	require.NotEmpty(t, result.Findings)

	// Should find the no-auth issue.
	var found bool
	for _, f := range result.Findings {
		if f.Severity == types.SeverityHigh && f.Metadata["check"] == "no-auth" {
			found = true
			assert.Contains(t, f.Title, "Endpoint accessible without authentication")
			break
		}
	}
	assert.True(t, found, "expected HIGH finding for endpoint accessible without auth")
}

func TestAuthScanner_ProtectedEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// Reject all bypass attempts too.
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	s := NewAuthScanner()
	target := types.Target{URL: srv.URL + "/api/secret", Host: "127.0.0.1", Scheme: "http"}
	result, err := s.Run(context.Background(), target, scanner.DefaultOptions())

	require.NoError(t, err)

	// No no-auth findings since the endpoint returns 401.
	for _, f := range result.Findings {
		assert.NotEqual(t, "no-auth", f.Metadata["check"],
			"expected no 'no-auth' findings for a protected endpoint")
	}
}

func TestAuthScanner_AuthBypass(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// Server incorrectly accepts "Bearer null".
		if auth == "Bearer null" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"bypassed":true}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	s := NewAuthScanner()
	target := types.Target{URL: srv.URL + "/api/data", Host: "127.0.0.1", Scheme: "http"}
	result, err := s.Run(context.Background(), target, scanner.DefaultOptions())

	require.NoError(t, err)

	var bypassFound bool
	for _, f := range result.Findings {
		if f.Metadata["check"] == "auth-bypass" && f.Metadata["bypass_method"] == "Bearer null" {
			bypassFound = true
			assert.Equal(t, types.SeverityHigh, f.Severity)
			assert.Contains(t, f.Title, "Authentication bypass")
			break
		}
	}
	assert.True(t, bypassFound, "expected auth bypass finding for Bearer null")
}

func TestAuthScanner_NoBypassOnWellProtectedEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" || auth == "Bearer null" || auth == "Bearer undefined" || auth == "Bearer " {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// Only accept valid tokens.
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	s := NewAuthScanner()
	target := types.Target{URL: srv.URL + "/api/secure", Host: "127.0.0.1", Scheme: "http"}
	result, err := s.Run(context.Background(), target, scanner.DefaultOptions())

	require.NoError(t, err)

	for _, f := range result.Findings {
		assert.NotEqual(t, "auth-bypass", f.Metadata["check"],
			"expected no bypass findings for a well-protected endpoint")
	}
}

func TestAuthScanner_DefaultCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" && r.Method == http.MethodPost {
			var body struct {
				Username string `json:"username"`
				Password string `json:"password"`
			}
			json.NewDecoder(r.Body).Decode(&body)

			if body.Username == "admin" && body.Password == "admin" {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"token":"fake-jwt"}`))
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if r.Method == http.MethodGet && r.URL.Path == "/login" {
			// Login endpoint exists.
			w.WriteHeader(http.StatusOK)
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	s := NewAuthScanner()
	target := types.Target{URL: srv.URL, Host: "127.0.0.1", Scheme: "http"}
	result, err := s.Run(context.Background(), target, scanner.DefaultOptions())

	require.NoError(t, err)

	var credFound bool
	for _, f := range result.Findings {
		if f.Metadata["check"] == "default-credentials" {
			credFound = true
			assert.Equal(t, types.SeverityCritical, f.Severity)
			assert.Contains(t, f.Title, "Default credentials accepted")
			assert.Contains(t, f.Title, "admin/admin")
			break
		}
	}
	assert.True(t, credFound, "expected CRITICAL finding for default credentials")
}

func TestAuthScanner_DefaultCredentialsRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" && r.Method == http.MethodPost {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Path == "/login" && r.Method == http.MethodGet {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	s := NewAuthScanner()
	target := types.Target{URL: srv.URL, Host: "127.0.0.1", Scheme: "http"}
	result, err := s.Run(context.Background(), target, scanner.DefaultOptions())

	require.NoError(t, err)

	for _, f := range result.Findings {
		assert.NotEqual(t, "default-credentials", f.Metadata["check"],
			"expected no default-credentials findings when creds are rejected")
	}
}

func TestAuthScanner_NotFoundEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	s := NewAuthScanner()
	target := types.Target{URL: srv.URL + "/api/nonexistent", Host: "127.0.0.1", Scheme: "http"}
	result, err := s.Run(context.Background(), target, scanner.DefaultOptions())

	require.NoError(t, err)
	assert.Empty(t, result.Findings, "expected no findings for 404 endpoints")
}

func TestAuthScanner_InvalidTarget(t *testing.T) {
	s := NewAuthScanner()
	target := types.Target{}
	_, err := s.Run(context.Background(), target, scanner.DefaultOptions())

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot determine URL")
}

func TestAuthScanner_ScanResultMetadata(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := NewAuthScanner()
	target := types.Target{URL: srv.URL + "/api/test", Host: "127.0.0.1", Scheme: "http"}
	result, err := s.Run(context.Background(), target, scanner.DefaultOptions())

	require.NoError(t, err)
	assert.Equal(t, "api-auth", result.ScannerName)
	assert.False(t, result.StartedAt.IsZero())
	assert.False(t, result.CompletedAt.IsZero())
	assert.True(t, result.CompletedAt.After(result.StartedAt) || result.CompletedAt.Equal(result.StartedAt))
}

func TestTruncate(t *testing.T) {
	assert.Equal(t, "hello", truncate("hello", 10))
	assert.Equal(t, "hel...", truncate("hello world", 3))
	assert.Equal(t, "", truncate("", 5))
}
