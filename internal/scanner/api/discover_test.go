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

func TestScanner_NameAndDescription(t *testing.T) {
	s := New()
	assert.Equal(t, "api-discover", s.Name())
	assert.Equal(t, "API endpoint discovery", s.Description())
}

func TestScanner_DiscoversEndpoints(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
		case "/api/v1":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
		case "/swagger.json":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	s := New()
	target := types.Target{URL: srv.URL, Host: "127.0.0.1", Scheme: "http"}
	result, err := s.Run(context.Background(), target, scanner.DefaultOptions())

	require.NoError(t, err)
	assert.Len(t, result.Findings, 3)

	titles := make([]string, len(result.Findings))
	for i, f := range result.Findings {
		titles[i] = f.Title
	}
	assert.Contains(t, titles, "API endpoint discovered: /api")
	assert.Contains(t, titles, "API endpoint discovered: /api/v1")
	assert.Contains(t, titles, "API endpoint discovered: /swagger.json")
}

func TestScanner_NoEndpointsFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	s := New()
	target := types.Target{URL: srv.URL, Host: "127.0.0.1", Scheme: "http"}
	result, err := s.Run(context.Background(), target, scanner.DefaultOptions())

	require.NoError(t, err)
	assert.Empty(t, result.Findings)
}

func TestScanner_GraphQLIntrospection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/graphql" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		if r.Method == http.MethodPost {
			resp := map[string]interface{}{
				"data": map[string]interface{}{
					"__schema": map[string]interface{}{
						"types": []map[string]string{
							{"name": "Query"},
							{"name": "String"},
						},
					},
				},
			}
			json.NewEncoder(w).Encode(resp)
			return
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := New()
	target := types.Target{URL: srv.URL, Host: "127.0.0.1", Scheme: "http"}
	result, err := s.Run(context.Background(), target, scanner.DefaultOptions())

	require.NoError(t, err)
	require.Len(t, result.Findings, 2)
	assert.Equal(t, "API endpoint discovered: /graphql", result.Findings[0].Title)
	assert.Contains(t, result.Findings[1].Title, "GraphQL introspection enabled")
}

func TestScanner_GraphQLIntrospectionDisabled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/graphql" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		if r.Method == http.MethodPost {
			resp := map[string]interface{}{
				"errors": []map[string]string{
					{"message": "introspection is disabled"},
				},
			}
			json.NewEncoder(w).Encode(resp)
			return
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := New()
	target := types.Target{URL: srv.URL, Host: "127.0.0.1", Scheme: "http"}
	result, err := s.Run(context.Background(), target, scanner.DefaultOptions())

	require.NoError(t, err)
	// Only the GET probe finding, no introspection finding.
	require.Len(t, result.Findings, 1)
	assert.Equal(t, "API endpoint discovered: /graphql", result.Findings[0].Title)
}

func TestScanner_FindingMetadata(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api" {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	s := New()
	target := types.Target{URL: srv.URL, Host: "127.0.0.1", Scheme: "http"}
	result, err := s.Run(context.Background(), target, scanner.DefaultOptions())

	require.NoError(t, err)
	require.Len(t, result.Findings, 1)

	f := result.Findings[0]
	assert.Equal(t, types.SeverityInfo, f.Severity)
	assert.Equal(t, "/api", f.Metadata["path"])
	assert.Equal(t, "200", f.Metadata["status"])
	assert.Equal(t, "application/json; charset=utf-8", f.Metadata["content_type"])
}

func TestScanner_AllSeveritiesAreInfo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return 200 for every path to generate findings for all probed paths.
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := New()
	target := types.Target{URL: srv.URL, Host: "127.0.0.1", Scheme: "http"}
	result, err := s.Run(context.Background(), target, scanner.DefaultOptions())

	require.NoError(t, err)
	for _, f := range result.Findings {
		assert.Equal(t, types.SeverityInfo, f.Severity, "finding %q should be INFO", f.Title)
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

func TestScanner_EmptyTarget(t *testing.T) {
	s := New()
	target := types.Target{}
	_, err := s.Run(context.Background(), target, scanner.DefaultOptions())

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot determine URL")
}
