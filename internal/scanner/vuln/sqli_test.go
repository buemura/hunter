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

func TestCheckSQLi_DetectsSQLError(t *testing.T) {
	// Vulnerable server: returns SQL error messages for injected params.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Error: You have an error in your SQL syntax near '%s'", id)
	}))
	defer srv.Close()

	target := types.Target{URL: srv.URL + "?id=1", Host: "127.0.0.1", Scheme: "http"}
	findings := CheckSQLi(context.Background(), target, scanner.DefaultOptions())

	require.NotEmpty(t, findings)
	assert.Equal(t, "Potential SQL injection", findings[0].Title)
	assert.Equal(t, types.SeverityCritical, findings[0].Severity)
	assert.Equal(t, "sqli", findings[0].Metadata["check"])
	assert.Equal(t, "id", findings[0].Metadata["param"])
}

func TestCheckSQLi_NoFindingsForSafeServer(t *testing.T) {
	// Safe server: returns a generic error without SQL details.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "Bad request: invalid input")
	}))
	defer srv.Close()

	target := types.Target{URL: srv.URL + "?id=1", Host: "127.0.0.1", Scheme: "http"}
	findings := CheckSQLi(context.Background(), target, scanner.DefaultOptions())

	assert.Empty(t, findings)
}

func TestCheckSQLi_SkipsWhenNoQueryParams(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	target := types.Target{URL: srv.URL, Host: "127.0.0.1", Scheme: "http"}
	findings := CheckSQLi(context.Background(), target, scanner.DefaultOptions())

	assert.Empty(t, findings)
}

func TestCheckSQLi_DetectsMultipleErrorPatterns(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		pattern string
	}{
		{"PostgreSQL", "ERROR: PostgreSQL query failed", "postgresql"},
		{"SQLite", "SQLite error: near syntax", "sqlite"},
		{"ORA", "ORA-01756: quoted string not properly terminated", "ora-"},
		{"ODBC", "Microsoft ODBC Driver error", "odbc"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, tt.body)
			}))
			defer srv.Close()

			target := types.Target{URL: srv.URL + "?id=1", Host: "127.0.0.1", Scheme: "http"}
			findings := CheckSQLi(context.Background(), target, scanner.DefaultOptions())

			require.NotEmpty(t, findings)
			assert.Equal(t, tt.pattern, findings[0].Metadata["error_pattern"])
		})
	}
}

func TestCheckSQLi_ContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	target := types.Target{URL: srv.URL + "?id=1", Host: "127.0.0.1", Scheme: "http"}
	findings := CheckSQLi(ctx, target, scanner.DefaultOptions())

	assert.Empty(t, findings)
}
