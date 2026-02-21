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

func TestCheckOpenRedirect_DetectsVulnerableRedirect(t *testing.T) {
	// Vulnerable server: redirects to whatever URL the "redirect" param says.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if redir := r.URL.Query().Get("redirect"); redir != "" {
			http.Redirect(w, r, redir, http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	target := types.Target{URL: srv.URL, Host: "127.0.0.1", Scheme: "http"}
	findings := CheckOpenRedirect(context.Background(), target, scanner.DefaultOptions())

	require.NotEmpty(t, findings)

	var found bool
	for _, f := range findings {
		if f.Metadata["param"] == "redirect" {
			found = true
			assert.Equal(t, "Potential open redirect", f.Title)
			assert.Equal(t, types.SeverityMedium, f.Severity)
			assert.Equal(t, "redirect", f.Metadata["check"])
		}
	}
	assert.True(t, found, "expected finding for 'redirect' param")
}

func TestCheckOpenRedirect_NoFindingsForSafeServer(t *testing.T) {
	// Safe server: ignores redirect parameters.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "OK")
	}))
	defer srv.Close()

	target := types.Target{URL: srv.URL, Host: "127.0.0.1", Scheme: "http"}
	findings := CheckOpenRedirect(context.Background(), target, scanner.DefaultOptions())

	assert.Empty(t, findings)
}

func TestCheckOpenRedirect_WithExistingRedirectParam(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if dest := r.URL.Query().Get("next"); dest != "" {
			http.Redirect(w, r, dest, http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// URL already has the "next" param which is a known redirect param.
	target := types.Target{URL: srv.URL + "?next=/dashboard", Host: "127.0.0.1", Scheme: "http"}
	findings := CheckOpenRedirect(context.Background(), target, scanner.DefaultOptions())

	require.NotEmpty(t, findings)
	assert.Equal(t, "next", findings[0].Metadata["param"])
}

func TestCheckOpenRedirect_ContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	target := types.Target{URL: srv.URL, Host: "127.0.0.1", Scheme: "http"}
	findings := CheckOpenRedirect(ctx, target, scanner.DefaultOptions())

	assert.Empty(t, findings)
}
