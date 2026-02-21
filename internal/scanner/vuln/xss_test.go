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

func TestCheckReflectedXSS_DetectsReflection(t *testing.T) {
	// Vulnerable server: echoes query params in response body unescaped.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("search")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "<html><body>Results for: %s</body></html>", q)
	}))
	defer srv.Close()

	target := types.Target{URL: srv.URL + "?search=test", Host: "127.0.0.1", Scheme: "http"}
	findings := CheckReflectedXSS(context.Background(), target, scanner.DefaultOptions())

	require.NotEmpty(t, findings)
	assert.Equal(t, "Potential reflected XSS", findings[0].Title)
	assert.Equal(t, types.SeverityHigh, findings[0].Severity)
	assert.Equal(t, "xss", findings[0].Metadata["check"])
	assert.Equal(t, "search", findings[0].Metadata["param"])
}

func TestCheckReflectedXSS_NoFindingsForEscapedServer(t *testing.T) {
	// Safe server: strips/ignores query params instead of reflecting them.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.URL.Query().Get("search")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "<html><body>Results for: safe content</body></html>")
	}))
	defer srv.Close()

	target := types.Target{URL: srv.URL + "?search=test", Host: "127.0.0.1", Scheme: "http"}
	findings := CheckReflectedXSS(context.Background(), target, scanner.DefaultOptions())

	assert.Empty(t, findings)
}

func TestCheckReflectedXSS_SkipsWhenNoQueryParams(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	target := types.Target{URL: srv.URL, Host: "127.0.0.1", Scheme: "http"}
	findings := CheckReflectedXSS(context.Background(), target, scanner.DefaultOptions())

	assert.Empty(t, findings)
}

func TestCheckReflectedXSS_MultipleParams(t *testing.T) {
	// Server that reflects all params.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		for _, vals := range r.URL.Query() {
			for _, v := range vals {
				fmt.Fprint(w, v)
			}
		}
	}))
	defer srv.Close()

	target := types.Target{URL: srv.URL + "?a=1&b=2", Host: "127.0.0.1", Scheme: "http"}
	findings := CheckReflectedXSS(context.Background(), target, scanner.DefaultOptions())

	// Both params should yield findings (3 payloads each).
	assert.GreaterOrEqual(t, len(findings), 2)
}

func TestCheckReflectedXSS_ContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	target := types.Target{URL: srv.URL + "?q=test", Host: "127.0.0.1", Scheme: "http"}
	findings := CheckReflectedXSS(ctx, target, scanner.DefaultOptions())

	assert.Empty(t, findings)
}
