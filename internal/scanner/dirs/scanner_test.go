package dirs

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/buemura/hunter/internal/scanner"
	"github.com/buemura/hunter/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("admin panel"))
	})
	mux.HandleFunc("/secret", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})
	mux.HandleFunc("/old-page", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/new-page")
		w.WriteHeader(http.StatusMovedPermanently)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	return httptest.NewServer(mux)
}

func TestScanner_DiscoversAdmin(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	s := New()
	target := types.Target{Host: "localhost", URL: srv.URL}
	opts := scanner.Options{
		Concurrency: 5,
		Timeout:     2 * time.Second,
		ExtraArgs:   map[string]interface{}{},
	}

	// Use a small custom wordlist to keep the test fast.
	wordlist := filepath.Join(t.TempDir(), "wordlist.txt")
	err := os.WriteFile(wordlist, []byte("/admin\n/nonexistent\n/another404\n"), 0644)
	require.NoError(t, err)
	opts.ExtraArgs["wordlist"] = wordlist

	result, err := s.Run(context.Background(), target, opts)
	require.NoError(t, err)
	require.Len(t, result.Findings, 1)
	assert.Equal(t, "/admin", result.Findings[0].Metadata["path"])
	assert.Equal(t, "200", result.Findings[0].Metadata["status_code"])
	assert.Equal(t, types.SeverityInfo, result.Findings[0].Severity)
}

func TestScanner_DoesNotReport404(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	s := New()
	target := types.Target{Host: "localhost", URL: srv.URL}

	wordlist := filepath.Join(t.TempDir(), "wordlist.txt")
	err := os.WriteFile(wordlist, []byte("/nonexistent\n/fake\n/missing\n"), 0644)
	require.NoError(t, err)

	opts := scanner.Options{
		Concurrency: 5,
		Timeout:     2 * time.Second,
		ExtraArgs:   map[string]interface{}{"wordlist": wordlist},
	}

	result, err := s.Run(context.Background(), target, opts)
	require.NoError(t, err)
	assert.Empty(t, result.Findings)
}

func TestScanner_Reports403AsLow(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	s := New()
	target := types.Target{Host: "localhost", URL: srv.URL}

	wordlist := filepath.Join(t.TempDir(), "wordlist.txt")
	err := os.WriteFile(wordlist, []byte("/secret\n"), 0644)
	require.NoError(t, err)

	opts := scanner.Options{
		Concurrency: 5,
		Timeout:     2 * time.Second,
		ExtraArgs:   map[string]interface{}{"wordlist": wordlist},
	}

	result, err := s.Run(context.Background(), target, opts)
	require.NoError(t, err)
	require.Len(t, result.Findings, 1)
	assert.Equal(t, types.SeverityLow, result.Findings[0].Severity)
	assert.Equal(t, "403", result.Findings[0].Metadata["status_code"])
}

func TestScanner_ReportsRedirect(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	s := New()
	target := types.Target{Host: "localhost", URL: srv.URL}

	wordlist := filepath.Join(t.TempDir(), "wordlist.txt")
	err := os.WriteFile(wordlist, []byte("/old-page\n"), 0644)
	require.NoError(t, err)

	opts := scanner.Options{
		Concurrency: 5,
		Timeout:     2 * time.Second,
		ExtraArgs:   map[string]interface{}{"wordlist": wordlist},
	}

	result, err := s.Run(context.Background(), target, opts)
	require.NoError(t, err)
	require.Len(t, result.Findings, 1)
	assert.Equal(t, types.SeverityInfo, result.Findings[0].Severity)
	assert.Equal(t, "301", result.Findings[0].Metadata["status_code"])
	assert.Equal(t, "/new-page", result.Findings[0].Metadata["location"])
}

func TestScanner_ContextCancellation(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	s := New()
	target := types.Target{Host: "localhost", URL: srv.URL}

	wordlist := filepath.Join(t.TempDir(), "wordlist.txt")
	err := os.WriteFile(wordlist, []byte("/admin\n/secret\n"), 0644)
	require.NoError(t, err)

	opts := scanner.Options{
		Concurrency: 5,
		Timeout:     2 * time.Second,
		ExtraArgs:   map[string]interface{}{"wordlist": wordlist},
	}

	result, err := s.Run(ctx, target, opts)
	require.NoError(t, err)
	assert.NotNil(t, result)
	// With an already-cancelled context, no findings should be reported.
	assert.Empty(t, result.Findings)
}

func TestLoadWordlist_Default(t *testing.T) {
	paths, err := LoadWordlist("")
	require.NoError(t, err)
	assert.NotEmpty(t, paths)
	assert.Contains(t, paths, "/admin")
	assert.Contains(t, paths, "/.env")
}

func TestLoadWordlist_CustomFile(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "custom.txt")
	err := os.WriteFile(tmp, []byte("/custom1\n/custom2\n# comment\n\n/custom3\n"), 0644)
	require.NoError(t, err)

	paths, err := LoadWordlist(tmp)
	require.NoError(t, err)
	assert.Equal(t, []string{"/custom1", "/custom2", "/custom3"}, paths)
}

func TestLoadWordlist_FileNotFound(t *testing.T) {
	_, err := LoadWordlist("/nonexistent/file.txt")
	assert.Error(t, err)
}

func TestScanner_NameAndDescription(t *testing.T) {
	s := New()
	assert.Equal(t, "dirs", s.Name())
	assert.Equal(t, "Directory and path enumeration", s.Description())
}

func TestBuildBaseURL(t *testing.T) {
	tests := []struct {
		name   string
		target types.Target
		want   string
	}{
		{
			name:   "with URL",
			target: types.Target{URL: "http://example.com/"},
			want:   "http://example.com",
		},
		{
			name:   "with host and scheme",
			target: types.Target{Host: "example.com", Scheme: "https"},
			want:   "https://example.com",
		},
		{
			name:   "with host only",
			target: types.Target{Host: "example.com"},
			want:   "https://example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, buildBaseURL(tt.target))
		})
	}
}
