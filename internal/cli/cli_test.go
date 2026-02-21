package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"

	"github.com/buemura/hunter/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func executeCmd(args ...string) (string, error) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs(args)

	// Capture stdout for commands that write to os.Stdout.
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := rootCmd.Execute()

	w.Close()
	os.Stdout = oldStdout

	var captured bytes.Buffer
	captured.ReadFrom(r)

	// Combine cobra output and stdout capture.
	output := buf.String() + captured.String()
	return output, err
}

// executeCmdLarge is like executeCmd but reads stdout in a goroutine to avoid
// pipe buffer deadlocks when commands produce large output (>64KB).
func executeCmdLarge(args ...string) (string, error) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs(args)

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Read pipe concurrently to prevent buffer deadlock.
	var captured bytes.Buffer
	done := make(chan struct{})
	go func() {
		captured.ReadFrom(r)
		close(done)
	}()

	err := rootCmd.Execute()

	w.Close()
	os.Stdout = oldStdout
	<-done

	output := buf.String() + captured.String()
	return output, err
}

func TestVersionCommand(t *testing.T) {
	output, err := executeCmd("version")
	require.NoError(t, err)
	assert.Contains(t, output, "hunter version")
}

func TestScanPortMissingTarget(t *testing.T) {
	_, err := executeCmd("scan", "port")
	assert.Error(t, err)
}

func TestScanPortDetectsOpenPort(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	_, portStr, _ := net.SplitHostPort(listener.Addr().String())

	output, err := executeCmd("scan", "port", "-t", "127.0.0.1", "--ports", portStr, "-o", "table")
	require.NoError(t, err)
	assert.Contains(t, output, "Open port: "+portStr)
}

func TestScanPortJSONOutput(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	_, portStr, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	output, err := executeCmd("scan", "port", "-t", "127.0.0.1", "--ports", portStr, "-o", "json")
	require.NoError(t, err)

	var results []types.ScanResult
	err = json.Unmarshal([]byte(output), &results)
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.Len(t, results[0].Findings, 1)
	assert.Equal(t, strconv.Itoa(port), results[0].Findings[0].Metadata["port"])
}

func TestScanHelpListsPort(t *testing.T) {
	output, err := executeCmd("scan", "--help")
	require.NoError(t, err)
	assert.Contains(t, output, "port")
}

func TestScanHeadersMissingTarget(t *testing.T) {
	_, err := executeCmd("scan", "headers")
	assert.Error(t, err)
}

func TestScanHeadersDetectsMissingHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	output, err := executeCmd("scan", "headers", "-t", srv.URL, "-o", "table")
	require.NoError(t, err)
	assert.Contains(t, output, "Missing Content-Security-Policy header")
	assert.Contains(t, output, "Missing X-Content-Type-Options header")
}

func TestScanHeadersNoFindingsWhenAllPresent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "0")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "camera=()")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	output, err := executeCmd("scan", "headers", "-t", srv.URL, "-o", "json")
	require.NoError(t, err)

	var results []types.ScanResult
	err = json.Unmarshal([]byte(output), &results)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Empty(t, results[0].Findings)
}

func TestScanHelpListsHeaders(t *testing.T) {
	output, err := executeCmd("scan", "--help")
	require.NoError(t, err)
	assert.Contains(t, output, "headers")
}

func TestScanVulnMissingTarget(t *testing.T) {
	targetFlag = ""
	_, err := executeCmd("scan", "vuln")
	assert.Error(t, err)
}

func TestScanVulnDetectsXSS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "<html>"+q+"</html>")
	}))
	defer srv.Close()

	output, err := executeCmd("scan", "vuln", "-t", srv.URL+"?q=test", "-o", "table")
	require.NoError(t, err)
	assert.Contains(t, output, "Potential reflected XSS")
}

func TestScanVulnJSONOutput(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "safe response")
	}))
	defer srv.Close()

	output, err := executeCmd("scan", "vuln", "-t", srv.URL, "-o", "json")
	require.NoError(t, err)

	var results []types.ScanResult
	err = json.Unmarshal([]byte(output), &results)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "vuln", results[0].ScannerName)
}

func TestScanHelpListsVuln(t *testing.T) {
	output, err := executeCmd("scan", "--help")
	require.NoError(t, err)
	assert.Contains(t, output, "vuln")
}

// --- scan full ---

func TestScanFullMissingTarget(t *testing.T) {
	targetFlag = ""
	_, err := executeCmd("scan", "full")
	assert.Error(t, err)
}

func TestScanFullRunsAllWebScanners(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	output, err := executeCmd("scan", "full", "-t", srv.URL, "-o", "json")
	require.NoError(t, err)

	var results []types.ScanResult
	err = json.Unmarshal([]byte(output), &results)
	require.NoError(t, err)

	scannerNames := make(map[string]bool)
	for _, r := range results {
		scannerNames[r.ScannerName] = true
	}
	for _, name := range []string{"port", "headers", "ssl", "dirs", "vuln"} {
		assert.True(t, scannerNames[name], "expected scanner %q in results", name)
	}
}

func TestScanHelpListsFull(t *testing.T) {
	output, err := executeCmd("scan", "--help")
	require.NoError(t, err)
	assert.Contains(t, output, "full")
}

// --- api full ---

func TestAPIFullMissingTarget(t *testing.T) {
	targetFlag = ""
	_, err := executeCmd("api", "full")
	assert.Error(t, err)
}

func TestAPIFullRunsAllAPIScanners(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	output, err := executeCmd("api", "full", "-t", srv.URL, "-o", "json")
	require.NoError(t, err)

	var results []types.ScanResult
	err = json.Unmarshal([]byte(output), &results)
	require.NoError(t, err)

	scannerNames := make(map[string]bool)
	for _, r := range results {
		scannerNames[r.ScannerName] = true
	}
	for _, name := range []string{"api-discover", "api-auth", "api-cors", "api-ratelimit"} {
		assert.True(t, scannerNames[name], "expected scanner %q in results", name)
	}
}

func TestAPIHelpListsFull(t *testing.T) {
	output, err := executeCmd("api", "--help")
	require.NoError(t, err)
	assert.Contains(t, output, "full")
}

// --- all ---

func TestAllMissingTarget(t *testing.T) {
	targetFlag = ""
	_, err := executeCmd("all")
	assert.Error(t, err)
}

func TestAllRunsEverything(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	// Use executeCmdLarge to avoid pipe buffer deadlock on large output.
	output, err := executeCmdLarge("all", "-t", srv.URL, "-o", "json", "--timeout", "1s")
	require.NoError(t, err)

	var results []types.ScanResult
	err = json.Unmarshal([]byte(output), &results)
	require.NoError(t, err)

	scannerNames := make(map[string]bool)
	for _, r := range results {
		scannerNames[r.ScannerName] = true
	}
	all := []string{"port", "headers", "ssl", "dirs", "vuln", "api-discover", "api-auth", "api-cors", "api-ratelimit"}
	for _, name := range all {
		assert.True(t, scannerNames[name], "expected scanner %q in results", name)
	}
}

func TestRootHelpListsAll(t *testing.T) {
	output, err := executeCmd("--help")
	require.NoError(t, err)
	assert.Contains(t, output, "all")
}
