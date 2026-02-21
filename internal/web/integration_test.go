package web

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/buemura/hunter/internal/scanner"
	"github.com/buemura/hunter/internal/web/jobs"
	"github.com/buemura/hunter/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockScanner struct {
	name string
}

func (m *mockScanner) Name() string        { return m.name }
func (m *mockScanner) Description() string { return "mock " + m.name }
func (m *mockScanner) Run(_ context.Context, target types.Target, _ scanner.Options) (*types.ScanResult, error) {
	return &types.ScanResult{
		ScannerName: m.name,
		Target:      target,
		Findings: []types.Finding{
			{Title: m.name + " finding", Severity: types.SeverityInfo, Description: "test finding from " + m.name},
		},
	}, nil
}

func newIntegrationServer() (*Server, *httptest.Server) {
	reg := scanner.NewRegistry()
	reg.Register(&mockScanner{name: "headers"})
	reg.Register(&mockScanner{name: "port"})
	srv := NewServer(":0", reg)
	ts := httptest.NewServer(srv.Router())
	return srv, ts
}

func waitForCompletion(t *testing.T, mgr *jobs.Manager, jobID string) {
	t.Helper()
	require.Eventually(t, func() bool {
		j, err := mgr.Get(jobID)
		if err != nil {
			return false
		}
		return j.Status == jobs.StatusCompleted
	}, 5*time.Second, 10*time.Millisecond)
}

func TestIntegration_SubmitScanPollAndVerifyResults(t *testing.T) {
	srv, ts := newIntegrationServer()
	defer ts.Close()

	// Create scan via API.
	body := `{"target": "https://example.com", "scanners": ["headers"]}`
	resp, err := http.Post(ts.URL+"/api/v1/scans", "application/json", bytes.NewBufferString(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	var created map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&created)
	require.NoError(t, err)
	jobID := created["id"].(string)
	assert.NotEmpty(t, jobID)

	// Wait for completion.
	waitForCompletion(t, srv.manager, jobID)

	// Poll results.
	resp2, err := http.Get(ts.URL + "/api/v1/scans/" + jobID)
	require.NoError(t, err)
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusOK, resp2.StatusCode)

	var job map[string]interface{}
	err = json.NewDecoder(resp2.Body).Decode(&job)
	require.NoError(t, err)
	assert.Equal(t, "completed", job["status"])
	results, ok := job["results"].([]interface{})
	require.True(t, ok)
	assert.NotEmpty(t, results)
}

func TestIntegration_CreateScanAndFetchHTMLReport(t *testing.T) {
	srv, ts := newIntegrationServer()
	defer ts.Close()

	// Create scan.
	body := `{"target": "https://example.com", "scanners": ["headers"]}`
	resp, err := http.Post(ts.URL+"/api/v1/scans", "application/json", bytes.NewBufferString(body))
	require.NoError(t, err)
	defer resp.Body.Close()

	var created map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&created)
	jobID := created["id"].(string)

	waitForCompletion(t, srv.manager, jobID)

	// Fetch HTML report.
	resp2, err := http.Get(ts.URL + "/api/v1/scans/" + jobID + "/report")
	require.NoError(t, err)
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusOK, resp2.StatusCode)
	assert.Equal(t, "text/html", resp2.Header.Get("Content-Type"))

	htmlBody, _ := io.ReadAll(resp2.Body)
	assert.Contains(t, string(htmlBody), "<!DOCTYPE html>")
}

func TestIntegration_ScanListShowsCreatedScan(t *testing.T) {
	_, ts := newIntegrationServer()
	defer ts.Close()

	// Initially empty.
	resp, err := http.Get(ts.URL + "/api/v1/scans")
	require.NoError(t, err)
	defer resp.Body.Close()

	var emptyList []interface{}
	json.NewDecoder(resp.Body).Decode(&emptyList)
	assert.Empty(t, emptyList)

	// Create a scan.
	body := `{"target": "https://example.com", "scanners": ["port"]}`
	resp2, err := http.Post(ts.URL+"/api/v1/scans", "application/json", bytes.NewBufferString(body))
	require.NoError(t, err)
	defer resp2.Body.Close()

	// Check list now contains it.
	resp3, err := http.Get(ts.URL + "/api/v1/scans")
	require.NoError(t, err)
	defer resp3.Body.Close()

	var list []interface{}
	json.NewDecoder(resp3.Body).Decode(&list)
	assert.Len(t, list, 1)
}

func TestIntegration_CreateAndDeleteScan(t *testing.T) {
	_, ts := newIntegrationServer()
	defer ts.Close()

	// Create scan.
	body := `{"target": "https://example.com", "scanners": ["headers"]}`
	resp, err := http.Post(ts.URL+"/api/v1/scans", "application/json", bytes.NewBufferString(body))
	require.NoError(t, err)
	defer resp.Body.Close()

	var created map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&created)
	jobID := created["id"].(string)

	// Delete it.
	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/scans/"+jobID, nil)
	resp2, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusNoContent, resp2.StatusCode)

	// Verify 404 on GET.
	resp3, err := http.Get(ts.URL + "/api/v1/scans/" + jobID)
	require.NoError(t, err)
	defer resp3.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp3.StatusCode)
}

func TestIntegration_HealthCheck(t *testing.T) {
	_, ts := newIntegrationServer()
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/health")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var body map[string]string
	json.NewDecoder(resp.Body).Decode(&body)
	assert.Equal(t, "ok", body["status"])
}

func TestIntegration_IndexPage(t *testing.T) {
	_, ts := newIntegrationServer()
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Content-Type"), "text/html")

	htmlBody, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(htmlBody), "Start Scan")
}

func TestIntegration_ScansPage(t *testing.T) {
	_, ts := newIntegrationServer()
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/scans")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Content-Type"), "text/html")
}

func TestIntegration_ScanDetailPage_NotFound(t *testing.T) {
	_, ts := newIntegrationServer()
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/scans/nonexistent")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestIntegration_StaticFiles(t *testing.T) {
	_, ts := newIntegrationServer()
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/static/css/style.css")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.NotEmpty(t, body)
}
