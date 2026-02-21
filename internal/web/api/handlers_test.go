package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/buemura/hunter/internal/scanner"
	"github.com/buemura/hunter/internal/web/jobs"
	"github.com/buemura/hunter/pkg/types"
	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockScanner struct {
	name string
}

func (m *mockScanner) Name() string        { return m.name }
func (m *mockScanner) Description() string { return "mock" }
func (m *mockScanner) Run(_ context.Context, target types.Target, _ scanner.Options) (*types.ScanResult, error) {
	return &types.ScanResult{
		ScannerName: m.name,
		Target:      target,
		Findings: []types.Finding{
			{Title: m.name + " finding", Severity: types.SeverityInfo},
		},
	}, nil
}

func setupTestHandlers() (*Handlers, *chi.Mux) {
	reg := scanner.NewRegistry()
	reg.Register(&mockScanner{name: "headers"})
	reg.Register(&mockScanner{name: "port"})
	runner := scanner.NewRunner(reg)
	mgr := jobs.NewManager(runner)
	h := NewHandlers(mgr, reg)

	r := chi.NewRouter()
	r.Post("/api/v1/scans", h.CreateScan)
	r.Get("/api/v1/scans", h.ListScans)
	r.Get("/api/v1/scans/{id}", h.GetScan)
	r.Get("/api/v1/scans/{id}/report", h.GetScanReport)
	r.Delete("/api/v1/scans/{id}", h.DeleteScan)
	return h, r
}

func TestCreateScan_ValidBody(t *testing.T) {
	_, router := setupTestHandlers()

	body := `{"target": "https://example.com", "scanners": ["headers"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scans", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.NotEmpty(t, resp["id"])
	assert.Equal(t, "running", resp["status"])
}

func TestCreateScan_EmptyTarget(t *testing.T) {
	_, router := setupTestHandlers()

	body := `{"target": "", "scanners": ["headers"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scans", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateScan_InvalidJSON(t *testing.T) {
	_, router := setupTestHandlers()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/scans", bytes.NewBufferString("{invalid"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateScan_AllScanners(t *testing.T) {
	_, router := setupTestHandlers()

	body := `{"target": "https://example.com", "scanners": ["all"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scans", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
}

func TestListScans_ReturnsJobs(t *testing.T) {
	h, router := setupTestHandlers()

	// Create a job directly.
	target := types.Target{Host: "example.com", Scheme: "https"}
	h.Manager.Create(target, []string{"headers"}, scanner.DefaultOptions())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var list []map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &list)
	require.NoError(t, err)
	assert.Len(t, list, 1)
	assert.Equal(t, "example.com", list[0]["target"])
}

func TestGetScan_Found(t *testing.T) {
	h, router := setupTestHandlers()

	target := types.Target{Host: "example.com", Scheme: "https"}
	job := h.Manager.Create(target, []string{"headers"}, scanner.DefaultOptions())
	h.Manager.Start(job.ID)

	// Wait for completion.
	require.Eventually(t, func() bool {
		j, _ := h.Manager.Get(job.ID)
		return j.Status == jobs.StatusCompleted
	}, 5*time.Second, 10*time.Millisecond)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans/"+job.ID, nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, job.ID, resp["id"])
	assert.NotNil(t, resp["results"])
}

func TestGetScan_NotFound(t *testing.T) {
	_, router := setupTestHandlers()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans/nonexistent", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestGetScanReport_ReturnsHTML(t *testing.T) {
	h, router := setupTestHandlers()

	target := types.Target{Host: "example.com", Scheme: "https"}
	job := h.Manager.Create(target, []string{"headers"}, scanner.DefaultOptions())
	h.Manager.Start(job.ID)

	require.Eventually(t, func() bool {
		j, _ := h.Manager.Get(job.ID)
		return j.Status == jobs.StatusCompleted
	}, 5*time.Second, 10*time.Millisecond)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans/"+job.ID+"/report", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "text/html", w.Header().Get("Content-Type"))
	assert.Contains(t, w.Body.String(), "<!DOCTYPE html>")
}

func TestGetScanReport_NotCompleted(t *testing.T) {
	h, router := setupTestHandlers()

	target := types.Target{Host: "example.com", Scheme: "https"}
	job := h.Manager.Create(target, []string{"headers"}, scanner.DefaultOptions())
	// Don't start — status is pending.

	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans/"+job.ID+"/report", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusConflict, w.Code)
}

func TestDeleteScan_Success(t *testing.T) {
	h, router := setupTestHandlers()

	target := types.Target{Host: "example.com", Scheme: "https"}
	job := h.Manager.Create(target, []string{"headers"}, scanner.DefaultOptions())

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/scans/"+job.ID, nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)

	// Verify deleted.
	_, err := h.Manager.Get(job.ID)
	assert.Error(t, err)
}

func TestDeleteScan_NotFound(t *testing.T) {
	_, router := setupTestHandlers()

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/scans/nonexistent", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}
