package pages_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/buemura/hunter/internal/scanner"
	"github.com/buemura/hunter/internal/web/jobs"
	"github.com/buemura/hunter/internal/web/pages"
	"github.com/buemura/hunter/pkg/types"
	"github.com/go-chi/chi/v5"
)

// mockScanner is a minimal scanner for testing.
type mockScanner struct {
	name string
	desc string
}

func (m *mockScanner) Name() string        { return m.name }
func (m *mockScanner) Description() string { return m.desc }
func (m *mockScanner) Run(_ context.Context, _ types.Target, _ scanner.Options) (*types.ScanResult, error) {
	return &types.ScanResult{ScannerName: m.name}, nil
}

func newTestRegistry() *scanner.Registry {
	reg := scanner.NewRegistry()
	reg.Register(&mockScanner{name: "port", desc: "TCP port scan"})
	reg.Register(&mockScanner{name: "headers", desc: "HTTP security header analysis"})
	return reg
}

func newTestManager(reg *scanner.Registry) *jobs.Manager {
	runner := scanner.NewRunner(reg)
	return jobs.NewManager(runner)
}

func TestIndex_Returns200WithStartScan(t *testing.T) {
	reg := newTestRegistry()
	mgr := newTestManager(reg)
	h := pages.NewPageHandlers(mgr, reg)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	h.Index(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Start Scan") {
		t.Error("expected response to contain 'Start Scan'")
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Errorf("expected Content-Type text/html, got %q", ct)
	}
}

func TestIndex_ContainsScannerNames(t *testing.T) {
	reg := newTestRegistry()
	mgr := newTestManager(reg)
	h := pages.NewPageHandlers(mgr, reg)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	h.Index(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, "port") {
		t.Error("expected response to contain scanner name 'port'")
	}
	if !strings.Contains(body, "headers") {
		t.Error("expected response to contain scanner name 'headers'")
	}
}

func TestScanList_Returns200WithScanTable(t *testing.T) {
	reg := newTestRegistry()
	mgr := newTestManager(reg)
	h := pages.NewPageHandlers(mgr, reg)

	// Create a job so the list is not empty.
	target := types.Target{Host: "example.com", Scheme: "https"}
	mgr.Create(target, []string{"port"}, scanner.DefaultOptions())

	req := httptest.NewRequest(http.MethodGet, "/scans", nil)
	rec := httptest.NewRecorder()

	h.ScanList(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "scans-table") {
		t.Error("expected response to contain scan table")
	}
	if !strings.Contains(body, "example.com") {
		t.Error("expected response to contain target 'example.com'")
	}
}

func TestScanList_EmptyReturnsNoScansMessage(t *testing.T) {
	reg := newTestRegistry()
	mgr := newTestManager(reg)
	h := pages.NewPageHandlers(mgr, reg)

	req := httptest.NewRequest(http.MethodGet, "/scans", nil)
	rec := httptest.NewRecorder()

	h.ScanList(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "No scans yet") {
		t.Error("expected response to contain 'No scans yet'")
	}
}

func TestScanDetail_Returns200WithScanInfo(t *testing.T) {
	reg := newTestRegistry()
	mgr := newTestManager(reg)
	h := pages.NewPageHandlers(mgr, reg)

	target := types.Target{Host: "example.com", Scheme: "https"}
	job := mgr.Create(target, []string{"port"}, scanner.DefaultOptions())

	// Set up chi context with URL param.
	r := chi.NewRouter()
	r.Get("/scans/{id}", h.ScanDetail)

	req := httptest.NewRequest(http.MethodGet, "/scans/"+job.ID, nil)
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, job.ID) {
		t.Errorf("expected response to contain job ID %q", job.ID)
	}
	if !strings.Contains(body, "example.com") {
		t.Error("expected response to contain target 'example.com'")
	}
}

func TestScanDetail_Returns404ForUnknownID(t *testing.T) {
	reg := newTestRegistry()
	mgr := newTestManager(reg)
	h := pages.NewPageHandlers(mgr, reg)

	r := chi.NewRouter()
	r.Get("/scans/{id}", h.ScanDetail)

	req := httptest.NewRequest(http.MethodGet, "/scans/nonexistent", nil)
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "not found") && !strings.Contains(body, "Not Found") {
		t.Error("expected response to contain not found message")
	}
}
