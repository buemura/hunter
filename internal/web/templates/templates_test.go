package templates

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/buemura/hunter/internal/web/jobs"
	"github.com/buemura/hunter/pkg/types"
)

func TestAllTemplatesParseWithoutError(t *testing.T) {
	expectedPages := []string{"index.html", "scans.html", "scan_detail.html", "not_found.html"}
	for _, name := range expectedPages {
		if _, ok := pages[name]; !ok {
			t.Errorf("expected page template %q to be parsed", name)
		}
	}
}

func TestRenderPage_SetsContentType(t *testing.T) {
	rec := httptest.NewRecorder()
	err := RenderPage(rec, "not_found.html", struct{ Message string }{"test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("expected Content-Type text/html, got %q", ct)
	}
}

func TestRenderPage_UnknownTemplateReturnsError(t *testing.T) {
	rec := httptest.NewRecorder()
	err := RenderPage(rec, "does_not_exist.html", nil)
	if err == nil {
		t.Fatal("expected error for unknown template")
	}
	if !strings.Contains(err.Error(), "template not found") {
		t.Errorf("expected 'template not found' in error, got: %v", err)
	}
}

func TestRenderPage_IndexContainsExpectedElements(t *testing.T) {
	rec := httptest.NewRecorder()

	type scannerInfo struct {
		Name        string
		Description string
	}
	data := struct {
		Scanners []scannerInfo
	}{
		Scanners: []scannerInfo{
			{Name: "port", Description: "TCP port scan"},
			{Name: "headers", Description: "HTTP security header analysis"},
		},
	}

	err := RenderPage(rec, "index.html", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	body := rec.Body.String()
	for _, expected := range []string{"Start Scan", "port", "headers", "New Scan", "Target"} {
		if !strings.Contains(body, expected) {
			t.Errorf("expected index page to contain %q", expected)
		}
	}
}

func TestRenderPage_ScansEmptyList(t *testing.T) {
	rec := httptest.NewRecorder()
	data := struct {
		Jobs       []*jobs.Job
		HasRunning bool
	}{
		Jobs:       nil,
		HasRunning: false,
	}
	err := RenderPage(rec, "scans.html", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "Scan History") {
		t.Error("expected scans page to contain 'Scan History'")
	}
	if !strings.Contains(body, "No scans yet") {
		t.Error("expected scans page to contain 'No scans yet'")
	}
}

func TestRenderPage_ScansWithJobs(t *testing.T) {
	rec := httptest.NewRecorder()
	j := &jobs.Job{
		ID:        "abcdef12-3456-7890-abcd-ef1234567890",
		Target:    types.Target{Host: "example.com", Scheme: "https"},
		Scanners:  []string{"port", "headers"},
		Status:    jobs.StatusCompleted,
		CreatedAt: time.Date(2026, 2, 20, 10, 0, 0, 0, time.UTC),
		Results: []types.ScanResult{
			{Findings: []types.Finding{{Severity: types.SeverityInfo}}},
		},
	}
	data := struct {
		Jobs       []*jobs.Job
		HasRunning bool
	}{
		Jobs:       []*jobs.Job{j},
		HasRunning: false,
	}
	err := RenderPage(rec, "scans.html", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	body := rec.Body.String()
	for _, expected := range []string{"abcdef12", "example.com", "completed", "port", "headers"} {
		if !strings.Contains(body, expected) {
			t.Errorf("expected scans page to contain %q", expected)
		}
	}
}

func TestRenderPage_ScanDetailCompleted(t *testing.T) {
	rec := httptest.NewRecorder()
	started := time.Date(2026, 2, 20, 10, 0, 0, 0, time.UTC)
	completed := started.Add(5 * time.Second)
	j := &jobs.Job{
		ID:          "abcdef12-3456-7890-abcd-ef1234567890",
		Target:      types.Target{Host: "example.com", URL: "https://example.com", Scheme: "https"},
		Scanners:    []string{"headers"},
		Status:      jobs.StatusCompleted,
		CreatedAt:   started,
		StartedAt:   started,
		CompletedAt: completed,
		Results: []types.ScanResult{
			{
				ScannerName: "headers",
				Findings: []types.Finding{
					{
						Title:       "Missing HSTS",
						Description: "Strict-Transport-Security header is missing",
						Severity:    types.SeverityHigh,
						Evidence:    "No HSTS header found",
						Remediation: "Add Strict-Transport-Security header",
					},
					{
						Title:       "CSP Present",
						Description: "Content-Security-Policy found",
						Severity:    types.SeverityInfo,
					},
				},
			},
		},
	}
	data := struct {
		Job *jobs.Job
	}{Job: j}
	err := RenderPage(rec, "scan_detail.html", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	body := rec.Body.String()
	for _, expected := range []string{
		"Scan Details",
		"abcdef12-3456-7890-abcd-ef1234567890",
		"https://example.com",
		"Missing HSTS",
		"1 High",
		"1 Info",
		"2 total findings",
		"Show details",
		"No HSTS header found",
		"Download JSON",
		"View HTML Report",
		"Delete Scan",
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("expected scan detail page to contain %q", expected)
		}
	}
}

func TestRenderPage_ScanDetailRunning(t *testing.T) {
	rec := httptest.NewRecorder()
	j := &jobs.Job{
		ID:       "running-id-1234567890",
		Target:   types.Target{Host: "example.com"},
		Scanners: []string{"port", "headers"},
		Status:   jobs.StatusRunning,
		Progress: jobs.JobProgress{
			TotalScanners:     2,
			CompletedScanners: 1,
			CurrentScanner:    "headers",
		},
		CreatedAt: time.Now(),
		StartedAt: time.Now(),
	}
	data := struct {
		Job *jobs.Job
	}{Job: j}
	err := RenderPage(rec, "scan_detail.html", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	body := rec.Body.String()
	for _, expected := range []string{"Progress", "1 / 2 scanners complete", "headers"} {
		if !strings.Contains(body, expected) {
			t.Errorf("expected running scan detail to contain %q", expected)
		}
	}
}

func TestRenderPage_ScanDetailFailed(t *testing.T) {
	rec := httptest.NewRecorder()
	j := &jobs.Job{
		ID:        "failed-id-1234567890",
		Target:    types.Target{Host: "example.com"},
		Status:    jobs.StatusFailed,
		Error:     "connection refused",
		CreatedAt: time.Now(),
	}
	data := struct {
		Job *jobs.Job
	}{Job: j}
	err := RenderPage(rec, "scan_detail.html", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "connection refused") {
		t.Error("expected failed scan detail to contain error message")
	}
}

func TestRenderPage_NotFoundContainsMessage(t *testing.T) {
	rec := httptest.NewRecorder()
	err := RenderPage(rec, "not_found.html", struct{ Message string }{"Scan not found."})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Scan not found.") {
		t.Error("expected not_found page to contain the error message")
	}
	if !strings.Contains(body, "Not Found") {
		t.Error("expected not_found page to contain 'Not Found'")
	}
}

// Template function tests

func TestSeverityColor(t *testing.T) {
	tests := []struct {
		sev  types.Severity
		want string
	}{
		{types.SeverityCritical, "#dc2626"},
		{types.SeverityHigh, "#ea580c"},
		{types.SeverityMedium, "#ca8a04"},
		{types.SeverityLow, "#0891b2"},
		{types.SeverityInfo, "#6b7280"},
		{types.Severity("UNKNOWN"), "#6b7280"},
	}
	for _, tt := range tests {
		if got := severityColor(tt.sev); got != tt.want {
			t.Errorf("severityColor(%q) = %q, want %q", tt.sev, got, tt.want)
		}
	}
}

func TestSeverityClass(t *testing.T) {
	tests := []struct {
		sev  types.Severity
		want string
	}{
		{types.SeverityCritical, "critical"},
		{types.SeverityHigh, "high"},
		{types.SeverityMedium, "medium"},
		{types.SeverityLow, "low"},
		{types.SeverityInfo, "info"},
	}
	for _, tt := range tests {
		if got := severityClass(tt.sev); got != tt.want {
			t.Errorf("severityClass(%q) = %q, want %q", tt.sev, got, tt.want)
		}
	}
}

func TestTruncateID(t *testing.T) {
	if got := truncateID("abcdefghijklmnop"); got != "abcdefgh" {
		t.Errorf("truncateID long = %q, want %q", got, "abcdefgh")
	}
	if got := truncateID("short"); got != "short" {
		t.Errorf("truncateID short = %q, want %q", got, "short")
	}
	if got := truncateID(""); got != "" {
		t.Errorf("truncateID empty = %q, want %q", got, "")
	}
}

func TestFormatDuration(t *testing.T) {
	if got := formatDuration(500 * time.Millisecond); got != "500ms" {
		t.Errorf("formatDuration(500ms) = %q", got)
	}
	if got := formatDuration(3 * time.Second); got != "3s" {
		t.Errorf("formatDuration(3s) = %q", got)
	}
	if got := formatDuration(65 * time.Second); got != "1m5s" {
		t.Errorf("formatDuration(65s) = %q", got)
	}
}

func TestFormatTime(t *testing.T) {
	if got := formatTime(time.Time{}); got != "-" {
		t.Errorf("formatTime(zero) = %q, want %q", got, "-")
	}
	ts := time.Date(2026, 2, 20, 14, 30, 0, 0, time.UTC)
	if got := formatTime(ts); got != "2026-02-20 14:30:00" {
		t.Errorf("formatTime = %q", got)
	}
}

func TestCountSeverity(t *testing.T) {
	results := []types.ScanResult{
		{Findings: []types.Finding{
			{Severity: types.SeverityHigh},
			{Severity: types.SeverityHigh},
			{Severity: types.SeverityLow},
		}},
		{Findings: []types.Finding{
			{Severity: types.SeverityHigh},
		}},
	}
	if got := countSeverity(results, "HIGH"); got != 3 {
		t.Errorf("countSeverity HIGH = %d, want 3", got)
	}
	if got := countSeverity(results, "LOW"); got != 1 {
		t.Errorf("countSeverity LOW = %d, want 1", got)
	}
	if got := countSeverity(results, "CRITICAL"); got != 0 {
		t.Errorf("countSeverity CRITICAL = %d, want 0", got)
	}
}

func TestTotalFindings(t *testing.T) {
	results := []types.ScanResult{
		{Findings: []types.Finding{{}, {}}},
		{Findings: []types.Finding{{}}},
	}
	if got := totalFindings(results); got != 3 {
		t.Errorf("totalFindings = %d, want 3", got)
	}
	if got := totalFindings(nil); got != 0 {
		t.Errorf("totalFindings(nil) = %d, want 0", got)
	}
}

func TestProgressPct(t *testing.T) {
	if got := progressPct(0, 0); got != 0 {
		t.Errorf("progressPct(0,0) = %d, want 0", got)
	}
	if got := progressPct(1, 2); got != 50 {
		t.Errorf("progressPct(1,2) = %d, want 50", got)
	}
	if got := progressPct(3, 3); got != 100 {
		t.Errorf("progressPct(3,3) = %d, want 100", got)
	}
	if got := progressPct(1, 3); got != 33 {
		t.Errorf("progressPct(1,3) = %d, want 33", got)
	}
}
