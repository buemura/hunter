package api

import (
	"bytes"
	"net/http"
	"time"

	"github.com/buemura/hunter/internal/output"
	"github.com/buemura/hunter/internal/scanner"
	"github.com/buemura/hunter/internal/web/jobs"
	"github.com/buemura/hunter/pkg/types"
	"github.com/go-chi/chi/v5"
)

// Handlers holds dependencies for the REST API handlers.
type Handlers struct {
	Manager  *jobs.Manager
	Registry *scanner.Registry
}

// NewHandlers creates API handlers with the given dependencies.
func NewHandlers(manager *jobs.Manager, registry *scanner.Registry) *Handlers {
	return &Handlers{Manager: manager, Registry: registry}
}

// CreateScan handles POST /api/v1/scans.
func (h *Handlers) CreateScan(w http.ResponseWriter, r *http.Request) {
	req, err := decodeCreateScanRequest(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	target, err := types.ParseTarget(req.Target)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid target: "+err.Error())
		return
	}

	scannerNames := req.Scanners
	if len(scannerNames) == 0 || (len(scannerNames) == 1 && scannerNames[0] == "all") {
		all := h.Registry.All()
		scannerNames = make([]string, len(all))
		for i, s := range all {
			scannerNames[i] = s.Name()
		}
	}

	opts := scanner.Options{
		Concurrency: req.Concurrency,
		Timeout:     5 * time.Second,
	}
	if req.Timeout != "" {
		d, _ := time.ParseDuration(req.Timeout) // already validated
		opts.Timeout = d
	}

	job := h.Manager.Create(target, scannerNames, opts)
	if err := h.Manager.Start(job.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to start scan: "+err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"id":     job.ID,
		"status": job.Status,
	})
}

// ListScans handles GET /api/v1/scans.
func (h *Handlers) ListScans(w http.ResponseWriter, r *http.Request) {
	jobList := h.Manager.List()

	type scanSummary struct {
		ID           string         `json:"id"`
		Target       string         `json:"target"`
		Status       jobs.JobStatus `json:"status"`
		CreatedAt    time.Time      `json:"created_at"`
		Scanners     []string       `json:"scanners"`
		FindingCount int            `json:"finding_count"`
	}

	summaries := make([]scanSummary, len(jobList))
	for i, j := range jobList {
		target := j.Target.Host
		if j.Target.URL != "" {
			target = j.Target.URL
		}
		summaries[i] = scanSummary{
			ID:           j.ID,
			Target:       target,
			Status:       j.Status,
			CreatedAt:    j.CreatedAt,
			Scanners:     j.Scanners,
			FindingCount: j.FindingCount(),
		}
	}

	writeJSON(w, http.StatusOK, summaries)
}

// GetScan handles GET /api/v1/scans/{id}.
func (h *Handlers) GetScan(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	job, err := h.Manager.Get(id)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, job)
}

// GetScanReport handles GET /api/v1/scans/{id}/report.
func (h *Handlers) GetScanReport(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	job, err := h.Manager.Get(id)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	if job.Status != jobs.StatusCompleted {
		writeError(w, http.StatusConflict, "scan is not yet completed")
		return
	}

	formatter := &output.HTMLFormatter{}
	var buf bytes.Buffer
	if err := formatter.Format(&buf, job.Results); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to render report: "+err.Error())
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	w.Write(buf.Bytes())
}

// DeleteScan handles DELETE /api/v1/scans/{id}.
func (h *Handlers) DeleteScan(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := h.Manager.Delete(id); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
