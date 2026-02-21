package pages

import (
	"net/http"

	"github.com/buemura/hunter/internal/scanner"
	"github.com/buemura/hunter/internal/web/jobs"
	"github.com/buemura/hunter/internal/web/templates"
	"github.com/go-chi/chi/v5"
)

// ScannerInfo holds display information about a registered scanner.
type ScannerInfo struct {
	Name        string
	Description string
}

// IndexData is the template data for the index (scan form) page.
type IndexData struct {
	Scanners []ScannerInfo
}

// ScanListData is the template data for the scan history page.
type ScanListData struct {
	Jobs       []*jobs.Job
	HasRunning bool
}

// ScanDetailData is the template data for the scan detail page.
type ScanDetailData struct {
	Job *jobs.Job
}

// NotFoundData is the template data for the 404 page.
type NotFoundData struct {
	Message string
}

// PageHandlers serves the HTML pages of the web application.
type PageHandlers struct {
	manager  *jobs.Manager
	registry *scanner.Registry
}

// NewPageHandlers creates a new PageHandlers.
func NewPageHandlers(manager *jobs.Manager, registry *scanner.Registry) *PageHandlers {
	return &PageHandlers{
		manager:  manager,
		registry: registry,
	}
}

// Index renders the landing page with the scan form.
func (h *PageHandlers) Index(w http.ResponseWriter, r *http.Request) {
	scanners := h.registry.All()
	info := make([]ScannerInfo, len(scanners))
	for i, s := range scanners {
		info[i] = ScannerInfo{Name: s.Name(), Description: s.Description()}
	}

	data := IndexData{Scanners: info}
	if err := templates.RenderPage(w, "index.html", data); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// ScanList renders the scan history page.
func (h *PageHandlers) ScanList(w http.ResponseWriter, r *http.Request) {
	jobList := h.manager.List()
	hasRunning := false
	for _, j := range jobList {
		if j.Status == jobs.StatusRunning || j.Status == jobs.StatusPending {
			hasRunning = true
			break
		}
	}
	data := ScanListData{Jobs: jobList, HasRunning: hasRunning}
	if err := templates.RenderPage(w, "scans.html", data); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// ScanDetail renders the detail page for a single scan.
func (h *PageHandlers) ScanDetail(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	job, err := h.manager.Get(id)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		templates.RenderPage(w, "not_found.html", NotFoundData{
			Message: "Scan not found.",
		})
		return
	}

	data := ScanDetailData{Job: job}
	if err := templates.RenderPage(w, "scan_detail.html", data); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}
