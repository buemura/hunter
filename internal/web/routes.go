package web

import (
	"encoding/json"
	"io/fs"
	"net/http"

	"github.com/buemura/hunter/internal/web/api"
	"github.com/buemura/hunter/internal/web/pages"
	"github.com/go-chi/chi/v5"
)

// registerRoutes mounts all route groups on the server's router.
func (s *Server) registerRoutes() {
	pageHandlers := pages.NewPageHandlers(s.manager, s.registry)
	apiHandlers := api.NewHandlers(s.manager, s.registry)

	// Page routes
	s.router.Get("/", pageHandlers.Index)
	s.router.Get("/scans", pageHandlers.ScanList)
	s.router.Get("/scans/{id}", pageHandlers.ScanDetail)

	// Health check
	s.router.Get("/health", s.handleHealth)

	// REST API
	s.router.Route("/api/v1", func(r chi.Router) {
		r.Post("/scans", apiHandlers.CreateScan)
		r.Get("/scans", apiHandlers.ListScans)
		r.Get("/scans/{id}", apiHandlers.GetScan)
		r.Get("/scans/{id}/report", apiHandlers.GetScanReport)
		r.Delete("/scans/{id}", apiHandlers.DeleteScan)
	})

	// Embedded static files
	staticSub, _ := fs.Sub(staticFS, "static")
	s.router.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(http.FS(staticSub))))
}

// handleHealth returns a simple health check response.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}
