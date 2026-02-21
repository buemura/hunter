package web

import (
	"embed"
	"net/http"
	"time"

	"github.com/buemura/hunter/internal/scanner"
	"github.com/buemura/hunter/internal/web/jobs"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

//go:embed static/*
var staticFS embed.FS

// Server is the HTTP server for the Hunter web application.
type Server struct {
	router   chi.Router
	addr     string
	registry *scanner.Registry
	runner   *scanner.Runner
	manager  *jobs.Manager
}

// NewServer builds a new Server with middleware and routes configured.
func NewServer(addr string, reg *scanner.Registry) *Server {
	runner := scanner.NewRunner(reg)
	s := &Server{
		router:   chi.NewRouter(),
		addr:     addr,
		registry: reg,
		runner:   runner,
		manager:  jobs.NewManager(runner),
	}

	s.router.Use(middleware.Logger)
	s.router.Use(middleware.Recoverer)
	s.router.Use(middleware.RequestID)
	s.router.Use(middleware.Timeout(60 * time.Second))

	s.registerRoutes()

	return s
}

// Start begins listening on the configured address.
func (s *Server) Start() error {
	return http.ListenAndServe(s.addr, s.router)
}

// Router exposes the chi.Router for testing.
func (s *Server) Router() chi.Router {
	return s.router
}
