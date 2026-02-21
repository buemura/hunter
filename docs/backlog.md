# Hunter — Backlog

## Phase 1: Project Setup + Port Scanner [COMPLETED]

- [x] Go module init (`github.com/buemura/hunter`), Makefile, `.golangci.yml`
- [x] Domain types in `pkg/types/`: `Target`, `ParseTarget()`, `Finding`, `ScanResult`, `Severity`
- [x] Scanner engine in `internal/scanner/`: `Scanner` interface, `Registry`, `Runner` with bounded concurrency
- [x] Output formatters in `internal/output/`: `Formatter` interface, `TableFormatter` (colored, severity-sorted), `JSONFormatter`
- [x] Port scanner in `internal/scanner/port/`: TCP connect scan, `ParsePortRange`, service identification map
- [x] Cobra CLI in `internal/cli/`: root command with global flags, `scan port` subcommand, `version` command
- [x] 32 tests across all packages (unit + integration)
- [x] Documentation: README.md, docs/architecture.md, docs/usage.md

---

## Phase 2: Web Scanners [COMPLETED]

Adds HTTP header analysis, SSL/TLS inspection, and directory enumeration as new scanner modules.

### 2A: HTTP Header Scanner [COMPLETED]

Create `internal/scanner/headers/` and `internal/cli/scan_headers.go`.

- [x] Create `internal/scanner/headers/scanner.go` implementing `scanner.Scanner` interface
  - `Name()` returns `"headers"`, `Description()` returns `"HTTP security header analysis"`
  - `Run()` makes an HTTP GET to `target.URL` or `target.Scheme + "://" + target.Host`
  - Checks for missing/misconfigured security headers:
    - `Strict-Transport-Security` (HSTS) — severity HIGH if missing on HTTPS
    - `Content-Security-Policy` (CSP) — severity MEDIUM if missing
    - `X-Content-Type-Options` — severity LOW if missing (should be `nosniff`)
    - `X-Frame-Options` — severity LOW if missing
    - `X-XSS-Protection` — severity INFO (deprecated but worth noting)
    - `Referrer-Policy` — severity LOW if missing
    - `Permissions-Policy` — severity LOW if missing
  - Each missing/bad header produces a `Finding` with title, description, severity, and remediation text
- [x] Create `internal/scanner/headers/rules.go` with a `HeaderRule` struct: `Name`, `Check func(http.Header) *types.Finding`
  - Define each rule as a `HeaderRule` so adding new checks is just appending to a slice
- [x] Create `internal/scanner/headers/scanner_test.go`
  - Use `httptest.NewServer` to create test servers with controlled headers
  - Test: server with all security headers returns no findings
  - Test: server missing all headers returns findings for each
  - Test: server with partial headers returns only relevant findings
  - Test: HSTS check only triggers on HTTPS targets
- [x] Create `internal/cli/scan_headers.go`
  - Add `scanHeadersCmd` as subcommand of `scanCmd`
  - Requires `--target` flag, registers `headers.New()` in registry, runs via `runner.RunOne`
  - Supports `--output` flag (table/json)
- [x] Add integration test in `internal/cli/cli_test.go` using `httptest.NewServer`

### 2B: SSL/TLS Scanner [COMPLETED]

Create `internal/scanner/ssl/` and `internal/cli/scan_ssl.go`.

- [x] Create `internal/scanner/ssl/scanner.go` implementing `scanner.Scanner`
  - `Name()` returns `"ssl"`, `Description()` returns `"SSL/TLS configuration checks"`
  - `Run()` performs a `tls.Dial` to `target.Host:443` (or target port)
  - Checks:
    - Certificate expiration — HIGH if expired, MEDIUM if expires within 30 days
    - Certificate hostname mismatch — HIGH
    - Self-signed certificate — MEDIUM
    - TLS version: flag TLS 1.0/1.1 as HIGH severity (deprecated protocols)
    - Weak cipher suites — MEDIUM
  - Use `crypto/tls` and `crypto/x509` from stdlib — no external deps needed
- [x] Create `internal/scanner/ssl/scanner_test.go`
  - Use `httptest.NewTLSServer` for tests with valid TLS
  - Test: valid cert produces INFO-level findings only
  - Test: expired cert detection (use `crypto/x509` to craft test certs if needed)
  - Test: connection refused produces an error result, not a panic
- [x] Create `internal/cli/scan_ssl.go`
  - Add `scanSSLCmd` as subcommand of `scanCmd`
  - Requires `--target` flag
  - Supports `--output` flag

### 2C: Directory Enumeration Scanner [COMPLETED]

Create `internal/scanner/dirs/` and `internal/cli/scan_dirs.go`.

- [x] Create `internal/scanner/dirs/wordlist.go`
  - Embed a default wordlist using `//go:embed` with common paths: `/admin`, `/login`, `/api`, `/wp-admin`, `/phpmyadmin`, `/.env`, `/.git`, `/robots.txt`, `/sitemap.xml`, etc. (~100 entries)
  - Function `LoadWordlist(path string) ([]string, error)` — loads custom wordlist from file, falls back to embedded default
- [x] Create `internal/scanner/dirs/scanner.go` implementing `scanner.Scanner`
  - `Name()` returns `"dirs"`, `Description()` returns `"Directory and path enumeration"`
  - `Run()` iterates over wordlist, makes HEAD or GET requests to `baseURL + path`
  - Reports found paths (HTTP 200, 301, 302, 403) as findings
  - 200 = INFO (accessible), 403 = LOW (exists but forbidden), 301/302 = INFO (redirect)
  - Uses `opts.Concurrency` to bound parallel requests
  - Respects `ctx` cancellation
  - `opts.ExtraArgs["wordlist"]` specifies custom wordlist path
- [x] Create `internal/scanner/dirs/scanner_test.go`
  - Use `httptest.NewServer` with a handler that returns 200 for `/admin`, 404 for everything else
  - Test: discovers `/admin`, does not report 404 paths
  - Test: custom wordlist loading from file
  - Test: context cancellation stops enumeration
- [x] Create `internal/cli/scan_dirs.go`
  - Add `scanDirsCmd` as subcommand of `scanCmd`
  - Flags: `--target` (required), `--wordlist` (optional, default embedded), `--output`
- [x] Create `testdata/wordlists/common.txt` with ~100 common paths

---

## Phase 3: Vulnerability Detection [COMPLETED]

Adds basic vulnerability checks for XSS, SQL injection, and open redirects.

### 3A: Vulnerability Scanner Framework [COMPLETED]

Create `internal/scanner/vuln/` and `internal/cli/scan_vuln.go`.

- [x] Create `internal/scanner/vuln/scanner.go` implementing `scanner.Scanner`
  - `Name()` returns `"vuln"`, `Description()` returns `"Basic vulnerability detection"`
  - `Run()` executes all vuln check modules (XSS, SQLi, redirect) against the target
  - Each check module is a function: `func(ctx context.Context, target types.Target, opts scanner.Options) []types.Finding`
  - Aggregates all findings into a single `ScanResult`

### 3B: Reflected XSS Detection [COMPLETED]

- [x] Create `internal/scanner/vuln/xss.go`
  - Injects common XSS payloads into URL query parameters: `<script>alert(1)</script>`, `"><img src=x onerror=alert(1)>`, `javascript:alert(1)`
  - For each parameter found in `target.URL`, replaces the value with each payload
  - Makes GET request, checks if the payload appears unescaped in the response body
  - If reflected: finding with severity HIGH, evidence showing the reflected payload
  - Only runs if `target.URL` has query parameters; otherwise skips gracefully
- [x] Create `internal/scanner/vuln/xss_test.go`
  - `httptest.NewServer` that echoes query params in response body (vulnerable)
  - `httptest.NewServer` that HTML-escapes query params (not vulnerable)
  - Test: detects reflection in vulnerable server
  - Test: no findings for properly escaped server

### 3C: SQL Injection Detection [COMPLETED]

- [x] Create `internal/scanner/vuln/sqli.go`
  - Injects error-based SQLi payloads into URL query parameters: `'`, `' OR '1'='1`, `1; DROP TABLE`, `' UNION SELECT NULL--`
  - Checks response for SQL error signatures: `SQL syntax`, `mysql_fetch`, `ORA-`, `PostgreSQL`, `SQLite`, `ODBC`, `unclosed quotation`
  - If SQL error detected: finding with severity CRITICAL, evidence with the error string
  - Only runs if `target.URL` has query parameters
- [x] Create `internal/scanner/vuln/sqli_test.go`
  - Test server that returns SQL error messages for injected params
  - Test server that returns generic error (no SQL leak)
  - Test: detects SQL error in vulnerable server
  - Test: no findings for safe server

### 3D: Open Redirect Detection [COMPLETED]

- [x] Create `internal/scanner/vuln/redirect.go`
  - Scans for common redirect parameters: `url`, `redirect`, `next`, `return`, `goto`, `dest`, `redir`, `redirect_uri`, `return_to`
  - For each, sets value to `https://evil.com` and follows the request (without auto-redirect)
  - If response is 3xx and `Location` header points to `evil.com`: finding with severity MEDIUM
  - If `target.URL` has no params, tries appending each redirect param with evil value
- [x] Create `internal/scanner/vuln/redirect_test.go`
  - Test server that redirects `?redirect=<url>` to the given URL (vulnerable)
  - Test server that ignores the redirect param (safe)

### 3E: Vuln CLI Wiring [COMPLETED]

- [x] Create `internal/cli/scan_vuln.go`
  - Add `scanVulnCmd` as subcommand of `scanCmd`
  - Requires `--target` with a URL (not just host)
  - Flag: `--checks` to run specific checks (default: all) — comma-separated: `xss,sqli,redirect`
  - Registers `vuln.New()`, runs via `runner.RunOne`, formats output

---

## Phase 4: API Security Testing [COMPLETED]

Adds REST/GraphQL endpoint discovery, authentication testing, rate limit checks, and CORS misconfiguration detection.

### 4A: API Endpoint Discovery [COMPLETED]

Create `internal/scanner/api/` and `internal/cli/api.go` + subcommands.

- [x] Create `internal/cli/api.go` — parent command `hunter api` (like `hunter scan`)
- [x] Create `internal/scanner/api/discover.go` implementing `scanner.Scanner`
  - `Name()` returns `"api-discover"`
  - Probes common API paths: `/api`, `/api/v1`, `/api/v2`, `/graphql`, `/graphiql`, `/swagger.json`, `/openapi.json`, `/api-docs`, `/.well-known/openid-configuration`
  - For GraphQL: sends introspection query `{ __schema { types { name } } }` to detected GraphQL endpoints
  - Reports discovered endpoints as INFO findings with response status and content-type in metadata
- [x] Create `internal/scanner/api/discover_test.go`
- [x] Create `internal/cli/api_discover.go` — `hunter api discover -t <url>`

### 4B: Authentication Testing [COMPLETED]

- [x] Create `internal/scanner/api/auth.go` implementing `scanner.Scanner`
  - `Name()` returns `"api-auth"`
  - Tests discovered endpoints (or target URL) without credentials
  - Checks if endpoints return 200 instead of 401/403 (missing auth)
  - Tests with common default credentials if a login endpoint is found: `admin/admin`, `admin/password`
  - Checks for authentication bypass: removing `Authorization` header, using `Bearer null`, etc.
  - Findings: HIGH for endpoints accessible without auth, CRITICAL for default credentials working
- [x] Create `internal/scanner/api/auth_test.go`
- [x] Create `internal/cli/api_auth.go` — `hunter api auth -t <url>`

### 4C: Rate Limiting Check [COMPLETED]

- [x] Create `internal/scanner/api/ratelimit.go` implementing `scanner.Scanner`
  - `Name()` returns `"api-ratelimit"`
  - Sends N rapid requests (default 50) to the target endpoint
  - Checks if any response returns 429 (Too Many Requests) or rate-limit headers (`X-RateLimit-Limit`, `Retry-After`)
  - If no rate limiting detected after N requests: finding with severity MEDIUM
  - Reports rate limit headers if found as INFO findings
  - `opts.ExtraArgs["requests"]` to configure number of requests (default 50)
- [x] Create `internal/scanner/api/ratelimit_test.go`
- [x] Create `internal/cli/api_ratelimit.go` — `hunter api ratelimit -t <url>`

### 4D: CORS Misconfiguration Detection [COMPLETED]

- [x] Create `internal/scanner/api/cors.go` implementing `scanner.Scanner`
  - `Name()` returns `"api-cors"`
  - Sends requests with various `Origin` headers:
    - `https://evil.com` — if reflected in `Access-Control-Allow-Origin`, that's HIGH
    - `null` — if ACAO is `null`, that's MEDIUM
    - Check if `Access-Control-Allow-Credentials: true` combined with wildcard or reflected origin — CRITICAL
  - Tests preflight (OPTIONS) requests as well
- [x] Create `internal/scanner/api/cors_test.go`
- [x] Create `internal/cli/api_cors.go` — `hunter api cors -t <url>`

---

## Phase 5: Interactive TUI [COMPLETED]

Adds a Bubble Tea interactive terminal UI accessible via `hunter interactive`.

### 5A: TUI Framework Setup [COMPLETED]

- [x] Add dependencies: `github.com/charmbracelet/bubbletea`, `github.com/charmbracelet/bubbles`, `github.com/charmbracelet/lipgloss`
- [x] Create `internal/tui/app.go` — main Bubble Tea program entry point, `Run() error` function
- [x] Create `internal/tui/model.go` — root model with state machine: `stateMenu -> stateTarget -> stateScan -> stateResults`
- [x] Create `internal/tui/styles/styles.go` — lipgloss styles: colors for severities, borders, headers

### 5B: TUI Views [COMPLETED]

- [x] Create `internal/tui/views/menu.go` — main menu listing all available scan types with arrow-key navigation
- [x] Create `internal/tui/views/target.go` — text input for target URL/host with validation
- [x] Create `internal/tui/views/scan.go` — progress view with spinner, showing which scanners are running, live finding count
- [x] Create `internal/tui/views/results.go` — results table with severity coloring, scrollable, option to export to JSON

### 5C: TUI CLI Wiring [COMPLETED]

- [x] Create `internal/cli/interactive.go` — `hunter interactive` command that calls `tui.Run()`
- [x] Wire all registered scanners into the TUI so the menu dynamically lists available scan modules

---

## Phase 6: Polish and Release

### 6A: Configuration [COMPLETED]

- [x] Add `github.com/spf13/viper` dependency
- [x] Create `internal/config/config.go` — loads config from `~/.hunter.yaml`, env vars (`HUNTER_*`), and CLI flags (flag > env > file)
- [x] Support config options: default target, default output format, concurrency, timeout, custom wordlist path, scan profiles
- [x] Create `internal/config/config_test.go`

### 6B: Scan Profiles [COMPLETED]

- [x] Add `hunter scan full -t <target>` — runs all web scanners (port, headers, ssl, dirs, vuln) via `runner.RunAll`
- [x] Add `hunter api full -t <target>` — runs all API scanners
- [x] Add `hunter all -t <target>` — runs everything

### 6C: Additional Output Formats [COMPLETED]

- [x] Create `internal/output/markdown.go` — Markdown table output for pasting into docs/issues
- [x] Create `internal/output/html.go` — HTML report with styled severity badges, expandable findings
- [x] Update `GetFormatter()` to support `"markdown"` and `"html"`

### 6D: Release Automation [COMPLETED]

- [x] Add `.goreleaser.yml` for cross-platform binary builds (linux, darwin, windows; amd64, arm64)
- [x] Add GitHub Actions CI workflow: test, lint, build on PRs
- [x] Add release workflow: tag-triggered goreleaser build + GitHub release

---

## Phase 7: Web Application

Evolve Hunter into a web-based application. Users start scans from a web UI, configure targets and scan options, then receive a comprehensive report with findings, severity, evidence, and remediation tips.

**Architecture:** Go HTTP server (chi router) serving a REST API + server-rendered HTML frontend (Go `html/template`). Reuses the existing scanner engine (`internal/scanner/`), output formatters (`internal/output/`), and config system (`internal/config/`) — no changes needed to those packages.

**Parallelization guide:** Phases 7A through 7E are fully independent and can be built by separate agents in parallel. Phase 7F wires them together and must run after all others complete.

---

### 7A: HTTP Server Skeleton + Router [COMPLETED]

Create `internal/web/server.go`, `internal/web/routes.go`, and `internal/cli/serve.go`. This phase sets up the HTTP server, router, middleware, and the `hunter serve` CLI command. No business logic — just the plumbing.

**Dependencies to add:** `github.com/go-chi/chi/v5`

- [x] Create `internal/web/server.go`
  - `Server` struct holding: `chi.Router`, listen address (`string`), `scanner.Registry`, `scanner.Runner`
  - `NewServer(addr string, reg *scanner.Registry) *Server` — builds router, registers middleware, mounts routes
  - `func (s *Server) Start() error` — calls `http.ListenAndServe(s.addr, s.router)`
  - `func (s *Server) Router() chi.Router` — exposes router for testing
  - Middleware stack: `middleware.Logger`, `middleware.Recoverer`, `middleware.RequestID`, `middleware.Timeout(60s)`
  - Serve static files from `internal/web/static/` using `http.FileServer` at `/static/`
- [x] Create `internal/web/routes.go`
  - `func (s *Server) registerRoutes()` — called by `NewServer`, mounts all route groups:
    - `GET /` — serves the landing page (scan form)
    - `GET /health` — returns `{"status": "ok"}` (for healthchecks)
    - Route group `/api/v1/` — mounted in 7C (placeholder comment for now)
    - Route group `/scans/` — mounted in 7F (placeholder comment for now)
- [x] Create `internal/web/server_test.go`
  - Test: `GET /health` returns 200 with `{"status": "ok"}`
  - Test: `GET /` returns 200 with HTML content-type
  - Test: unknown route returns 404
  - Use `httptest.NewServer` with `s.Router()` for all tests
- [x] Create `internal/cli/serve.go`
  - Add `serveCmd` as subcommand of `rootCmd`: `hunter serve`
  - Flags: `--addr` (default `:8080`), `--target` is NOT required for this command
  - Registers all scanners in a `scanner.Registry` (same set as `all.go`: port, headers, ssl, dirs, vuln, api-discover, api-auth, api-cors, api-ratelimit)
  - Creates `web.NewServer(addr, registry)` and calls `s.Start()`
  - Prints `"Hunter web server listening on <addr>"` to stdout before blocking
- [x] Update `Makefile` — add `serve` target: `go run ./cmd/hunter serve`

---

### 7B: Scan Job Manager (In-Memory) [COMPLETED]

Create `internal/web/jobs/`. This is the async engine that manages scan lifecycle: create, execute in background, track status, store results. Fully independent — no HTTP handlers, no templates. Pure Go with tests.

- [x] Create `internal/web/jobs/job.go`
  - `JobStatus` type: `StatusPending`, `StatusRunning`, `StatusCompleted`, `StatusFailed`
  - `Job` struct:
    ```
    ID          string              // UUID
    Target      types.Target
    Scanners    []string            // scanner names to run (e.g., ["port", "headers", "ssl"])
    Options     scanner.Options
    Status      JobStatus
    Results     []types.ScanResult  // populated after completion
    Error       string              // populated on failure
    CreatedAt   time.Time
    StartedAt   time.Time
    CompletedAt time.Time
    Progress    JobProgress
    ```
  - `JobProgress` struct: `TotalScanners int`, `CompletedScanners int`, `CurrentScanner string`
- [x] Create `internal/web/jobs/manager.go`
  - `Manager` struct holding: `sync.RWMutex`, `jobs map[string]*Job`, `runner *scanner.Runner`
  - `NewManager(runner *scanner.Runner) *Manager`
  - `func (m *Manager) Create(target types.Target, scanners []string, opts scanner.Options) *Job` — creates job with UUID, sets status to Pending, stores in map, returns job
  - `func (m *Manager) Start(jobID string) error` — sets status to Running, launches goroutine that:
    - Iterates over `job.Scanners`, runs each via `m.runner.RunOne()` sequentially
    - Updates `job.Progress` after each scanner completes (CurrentScanner, CompletedScanners)
    - Appends each `ScanResult` to `job.Results`
    - On completion: sets status to Completed, sets CompletedAt
    - On error/panic: sets status to Failed, captures error
  - `func (m *Manager) Get(jobID string) (*Job, error)` — returns job or "not found" error
  - `func (m *Manager) List() []*Job` — returns all jobs sorted by CreatedAt descending
  - `func (m *Manager) Delete(jobID string) error` — removes job from map
- [x] Create `internal/web/jobs/manager_test.go`
  - Test: Create returns a job with Pending status and a valid UUID
  - Test: Start transitions job to Running, then to Completed
  - Test: Results are populated after completion with correct scanner names
  - Test: Progress updates correctly (CompletedScanners increments)
  - Test: Get returns error for unknown ID
  - Test: List returns jobs sorted by CreatedAt descending
  - Test: Delete removes job from map
  - Test: Start with invalid job ID returns error
  - Use mock scanners (from `internal/scanner/registry_test.go` pattern) for fast, deterministic tests

---

### 7C: REST API Handlers [COMPLETED]

Create `internal/web/api/`. JSON API for creating scans, polling status, and fetching results. Depends on the `Job` and `Manager` types from 7B conceptually, but can be coded against the interface/struct signatures without 7B being complete.

- [x] Create `internal/web/api/handlers.go`
  - All handlers receive `jobs.Manager` via closure or struct field
  - `POST /api/v1/scans` — Create and start a new scan
    - Request body: `{"target": "https://example.com", "scanners": ["port", "headers", "ssl"], "concurrency": 10, "timeout": "5s"}`
    - Validates target via `types.ParseTarget()`
    - If `scanners` is empty or `["all"]`, use all scanner names
    - Calls `manager.Create()` then `manager.Start()`
    - Returns 201 with `{"id": "<uuid>", "status": "running"}`
  - `GET /api/v1/scans` — List all scan jobs
    - Returns 200 with `[{"id": "...", "target": "...", "status": "...", "created_at": "...", "scanners": [...], "finding_count": N}]`
    - No results in list view (too large) — just metadata + finding count
  - `GET /api/v1/scans/{id}` — Get scan details + full results
    - Returns 200 with full `Job` serialized as JSON (including `Results` array)
    - Returns 404 if not found
  - `GET /api/v1/scans/{id}/report` — Get HTML report
    - Uses `output.HTMLFormatter{}` to render results into HTML
    - Returns `Content-Type: text/html`
    - Returns 404 if not found, 409 if scan not yet completed
  - `DELETE /api/v1/scans/{id}` — Delete a scan job
    - Returns 204 on success, 404 if not found
- [x] Create `internal/web/api/request.go`
  - `CreateScanRequest` struct: `Target string`, `Scanners []string`, `Concurrency int`, `Timeout string`
  - `func decodeCreateScanRequest(r *http.Request) (*CreateScanRequest, error)` — JSON decode + validation
  - Validate: target is non-empty, timeout parses as duration, concurrency > 0 (or default)
- [x] Create `internal/web/api/response.go`
  - `ErrorResponse` struct: `Error string`, `Code int`
  - `func writeJSON(w http.ResponseWriter, status int, data interface{})` — sets Content-Type, encodes JSON
  - `func writeError(w http.ResponseWriter, status int, msg string)` — writes ErrorResponse
- [x] Create `internal/web/api/handlers_test.go`
  - Test: `POST /api/v1/scans` with valid body returns 201 with job ID
  - Test: `POST /api/v1/scans` with empty target returns 400
  - Test: `POST /api/v1/scans` with invalid JSON returns 400
  - Test: `GET /api/v1/scans` returns list of jobs
  - Test: `GET /api/v1/scans/{id}` returns job with results after completion
  - Test: `GET /api/v1/scans/{id}` returns 404 for unknown ID
  - Test: `GET /api/v1/scans/{id}/report` returns HTML content-type
  - Test: `GET /api/v1/scans/{id}/report` returns 409 if scan is still running
  - Test: `DELETE /api/v1/scans/{id}` returns 204
  - Use mock scanners that return instantly for fast tests

---

### 7D: Frontend Templates + Static Assets [COMPLETED]

Create `internal/web/templates/` and `internal/web/static/`. Server-rendered HTML pages using Go `html/template`. Fully independent of 7B and 7C — just HTML/CSS/JS files and Go template rendering helpers.

**NOTE FOR AGENTS:** Use frontend-design skills for all UI work in this phase. The design should be polished, professional, and production-quality — not just functional. Think security dashboard aesthetics: clean typography, proper spacing, visual hierarchy, severity color coding, smooth transitions, and a cohesive design system throughout.

- [x] Create `internal/web/templates/base.html`
  - Base layout with `<!DOCTYPE html>`, `<head>` (charset, viewport, link to `/static/css/style.css`, title "Hunter"), `<body>`
  - Navigation bar: Hunter logo/name, links to "New Scan" (`/`), "Scan History" (`/scans`)
  - `{{block "content" .}}{{end}}` for page-specific content
  - Footer with version info
  - Link to `/static/js/app.js` before `</body>`
- [x] Create `internal/web/templates/index.html`
  - Extends `base.html`
  - Scan form with fields:
    - Target URL/host (text input, required, placeholder "https://example.com")
    - Scanner selection (checkboxes): Port Scan, HTTP Headers, SSL/TLS, Directory Enum, Vulnerability Scan, API Discovery, API Auth, API CORS, API Rate Limit — plus "Select All" toggle
    - Concurrency (number input, default 10)
    - Timeout (select: 5s, 10s, 30s, 60s)
  - Submit button: "Start Scan"
  - Form submits via JavaScript `fetch()` to `POST /api/v1/scans`, then redirects to `/scans/{id}`
- [x] Create `internal/web/templates/scans.html`
  - Extends `base.html`
  - Table listing all past scans: ID (truncated, linked), Target, Scanners (badge list), Status (colored badge: green=completed, yellow=running, red=failed, gray=pending), Finding Count, Created At
  - Auto-refreshes every 5 seconds if any scan is running (via JS `setInterval` + `fetch GET /api/v1/scans`)
  - "New Scan" button linking to `/`
- [x] Create `internal/web/templates/scan_detail.html`
  - Extends `base.html`
  - Header section: scan ID, target, status badge, timestamps (created, started, completed, duration)
  - Progress section (shown while running): progress bar (`completedScanners / totalScanners`), current scanner name, auto-polls `GET /api/v1/scans/{id}` every 2 seconds
  - Results section (shown when completed): for each `ScanResult`:
    - Scanner name as section header
    - Finding count badge
    - Findings table: Severity (colored), Title, Description
    - Expandable details per finding: Evidence, Remediation tip
  - Summary section at top: total findings, breakdown by severity (badges: X critical, Y high, Z medium, W low, V info)
  - Action buttons: "Download JSON" (`/api/v1/scans/{id}` with Accept: application/json), "View HTML Report" (`/api/v1/scans/{id}/report`), "Delete Scan"
- [x] Create `internal/web/static/css/style.css`
  - Clean, modern design — dark header, light content area
  - Severity colors: critical=#dc2626, high=#ea580c, medium=#ca8a04, low=#0891b2, info=#6b7280
  - Responsive layout (works on mobile)
  - Form styling, table styling, badge/pill components, progress bar
  - Expandable `<details>` styling for evidence/remediation sections
- [x] Create `internal/web/static/js/app.js`
  - `submitScan()` — handles form submission via `fetch`, shows loading state, redirects on success, shows error on failure
  - `pollScanStatus(scanId)` — polls `GET /api/v1/scans/{id}` every 2s, updates progress bar and status badge, stops polling when completed/failed
  - `refreshScanList()` — fetches `GET /api/v1/scans`, updates the scans table DOM
  - `deleteScan(scanId)` — calls `DELETE /api/v1/scans/{id}`, removes row from table or redirects to `/scans`
  - No framework needed — vanilla JavaScript with `fetch()`
- [x] Create `internal/web/templates/templates.go`
  - `var Templates *template.Template` — parsed once at startup via `template.ParseGlob` or `embed.FS`
  - Embed all templates using `//go:embed templates/*.html`
  - Template functions: `severityColor(Severity) string`, `truncateID(string) string`, `formatDuration(time.Duration) string`, `formatTime(time.Time) string`
  - `func RenderPage(w http.ResponseWriter, name string, data interface{}) error` — executes named template into writer
- [x] Create `internal/web/templates/templates_test.go`
  - Test: all templates parse without error
  - Test: `RenderPage` for each page produces valid HTML containing expected elements
  - Test: template functions return expected values

---

### 7E: Web Page Handlers [COMPLETED]

Create `internal/web/pages/`. These are the HTTP handlers that serve the HTML pages. They sit between the templates (7D) and the job manager (7B). Can be built in parallel — just code against the `jobs.Manager` and `templates.RenderPage` signatures.

- [x] Create `internal/web/pages/handlers.go`
  - `PageHandlers` struct holding: `manager *jobs.Manager`, `registry *scanner.Registry`
  - `NewPageHandlers(manager *jobs.Manager, registry *scanner.Registry) *PageHandlers`
  - `func (h *PageHandlers) Index(w http.ResponseWriter, r *http.Request)` — renders `index.html` with available scanner list from registry
  - `func (h *PageHandlers) ScanList(w http.ResponseWriter, r *http.Request)` — calls `manager.List()`, renders `scans.html` with job list
  - `func (h *PageHandlers) ScanDetail(w http.ResponseWriter, r *http.Request)` — extracts `{id}` from URL path (via `chi.URLParam`), calls `manager.Get(id)`, renders `scan_detail.html` — returns 404 page if not found
- [x] Create `internal/web/pages/handlers_test.go`
  - Test: Index returns 200 with HTML containing "Start Scan"
  - Test: ScanList returns 200 with HTML containing scan table
  - Test: ScanDetail returns 200 with HTML containing scan ID and target
  - Test: ScanDetail returns 404 for unknown scan ID
  - Use mock job manager for tests

---

### 7F: Integration + Wiring [COMPLETED]

Wire all components together. This phase connects the server skeleton (7A), job manager (7B), REST API (7C), templates (7D), and page handlers (7E) into a working application.

- [x] Update `internal/web/server.go`
  - `NewServer` now also creates a `jobs.Manager` and stores it on the `Server` struct
  - Embed static files using `//go:embed static/*` for single-binary deployment
- [x] Update `internal/web/routes.go` — mount all routes:
  - `GET /` → `pages.Index`
  - `GET /scans` → `pages.ScanList`
  - `GET /scans/{id}` → `pages.ScanDetail`
  - `POST /api/v1/scans` → `api.CreateScan`
  - `GET /api/v1/scans` → `api.ListScans`
  - `GET /api/v1/scans/{id}` → `api.GetScan`
  - `GET /api/v1/scans/{id}/report` → `api.GetScanReport`
  - `DELETE /api/v1/scans/{id}` → `api.DeleteScan`
  - `GET /health` → healthcheck
  - `GET /static/*` → embedded file server
- [x] Create `internal/web/integration_test.go` — end-to-end tests:
  - Test: Start server, submit scan form via API, poll until completed, verify results
  - Test: Start server, create scan, fetch HTML report, verify it contains findings
  - Test: Start server, visit `/scans`, verify empty list, create scan, verify it appears
  - Test: Create scan, delete it, verify 404 on GET
  - Use mock scanners with instant results for fast tests
- [x] Update `README.md` — add "Web Mode" section:
  ```
  ## Web Mode
  hunter serve --addr :8080
  ```
  Open `http://localhost:8080` to access the web interface.
- [x] Update `docs/usage.md` — add web usage section with screenshots placeholders
- [x] Update `docs/architecture.md` — add web architecture section describing the server, job manager, API, and template layers
