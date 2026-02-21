# Architecture

## Overview

Hunter uses a modular scanner architecture where each scan type is an independent module implementing a common interface. This makes it easy to add new scanners without modifying existing code.

## Core Components

```
cmd/hunter/main.go  →  internal/cli/  →  internal/scanner/  →  internal/output/
     (entry)           (commands)         (engine)              (formatting)
                           ↓
                    internal/config/
                    (configuration)
                                              ↓
                                     internal/scanner/port/
                                     internal/scanner/headers/
                                     internal/scanner/ssl/
                                     internal/scanner/dirs/
                                     internal/scanner/vuln/
                                     internal/scanner/api/
```

### Scanner Interface

Every scanner module implements this interface:

```go
type Scanner interface {
    Name() string
    Description() string
    Run(ctx context.Context, target types.Target, opts Options) (*types.ScanResult, error)
}
```

### Registry

Scanners register themselves with a `Registry`. The CLI and TUI look up scanners by name:

```go
reg := scanner.NewRegistry()
reg.Register(port.New())
```

### Runner

The `Runner` executes scanners concurrently with configurable parallelism:

```go
runner := scanner.NewRunner(reg)
results := runner.RunAll(ctx, []string{"port", "headers"}, target, opts)
```

### Output Formatters

Results are rendered by `Formatter` implementations. The CLI picks the formatter based on the `--output` flag:

```go
formatter, _ := output.GetFormatter("json")
formatter.Format(os.Stdout, results)
```

Supported formats:

| Format     | Description                                                        |
|------------|--------------------------------------------------------------------|
| `table`    | Colored terminal table (default)                                   |
| `json`     | Indented JSON                                                      |
| `markdown` | Markdown table for pasting into docs/issues                        |
| `html`     | Self-contained HTML report with styled severity badges and expandable details |

## Adding a New Scanner

1. Create a new package under `internal/scanner/<name>/`
2. Implement the `Scanner` interface
3. Add tests in the same package
4. Register it in the CLI command that will use it
5. Create a new Cobra subcommand in `internal/cli/`

## Configuration

Hunter supports layered configuration with the following priority (highest to lowest):

1. **CLI flags** — e.g. `--concurrency 50`
2. **Environment variables** — prefixed with `HUNTER_`, e.g. `HUNTER_CONCURRENCY=50`
3. **Config file** — `~/.hunter.yaml`

The config package (`internal/config/`) uses [Viper](https://github.com/spf13/viper) to load and merge these sources. Supported config options:

| Option | YAML Key | Env Var | CLI Flag |
|--------|----------|---------|----------|
| Default target | `default_target` | `HUNTER_DEFAULT_TARGET` | `--target` |
| Output format | `output_format` | `HUNTER_OUTPUT_FORMAT` | `--output` |
| Concurrency | `concurrency` | `HUNTER_CONCURRENCY` | `--concurrency` |
| Timeout | `timeout` | `HUNTER_TIMEOUT` | `--timeout` |
| Wordlist path | `wordlist_path` | `HUNTER_WORDLIST_PATH` | — |
| Scan profiles | `scan_profiles` | — | — |

Example `~/.hunter.yaml`:

```yaml
default_target: "https://example.com"
output_format: json
concurrency: 20
timeout: 10s
wordlist_path: /usr/share/wordlists/dirb/common.txt
scan_profiles:
  - name: quick
    scanners: [port, headers]
  - name: full
    scanners: [port, headers, ssl, dirs, vuln]
```

## Web Application

Hunter includes a web interface for running scans from a browser. The web layer lives under `internal/web/` and reuses the existing scanner engine.

### Job Manager (`internal/web/jobs/`)

The job manager handles async scan lifecycle with an in-memory store:

- **Job** — represents a scan job with target, scanner list, status, results, and progress tracking
- **JobStatus** — `pending` → `running` → `completed` / `failed`
- **Manager** — thread-safe (sync.RWMutex) manager for creating, starting, tracking, and deleting jobs
  - `Create()` — initialises a pending job with a unique ID
  - `Start()` — launches scanners sequentially in a background goroutine, updating progress after each
  - `Get()` / `List()` / `Delete()` — standard CRUD operations
  - List returns jobs sorted by creation time (newest first)

The manager delegates scanner execution to the existing `scanner.Runner`, so all scanner modules work without modification.

### Templates (`internal/web/templates/`)

Server-rendered HTML using Go `html/template` with embedded template files:

- **Base layout** (`base.html`) — common HTML skeleton with nav, footer, and `{{block "content"}}` placeholder
- **Per-page templates** — `index.html` (scan form), `scans.html` (scan history), `scan_detail.html` (results), `not_found.html`
- **RenderPage()** — renders a named page template by cloning the base and executing the page-specific content block
- **Template functions** — `severityColor`, `severityClass`, `truncateID`, `formatDuration`, `formatTime`, `countSeverity`, `totalFindings`, `progressPct`

### Page Handlers (`internal/web/pages/`)

HTTP handlers that serve HTML pages, sitting between the templates and the job manager:

- **PageHandlers** struct — holds `jobs.Manager` and `scanner.Registry`
- **Index** — renders the scan form page with available scanners from the registry
- **ScanList** — lists all scan jobs with status and finding counts
- **ScanDetail** — shows full details for a single scan, including progress (if running) and results (if completed); returns 404 for unknown IDs

### REST API (`internal/web/api/`)

JSON handlers for programmatic scan management:

- **Handlers** struct — holds `jobs.Manager` and `scanner.Registry`
- `POST /api/v1/scans` — validates target, resolves scanner names, creates and starts a job
- `GET /api/v1/scans` — returns scan summaries (metadata + finding count, no full results)
- `GET /api/v1/scans/{id}` — returns full job with results
- `GET /api/v1/scans/{id}/report` — renders HTML report via `output.HTMLFormatter`
- `DELETE /api/v1/scans/{id}` — removes a job

### Server + Routes (`internal/web/`)

The HTTP server uses chi router with standard middleware (Logger, Recoverer, RequestID, Timeout). Static assets are embedded via `//go:embed static/*` for single-binary deployment. The `NewServer` constructor creates the job manager, wires up API handlers, page handlers, and mounts all routes.

```
GET  /                    → pages.Index (scan form)
GET  /scans               → pages.ScanList (scan history)
GET  /scans/{id}          → pages.ScanDetail (results)
GET  /health              → healthcheck JSON
POST /api/v1/scans        → api.CreateScan
GET  /api/v1/scans        → api.ListScans
GET  /api/v1/scans/{id}   → api.GetScan
GET  /api/v1/scans/{id}/report → api.GetScanReport
DELETE /api/v1/scans/{id} → api.DeleteScan
GET  /static/*            → embedded file server
```

## Domain Types

Shared types live in `pkg/types/`:

- `Target` — what to scan (host, ports, URL)
- `Finding` — a single discovered issue with severity, description, and metadata
- `ScanResult` — aggregates findings from a scanner run
- `Severity` — CRITICAL, HIGH, MEDIUM, LOW, INFO
