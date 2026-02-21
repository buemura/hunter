# Usage Guide

## Port Scanning

### Scan common ports

```bash
hunter scan port -t example.com
```

This scans the ~25 most common ports (SSH, HTTP, HTTPS, MySQL, PostgreSQL, etc.).

### Scan specific ports

```bash
hunter scan port -t example.com --ports 80,443,8080
```

### Scan a port range

```bash
hunter scan port -t example.com --ports 1-1024
```

### Scan with JSON output

```bash
hunter scan port -t example.com -o json
```

### Adjust concurrency and timeout

```bash
hunter scan port -t example.com --ports 1-65535 -c 100 --timeout 2s
```

## Vulnerability Scanning

### Run all vulnerability checks

```bash
hunter scan vuln -t http://example.com
```

Runs basic vulnerability detection including reflected XSS, SQL injection, and open redirect checks against the target.

### With JSON output

```bash
hunter scan vuln -t http://example.com -o json
```

### Adjust timeout

```bash
hunter scan vuln -t http://example.com --timeout 10s
```

## API Authentication Testing

### Test a target URL for auth issues

```bash
hunter api auth -t http://example.com/api/v1
```

Tests for missing authentication, authentication bypass techniques, and default credentials on login endpoints.

### Test with JSON output

```bash
hunter api auth -t http://example.com/api/v1 -o json
```

### Adjust timeout

```bash
hunter api auth -t http://example.com --timeout 10s
```

The scanner performs three checks:

1. **Missing Authentication** — sends unauthenticated requests to endpoints and flags those returning 200 OK (severity: HIGH)
2. **Authentication Bypass** — tests bypass payloads (`Bearer null`, empty tokens, etc.) against protected endpoints (severity: HIGH)
3. **Default Credentials** — discovers login endpoints and tests common credentials like `admin/admin` (severity: CRITICAL)

## Configuration

Hunter loads settings from three sources (highest priority first):

1. CLI flags (`--target`, `--output`, `--concurrency`, `--timeout`)
2. Environment variables (`HUNTER_DEFAULT_TARGET`, `HUNTER_OUTPUT_FORMAT`, `HUNTER_CONCURRENCY`, `HUNTER_TIMEOUT`)
3. Config file (`~/.hunter.yaml`)

### Example config file

Create `~/.hunter.yaml`:

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

### Using environment variables

```bash
export HUNTER_CONCURRENCY=50
export HUNTER_OUTPUT_FORMAT=json
hunter scan port -t example.com
```

## Target Formats

Hunter accepts targets in several formats:

| Format | Example | Behavior |
|--------|---------|----------|
| Hostname | `example.com` | Scans with HTTPS scheme |
| IP address | `192.168.1.1` | Scans with HTTPS scheme |
| Host:port | `example.com:8080` | Uses the specified port |
| Full URL | `http://example.com/api` | Extracts host and scheme |

## Web Interface

### Start the web server

```bash
hunter serve
```

By default the server listens on `:8080`. Use `--addr` to change:

```bash
hunter serve --addr :3000
```

### Web UI

Open `http://localhost:8080` in your browser. The web interface provides:

- **New Scan** (`/`) — form to configure target, select scanners, set concurrency and timeout
- **Scan History** (`/scans`) — table of all past scans with status badges and finding counts
- **Scan Detail** (`/scans/{id}`) — real-time progress, results grouped by scanner, severity summary, and expandable evidence/remediation details

### REST API

The web server exposes a JSON API for programmatic access:

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/scans` | Create and start a new scan |
| `GET` | `/api/v1/scans` | List all scan jobs |
| `GET` | `/api/v1/scans/{id}` | Get scan details and results |
| `GET` | `/api/v1/scans/{id}/report` | Get HTML report |
| `DELETE` | `/api/v1/scans/{id}` | Delete a scan job |

#### Create a scan

```bash
curl -X POST http://localhost:8080/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com", "scanners": ["headers", "ssl"], "concurrency": 10, "timeout": "5s"}'
```

#### Poll scan status

```bash
curl http://localhost:8080/api/v1/scans/<id>
```

## Output Formats

- `table` (default) — colored terminal table sorted by severity
- `json` — machine-readable JSON for piping to other tools
