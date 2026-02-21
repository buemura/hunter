package templates

import (
	"embed"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/buemura/hunter/pkg/types"
)

//go:embed *.html
var templateFS embed.FS

// pages holds a per-page template set, each cloned from the base layout.
var pages map[string]*template.Template

func init() {
	funcMap := template.FuncMap{
		"severityColor":  severityColor,
		"severityClass":  severityClass,
		"truncateID":     truncateID,
		"formatDuration": formatDuration,
		"formatTime":     formatTime,
		"countSeverity":  countSeverity,
		"totalFindings":  totalFindings,
		"progressPct":    progressPct,
		"lower":          strings.ToLower,
	}

	// Parse the base layout first.
	base := template.Must(template.New("").Funcs(funcMap).ParseFS(templateFS, "base.html"))

	// Each page template clones the base and adds its own content block.
	pageNames := []string{"index.html", "scans.html", "scan_detail.html", "not_found.html"}
	pages = make(map[string]*template.Template, len(pageNames))
	for _, name := range pageNames {
		clone := template.Must(base.Clone())
		pages[name] = template.Must(clone.ParseFS(templateFS, name))
	}
}

// RenderPage executes the named page template into the response writer.
func RenderPage(w http.ResponseWriter, name string, data interface{}) error {
	tmpl, ok := pages[name]
	if !ok {
		return fmt.Errorf("render template %q: template not found", name)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(w, "base", data); err != nil {
		return fmt.Errorf("render template %q: %w", name, err)
	}
	return nil
}

// severityColor returns a CSS color for the given severity level.
func severityColor(s types.Severity) string {
	switch s {
	case types.SeverityCritical:
		return "#dc2626"
	case types.SeverityHigh:
		return "#ea580c"
	case types.SeverityMedium:
		return "#ca8a04"
	case types.SeverityLow:
		return "#0891b2"
	case types.SeverityInfo:
		return "#6b7280"
	default:
		return "#6b7280"
	}
}

// severityClass returns a CSS class name for the given severity level.
func severityClass(s types.Severity) string {
	switch s {
	case types.SeverityCritical:
		return "critical"
	case types.SeverityHigh:
		return "high"
	case types.SeverityMedium:
		return "medium"
	case types.SeverityLow:
		return "low"
	default:
		return "info"
	}
}

// truncateID shortens a UUID for display.
func truncateID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

// formatDuration formats a duration for display.
func formatDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return d.Round(time.Second).String()
}

// formatTime formats a time for display.
func formatTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Format("2006-01-02 15:04:05")
}

// countSeverity counts findings with the given severity across all results.
func countSeverity(results []types.ScanResult, sev string) int {
	n := 0
	for _, r := range results {
		for _, f := range r.Findings {
			if string(f.Severity) == sev {
				n++
			}
		}
	}
	return n
}

// totalFindings returns the total number of findings across all results.
func totalFindings(results []types.ScanResult) int {
	n := 0
	for _, r := range results {
		n += len(r.Findings)
	}
	return n
}

// progressPct calculates a progress percentage from completed and total.
func progressPct(completed, total int) int {
	if total == 0 {
		return 0
	}
	return (completed * 100) / total
}
