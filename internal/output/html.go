package output

import (
	"fmt"
	"html/template"
	"io"
	"sort"

	"github.com/buemura/hunter/pkg/types"
)

// HTMLFormatter renders results as a self-contained HTML report with
// styled severity badges and expandable finding details.
type HTMLFormatter struct{}

func (f *HTMLFormatter) Format(w io.Writer, results []types.ScanResult) error {
	// Sort findings within each result before rendering.
	for i := range results {
		sort.Slice(results[i].Findings, func(a, b int) bool {
			return types.SeverityRank(results[i].Findings[a].Severity) < types.SeverityRank(results[i].Findings[b].Severity)
		})
	}

	return htmlTpl.Execute(w, templateData{Results: results})
}

type templateData struct {
	Results []types.ScanResult
}

// severityClass maps a Severity to a CSS class name.
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

var funcMap = template.FuncMap{
	"severityClass": severityClass,
	"findingsCount": func(results []types.ScanResult) int {
		n := 0
		for _, r := range results {
			n += len(r.Findings)
		}
		return n
	},
	"countSeverity": func(results []types.ScanResult, sev types.Severity) int {
		n := 0
		for _, r := range results {
			for _, f := range r.Findings {
				if f.Severity == sev {
					n++
				}
			}
		}
		return n
	},
	"severityCritical": func() types.Severity { return types.SeverityCritical },
	"severityHigh":     func() types.Severity { return types.SeverityHigh },
	"severityMedium":   func() types.Severity { return types.SeverityMedium },
	"severityLow":      func() types.Severity { return types.SeverityLow },
	"severityInfo":     func() types.Severity { return types.SeverityInfo },
}

var htmlTpl = template.Must(template.New("report").Funcs(funcMap).Parse(fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Hunter Scan Report</title>
<style>%s</style>
</head>
<body>
<div class="container">
  <h1>Hunter Scan Report</h1>

  <div class="summary-bar">
    <span class="badge critical">{{countSeverity .Results severityCritical}} Critical</span>
    <span class="badge high">{{countSeverity .Results severityHigh}} High</span>
    <span class="badge medium">{{countSeverity .Results severityMedium}} Medium</span>
    <span class="badge low">{{countSeverity .Results severityLow}} Low</span>
    <span class="badge info">{{countSeverity .Results severityInfo}} Info</span>
    <span class="total">{{findingsCount .Results}} total findings</span>
  </div>

  {{range .Results}}
  <section class="scanner-section">
    {{if .Error}}
      <h2>{{.ScannerName}} &mdash; Error</h2>
      <div class="error-box">{{.Error}}</div>
    {{else}}
      <h2>{{.ScannerName}} &mdash; {{.Target.Host}}</h2>

      {{if not .Findings}}
        <p class="no-findings">No findings.</p>
      {{else}}
        <table>
          <thead>
            <tr><th>Severity</th><th>Title</th><th>Description</th></tr>
          </thead>
          <tbody>
            {{range .Findings}}
            <tr>
              <td><span class="badge {{severityClass .Severity}}">{{.Severity}}</span></td>
              <td>{{.Title}}</td>
              <td>
                {{.Description}}
                {{if or .Evidence .Remediation}}
                <details>
                  <summary>Details</summary>
                  {{if .Evidence}}<p><strong>Evidence:</strong> {{.Evidence}}</p>{{end}}
                  {{if .Remediation}}<p><strong>Remediation:</strong> {{.Remediation}}</p>{{end}}
                </details>
                {{end}}
              </td>
            </tr>
            {{end}}
          </tbody>
        </table>
      {{end}}
    {{end}}
  </section>
  {{end}}
</div>
</body>
</html>`, cssStyles)))

const cssStyles = `
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
     line-height:1.6;color:#1a1a2e;background:#f5f5fa;padding:2rem}
.container{max-width:960px;margin:0 auto}
h1{margin-bottom:1rem;font-size:1.8rem}
h2{margin:1.5rem 0 .75rem;font-size:1.3rem;border-bottom:2px solid #e0e0e0;padding-bottom:.3rem}
.summary-bar{display:flex;gap:.5rem;flex-wrap:wrap;align-items:center;margin-bottom:1.5rem}
.total{margin-left:.5rem;font-weight:600}
.badge{display:inline-block;padding:2px 10px;border-radius:12px;font-size:.8rem;font-weight:700;color:#fff;text-transform:uppercase}
.badge.critical{background:#d32f2f}
.badge.high{background:#e53935}
.badge.medium{background:#f9a825;color:#333}
.badge.low{background:#0288d1}
.badge.info{background:#757575}
table{width:100%;border-collapse:collapse;margin-bottom:1rem}
th,td{text-align:left;padding:.5rem .75rem;border-bottom:1px solid #e0e0e0}
th{background:#eaeaea;font-weight:600}
tr:hover{background:#f0f0ff}
details{margin-top:.4rem}
summary{cursor:pointer;color:#1565c0;font-size:.85rem}
.error-box{background:#ffebee;color:#c62828;padding:.75rem 1rem;border-radius:6px;margin-bottom:1rem}
.no-findings{color:#666;font-style:italic}
.scanner-section{margin-bottom:2rem}
`
