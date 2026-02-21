package output

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/buemura/hunter/pkg/types"
)

// MarkdownFormatter renders results as Markdown tables suitable for
// pasting into docs, issues, or pull-request descriptions.
type MarkdownFormatter struct{}

func (f *MarkdownFormatter) Format(w io.Writer, results []types.ScanResult) error {
	for i, result := range results {
		if i > 0 {
			fmt.Fprintln(w)
		}

		if result.Error != "" {
			fmt.Fprintf(w, "## %s — Error\n\n> %s\n", result.ScannerName, result.Error)
			continue
		}

		fmt.Fprintf(w, "## %s — %s\n\n", result.ScannerName, result.Target.Host)

		if len(result.Findings) == 0 {
			fmt.Fprintln(w, "_No findings._")
			continue
		}

		sort.Slice(result.Findings, func(i, j int) bool {
			return types.SeverityRank(result.Findings[i].Severity) < types.SeverityRank(result.Findings[j].Severity)
		})

		fmt.Fprintln(w, "| Severity | Title | Description |")
		fmt.Fprintln(w, "|----------|-------|-------------|")

		counts := map[types.Severity]int{}
		for _, finding := range result.Findings {
			counts[finding.Severity]++
			sev := severityBadge(finding.Severity)
			title := escapeMarkdown(finding.Title)
			desc := escapeMarkdown(finding.Description)
			fmt.Fprintf(w, "| %s | %s | %s |\n", sev, title, desc)
		}

		fmt.Fprintf(w, "\n%s\n", markdownSummary(counts))
	}

	return nil
}

// severityBadge returns a bold, uppercased severity label for Markdown.
func severityBadge(s types.Severity) string {
	return fmt.Sprintf("**%s**", string(s))
}

// escapeMarkdown escapes pipe characters that would break Markdown tables.
func escapeMarkdown(s string) string {
	return strings.ReplaceAll(s, "|", "\\|")
}

func markdownSummary(counts map[types.Severity]int) string {
	total := 0
	for _, c := range counts {
		total += c
	}
	return fmt.Sprintf("**Summary:** %d findings (%d critical, %d high, %d medium, %d low, %d info)",
		total,
		counts[types.SeverityCritical],
		counts[types.SeverityHigh],
		counts[types.SeverityMedium],
		counts[types.SeverityLow],
		counts[types.SeverityInfo],
	)
}
