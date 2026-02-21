package output

import (
	"fmt"
	"io"
	"sort"

	"github.com/buemura/hunter/pkg/types"
	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
)

// TableFormatter renders results as a colored terminal table.
type TableFormatter struct{}

func (f *TableFormatter) Format(w io.Writer, results []types.ScanResult) error {
	for _, result := range results {
		if result.Error != "" {
			fmt.Fprintf(w, "\n[%s] Error: %s\n", result.ScannerName, result.Error)
			continue
		}

		fmt.Fprintf(w, "\n[%s] %s — %d findings\n", result.ScannerName, result.Target.Host, len(result.Findings))

		if len(result.Findings) == 0 {
			fmt.Fprintln(w, "  No findings.")
			continue
		}

		// Sort by severity (most severe first).
		sort.Slice(result.Findings, func(i, j int) bool {
			return types.SeverityRank(result.Findings[i].Severity) < types.SeverityRank(result.Findings[j].Severity)
		})

		table := tablewriter.NewWriter(w)
		table.SetHeader([]string{"Severity", "Title", "Description"})
		table.SetAutoWrapText(false)
		table.SetBorder(false)
		table.SetColumnSeparator("│")

		counts := map[types.Severity]int{}

		for _, finding := range result.Findings {
			counts[finding.Severity]++
			sev := colorSeverity(finding.Severity)
			table.Append([]string{sev, finding.Title, finding.Description})
		}

		table.Render()

		fmt.Fprintf(w, "  Summary: %s\n", formatSummary(counts))
	}

	return nil
}

func colorSeverity(s types.Severity) string {
	switch s {
	case types.SeverityCritical:
		return color.RedString("CRITICAL")
	case types.SeverityHigh:
		return color.RedString("HIGH")
	case types.SeverityMedium:
		return color.YellowString("MEDIUM")
	case types.SeverityLow:
		return color.CyanString("LOW")
	case types.SeverityInfo:
		return color.WhiteString("INFO")
	default:
		return string(s)
	}
}

func formatSummary(counts map[types.Severity]int) string {
	total := 0
	for _, c := range counts {
		total += c
	}
	return fmt.Sprintf("%d findings (%d critical, %d high, %d medium, %d low, %d info)",
		total,
		counts[types.SeverityCritical],
		counts[types.SeverityHigh],
		counts[types.SeverityMedium],
		counts[types.SeverityLow],
		counts[types.SeverityInfo],
	)
}
