package output

import (
	"fmt"
	"io"

	"github.com/buemura/hunter/pkg/types"
)

// Formatter renders scan results to a writer.
type Formatter interface {
	Format(w io.Writer, results []types.ScanResult) error
}

// GetFormatter returns the appropriate formatter for the given format string.
func GetFormatter(format string) (Formatter, error) {
	switch format {
	case "table":
		return &TableFormatter{}, nil
	case "json":
		return &JSONFormatter{}, nil
	case "markdown":
		return &MarkdownFormatter{}, nil
	case "html":
		return &HTMLFormatter{}, nil
	default:
		return nil, fmt.Errorf("unknown output format %q (supported: table, json, markdown, html)", format)
	}
}
