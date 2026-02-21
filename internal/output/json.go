package output

import (
	"encoding/json"
	"io"

	"github.com/buemura/hunter/pkg/types"
)

// JSONFormatter renders results as indented JSON.
type JSONFormatter struct{}

func (f *JSONFormatter) Format(w io.Writer, results []types.ScanResult) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(results)
}
