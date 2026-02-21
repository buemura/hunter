package output

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/buemura/hunter/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func sampleResults() []types.ScanResult {
	return []types.ScanResult{
		{
			ScannerName: "port",
			Target:      types.Target{Host: "example.com", Scheme: "https"},
			StartedAt:   time.Now(),
			CompletedAt: time.Now(),
			Findings: []types.Finding{
				{Title: "Open port: 80/HTTP", Severity: types.SeverityInfo, Description: "Port 80 is open"},
				{Title: "Open port: 22/SSH", Severity: types.SeverityMedium, Description: "SSH exposed"},
			},
		},
	}
}

func TestGetFormatter_Table(t *testing.T) {
	f, err := GetFormatter("table")
	require.NoError(t, err)
	assert.IsType(t, &TableFormatter{}, f)
}

func TestGetFormatter_JSON(t *testing.T) {
	f, err := GetFormatter("json")
	require.NoError(t, err)
	assert.IsType(t, &JSONFormatter{}, f)
}

func TestGetFormatter_Unknown(t *testing.T) {
	_, err := GetFormatter("xml")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown")
}

func TestTableFormatter(t *testing.T) {
	var buf bytes.Buffer
	f := &TableFormatter{}
	err := f.Format(&buf, sampleResults())
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "port")
	assert.Contains(t, output, "example.com")
	assert.Contains(t, output, "Open port: 80/HTTP")
	assert.Contains(t, output, "2 findings")
}

func TestTableFormatter_Error(t *testing.T) {
	var buf bytes.Buffer
	f := &TableFormatter{}
	results := []types.ScanResult{
		{ScannerName: "test", Error: "connection refused"},
	}
	err := f.Format(&buf, results)
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "connection refused")
}

func TestTableFormatter_NoFindings(t *testing.T) {
	var buf bytes.Buffer
	f := &TableFormatter{}
	results := []types.ScanResult{
		{ScannerName: "test", Target: types.Target{Host: "example.com"}},
	}
	err := f.Format(&buf, results)
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "No findings")
}

func TestJSONFormatter(t *testing.T) {
	var buf bytes.Buffer
	f := &JSONFormatter{}
	err := f.Format(&buf, sampleResults())
	require.NoError(t, err)

	var decoded []types.ScanResult
	err = json.Unmarshal(buf.Bytes(), &decoded)
	require.NoError(t, err)
	assert.Len(t, decoded, 1)
	assert.Equal(t, "port", decoded[0].ScannerName)
	assert.Len(t, decoded[0].Findings, 2)
}

// --- GetFormatter: Markdown & HTML ---

func TestGetFormatter_Markdown(t *testing.T) {
	f, err := GetFormatter("markdown")
	require.NoError(t, err)
	assert.IsType(t, &MarkdownFormatter{}, f)
}

func TestGetFormatter_HTML(t *testing.T) {
	f, err := GetFormatter("html")
	require.NoError(t, err)
	assert.IsType(t, &HTMLFormatter{}, f)
}

// --- MarkdownFormatter ---

func TestMarkdownFormatter(t *testing.T) {
	var buf bytes.Buffer
	f := &MarkdownFormatter{}
	err := f.Format(&buf, sampleResults())
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "## port")
	assert.Contains(t, output, "example.com")
	assert.Contains(t, output, "| Severity | Title | Description |")
	assert.Contains(t, output, "Open port: 80/HTTP")
	assert.Contains(t, output, "**MEDIUM**")
	assert.Contains(t, output, "**Summary:** 2 findings")
}

func TestMarkdownFormatter_Error(t *testing.T) {
	var buf bytes.Buffer
	f := &MarkdownFormatter{}
	results := []types.ScanResult{
		{ScannerName: "test", Error: "connection refused"},
	}
	err := f.Format(&buf, results)
	require.NoError(t, err)
	output := buf.String()
	assert.Contains(t, output, "Error")
	assert.Contains(t, output, "connection refused")
}

func TestMarkdownFormatter_NoFindings(t *testing.T) {
	var buf bytes.Buffer
	f := &MarkdownFormatter{}
	results := []types.ScanResult{
		{ScannerName: "test", Target: types.Target{Host: "example.com"}},
	}
	err := f.Format(&buf, results)
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "No findings")
}

func TestMarkdownFormatter_EscapesPipes(t *testing.T) {
	var buf bytes.Buffer
	f := &MarkdownFormatter{}
	results := []types.ScanResult{
		{
			ScannerName: "test",
			Target:      types.Target{Host: "example.com"},
			Findings: []types.Finding{
				{Title: "A|B", Severity: types.SeverityInfo, Description: "X|Y"},
			},
		},
	}
	err := f.Format(&buf, results)
	require.NoError(t, err)
	output := buf.String()
	assert.Contains(t, output, `A\|B`)
	assert.Contains(t, output, `X\|Y`)
}

// --- HTMLFormatter ---

func TestHTMLFormatter(t *testing.T) {
	var buf bytes.Buffer
	f := &HTMLFormatter{}
	err := f.Format(&buf, sampleResults())
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "<!DOCTYPE html>")
	assert.Contains(t, output, "Hunter Scan Report")
	assert.Contains(t, output, "example.com")
	assert.Contains(t, output, "Open port: 80/HTTP")
	assert.Contains(t, output, `class="badge medium"`)
	assert.Contains(t, output, `class="badge info"`)
}

func TestHTMLFormatter_Error(t *testing.T) {
	var buf bytes.Buffer
	f := &HTMLFormatter{}
	results := []types.ScanResult{
		{ScannerName: "test", Error: "connection refused"},
	}
	err := f.Format(&buf, results)
	require.NoError(t, err)
	output := buf.String()
	assert.Contains(t, output, "Error")
	assert.Contains(t, output, "connection refused")
}

func TestHTMLFormatter_NoFindings(t *testing.T) {
	var buf bytes.Buffer
	f := &HTMLFormatter{}
	results := []types.ScanResult{
		{ScannerName: "test", Target: types.Target{Host: "example.com"}},
	}
	err := f.Format(&buf, results)
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "No findings")
}

func TestHTMLFormatter_ExpandableDetails(t *testing.T) {
	var buf bytes.Buffer
	f := &HTMLFormatter{}
	results := []types.ScanResult{
		{
			ScannerName: "test",
			Target:      types.Target{Host: "example.com"},
			Findings: []types.Finding{
				{
					Title:       "Vuln",
					Severity:    types.SeverityHigh,
					Description: "A vulnerability",
					Evidence:    "proof",
					Remediation: "fix it",
				},
			},
		},
	}
	err := f.Format(&buf, results)
	require.NoError(t, err)
	output := buf.String()
	assert.Contains(t, output, "<details>")
	assert.Contains(t, output, "proof")
	assert.Contains(t, output, "fix it")
}
