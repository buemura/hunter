package vuln

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/buemura/hunter/internal/scanner"
	"github.com/buemura/hunter/pkg/types"
)

// sqliPayloads are error-based SQL injection test vectors.
var sqliPayloads = []string{
	`'`,
	`' OR '1'='1`,
	`1; DROP TABLE`,
	`' UNION SELECT NULL--`,
}

// sqlErrorPatterns are common database error signatures that indicate
// a SQL injection vulnerability when they appear in a response.
var sqlErrorPatterns = []string{
	"sql syntax",
	"mysql_fetch",
	"ora-",
	"postgresql",
	"sqlite",
	"odbc",
	"unclosed quotation",
}

// CheckSQLi tests for SQL injection by injecting error-based payloads into each
// existing URL query parameter and looking for database error signatures in the
// response. If the target URL has no query parameters the check is skipped.
func CheckSQLi(ctx context.Context, target types.Target, opts scanner.Options) []types.Finding {
	u, err := url.Parse(target.URL)
	if err != nil {
		return nil
	}

	params := u.Query()
	if len(params) == 0 {
		return nil
	}

	var findings []types.Finding

	for param := range params {
		for _, payload := range sqliPayloads {
			if ctx.Err() != nil {
				return findings
			}

			testURL := replaceQueryParam(target.URL, param, payload)
			body, err := httpGet(ctx, testURL, opts.Timeout)
			if err != nil {
				continue
			}

			lower := strings.ToLower(body)
			for _, pattern := range sqlErrorPatterns {
				if strings.Contains(lower, pattern) {
					findings = append(findings, types.Finding{
						Title:       "Potential SQL injection",
						Description: fmt.Sprintf("The server returned a database error message when parameter %q was set to a SQL injection test payload, suggesting improper input handling.", param),
						Severity:    types.SeverityCritical,
						Evidence:    fmt.Sprintf("Error pattern %q found in response from %s", pattern, testURL),
						Remediation: "Use parameterized queries or prepared statements. Never concatenate user input into SQL queries.",
						Metadata: map[string]string{
							"check":         "sqli",
							"param":         param,
							"payload":       payload,
							"url":           testURL,
							"error_pattern": pattern,
						},
					})
					break
				}
			}
		}
	}

	return findings
}
