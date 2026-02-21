package vuln

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/buemura/hunter/internal/scanner"
	"github.com/buemura/hunter/pkg/types"
)

// xssPayloads are common reflected XSS test vectors.
var xssPayloads = []string{
	`<script>alert(1)</script>`,
	`"><img src=x onerror=alert(1)>`,
	`javascript:alert(1)`,
}

// CheckReflectedXSS tests for reflected cross-site scripting by injecting
// payloads into each existing URL query parameter and checking if the payload
// appears unescaped in the response body. If the target URL has no query
// parameters the check is skipped gracefully.
func CheckReflectedXSS(ctx context.Context, target types.Target, opts scanner.Options) []types.Finding {
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
		for _, payload := range xssPayloads {
			if ctx.Err() != nil {
				return findings
			}

			testURL := replaceQueryParam(target.URL, param, payload)
			body, err := httpGet(ctx, testURL, opts.Timeout)
			if err != nil {
				continue
			}

			if strings.Contains(body, payload) {
				findings = append(findings, types.Finding{
					Title:       "Potential reflected XSS",
					Description: fmt.Sprintf("The server reflects user input in parameter %q without proper encoding, which may allow cross-site scripting attacks.", param),
					Severity:    types.SeverityHigh,
					Evidence:    fmt.Sprintf("Payload %q reflected in response from %s", payload, testURL),
					Remediation: "Sanitize and encode all user-supplied input before including it in HTML responses.",
					Metadata: map[string]string{
						"check":   "xss",
						"param":   param,
						"payload": payload,
						"url":     testURL,
					},
				})
			}
		}
	}

	return findings
}

// replaceQueryParam returns a copy of rawURL with the given query parameter
// value replaced.
func replaceQueryParam(rawURL, key, value string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	q := u.Query()
	q.Set(key, value)
	u.RawQuery = q.Encode()
	return u.String()
}
