package headers

import (
	"net/http"
	"strings"

	"github.com/buemura/hunter/pkg/types"
)

// HeaderRule defines a single security header check.
type HeaderRule struct {
	Name  string
	Check func(h http.Header, isHTTPS bool) *types.Finding
}

// Rules returns all header security rules.
func Rules() []HeaderRule {
	return []HeaderRule{
		{
			Name: "Strict-Transport-Security",
			Check: func(h http.Header, isHTTPS bool) *types.Finding {
				if !isHTTPS {
					return nil
				}
				if h.Get("Strict-Transport-Security") == "" {
					return &types.Finding{
						Title:       "Missing Strict-Transport-Security header",
						Description: "The HTTP Strict-Transport-Security (HSTS) header is not set. This allows downgrade attacks and cookie hijacking.",
						Severity:    types.SeverityHigh,
						Remediation: "Add the header: Strict-Transport-Security: max-age=31536000; includeSubDomains",
					}
				}
				return nil
			},
		},
		{
			Name: "Content-Security-Policy",
			Check: func(h http.Header, _ bool) *types.Finding {
				if h.Get("Content-Security-Policy") == "" {
					return &types.Finding{
						Title:       "Missing Content-Security-Policy header",
						Description: "The Content-Security-Policy (CSP) header is not set. This increases the risk of XSS and data injection attacks.",
						Severity:    types.SeverityMedium,
						Remediation: "Add a Content-Security-Policy header with a restrictive policy, e.g.: Content-Security-Policy: default-src 'self'",
					}
				}
				return nil
			},
		},
		{
			Name: "X-Content-Type-Options",
			Check: func(h http.Header, _ bool) *types.Finding {
				val := h.Get("X-Content-Type-Options")
				if val == "" {
					return &types.Finding{
						Title:       "Missing X-Content-Type-Options header",
						Description: "The X-Content-Type-Options header is not set. Browsers may MIME-sniff the content type, leading to security issues.",
						Severity:    types.SeverityLow,
						Remediation: "Add the header: X-Content-Type-Options: nosniff",
					}
				}
				if !strings.EqualFold(val, "nosniff") {
					return &types.Finding{
						Title:       "Misconfigured X-Content-Type-Options header",
						Description: "The X-Content-Type-Options header is set but not to 'nosniff'. Current value: " + val,
						Severity:    types.SeverityLow,
						Remediation: "Set the header value to 'nosniff': X-Content-Type-Options: nosniff",
					}
				}
				return nil
			},
		},
		{
			Name: "X-Frame-Options",
			Check: func(h http.Header, _ bool) *types.Finding {
				if h.Get("X-Frame-Options") == "" {
					return &types.Finding{
						Title:       "Missing X-Frame-Options header",
						Description: "The X-Frame-Options header is not set. The page may be vulnerable to clickjacking attacks.",
						Severity:    types.SeverityLow,
						Remediation: "Add the header: X-Frame-Options: DENY or X-Frame-Options: SAMEORIGIN",
					}
				}
				return nil
			},
		},
		{
			Name: "X-XSS-Protection",
			Check: func(h http.Header, _ bool) *types.Finding {
				if h.Get("X-XSS-Protection") == "" {
					return &types.Finding{
						Title:       "Missing X-XSS-Protection header",
						Description: "The X-XSS-Protection header is not set. While deprecated in modern browsers, its absence may indicate incomplete security hardening.",
						Severity:    types.SeverityInfo,
						Remediation: "Consider adding X-XSS-Protection: 0 (to explicitly disable the flawed XSS auditor) and rely on CSP instead.",
					}
				}
				return nil
			},
		},
		{
			Name: "Referrer-Policy",
			Check: func(h http.Header, _ bool) *types.Finding {
				if h.Get("Referrer-Policy") == "" {
					return &types.Finding{
						Title:       "Missing Referrer-Policy header",
						Description: "The Referrer-Policy header is not set. Sensitive information in URLs may be leaked via the Referer header.",
						Severity:    types.SeverityLow,
						Remediation: "Add the header: Referrer-Policy: strict-origin-when-cross-origin",
					}
				}
				return nil
			},
		},
		{
			Name: "Permissions-Policy",
			Check: func(h http.Header, _ bool) *types.Finding {
				if h.Get("Permissions-Policy") == "" {
					return &types.Finding{
						Title:       "Missing Permissions-Policy header",
						Description: "The Permissions-Policy header is not set. Browser features like camera, microphone, and geolocation are not explicitly restricted.",
						Severity:    types.SeverityLow,
						Remediation: "Add the header: Permissions-Policy: camera=(), microphone=(), geolocation=()",
					}
				}
				return nil
			},
		},
	}
}
