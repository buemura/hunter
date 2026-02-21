package ssl

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/buemura/hunter/internal/scanner"
	"github.com/buemura/hunter/pkg/types"
)

// Scanner performs SSL/TLS configuration checks against a target.
type Scanner struct{}

func New() *Scanner {
	return &Scanner{}
}

func (s *Scanner) Name() string        { return "ssl" }
func (s *Scanner) Description() string { return "SSL/TLS configuration checks" }

func (s *Scanner) Run(ctx context.Context, target types.Target, opts scanner.Options) (*types.ScanResult, error) {
	result := &types.ScanResult{
		ScannerName: s.Name(),
		Target:      target,
		StartedAt:   time.Now(),
	}

	port := resolvePort(target)
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	addr := net.JoinHostPort(target.Host, strconv.Itoa(port))

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		result.Error = fmt.Sprintf("TLS connection failed: %v", err)
		result.CompletedAt = time.Now()
		return result, nil
	}
	defer conn.Close()

	state := conn.ConnectionState()

	checkTLSVersion(state, result)
	checkCipherSuite(state, result)

	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		checkCertExpiration(cert, result)
		checkCertHostname(cert, target.Host, result)
		checkSelfSigned(cert, state.PeerCertificates, result)
	}

	if len(result.Findings) == 0 {
		result.Findings = append(result.Findings, types.Finding{
			Title:       "SSL/TLS configuration looks good",
			Description: "No issues found with the SSL/TLS configuration.",
			Severity:    types.SeverityInfo,
		})
	}

	result.CompletedAt = time.Now()
	return result, nil
}

func resolvePort(target types.Target) int {
	if len(target.Ports) > 0 {
		return target.Ports[0]
	}
	return 443
}

func checkTLSVersion(state tls.ConnectionState, result *types.ScanResult) {
	version := state.Version
	versionName := tlsVersionName(version)

	if version <= tls.VersionTLS11 {
		result.Findings = append(result.Findings, types.Finding{
			Title:       fmt.Sprintf("Deprecated TLS version: %s", versionName),
			Description: fmt.Sprintf("The server negotiated %s, which is deprecated and insecure.", versionName),
			Severity:    types.SeverityHigh,
			Evidence:    fmt.Sprintf("Negotiated protocol version: %s", versionName),
			Remediation: "Disable TLS 1.0 and TLS 1.1. Configure the server to support TLS 1.2 or higher.",
			Metadata:    map[string]string{"tls_version": versionName},
		})
	} else {
		result.Findings = append(result.Findings, types.Finding{
			Title:       fmt.Sprintf("TLS version: %s", versionName),
			Description: fmt.Sprintf("The server negotiated %s.", versionName),
			Severity:    types.SeverityInfo,
			Metadata:    map[string]string{"tls_version": versionName},
		})
	}
}

func checkCipherSuite(state tls.ConnectionState, result *types.ScanResult) {
	cipherID := state.CipherSuite
	cipherName := tls.CipherSuiteName(cipherID)

	if isWeakCipher(cipherID) {
		result.Findings = append(result.Findings, types.Finding{
			Title:       fmt.Sprintf("Weak cipher suite: %s", cipherName),
			Description: fmt.Sprintf("The server negotiated cipher suite %s, which is considered weak.", cipherName),
			Severity:    types.SeverityMedium,
			Evidence:    fmt.Sprintf("Negotiated cipher suite: %s (0x%04x)", cipherName, cipherID),
			Remediation: "Configure the server to use strong cipher suites such as AES-GCM or ChaCha20-Poly1305.",
			Metadata:    map[string]string{"cipher_suite": cipherName},
		})
	}
}

func checkCertExpiration(cert *x509.Certificate, result *types.ScanResult) {
	now := time.Now()

	if now.After(cert.NotAfter) {
		result.Findings = append(result.Findings, types.Finding{
			Title:       "Certificate expired",
			Description: fmt.Sprintf("The certificate expired on %s.", cert.NotAfter.Format(time.RFC3339)),
			Severity:    types.SeverityHigh,
			Evidence:    fmt.Sprintf("NotAfter: %s", cert.NotAfter.Format(time.RFC3339)),
			Remediation: "Renew the SSL/TLS certificate immediately.",
			Metadata: map[string]string{
				"not_after": cert.NotAfter.Format(time.RFC3339),
				"subject":   cert.Subject.CommonName,
			},
		})
		return
	}

	daysUntilExpiry := int(time.Until(cert.NotAfter).Hours() / 24)
	if daysUntilExpiry <= 30 {
		result.Findings = append(result.Findings, types.Finding{
			Title:       fmt.Sprintf("Certificate expires in %d days", daysUntilExpiry),
			Description: fmt.Sprintf("The certificate will expire on %s (%d days remaining).", cert.NotAfter.Format(time.RFC3339), daysUntilExpiry),
			Severity:    types.SeverityMedium,
			Evidence:    fmt.Sprintf("NotAfter: %s", cert.NotAfter.Format(time.RFC3339)),
			Remediation: "Renew the SSL/TLS certificate before it expires.",
			Metadata: map[string]string{
				"not_after":        cert.NotAfter.Format(time.RFC3339),
				"days_until_expiry": strconv.Itoa(daysUntilExpiry),
				"subject":          cert.Subject.CommonName,
			},
		})
	}
}

func checkCertHostname(cert *x509.Certificate, hostname string, result *types.ScanResult) {
	err := cert.VerifyHostname(hostname)
	if err != nil {
		result.Findings = append(result.Findings, types.Finding{
			Title:       "Certificate hostname mismatch",
			Description: fmt.Sprintf("The certificate does not match hostname %q: %v", hostname, err),
			Severity:    types.SeverityHigh,
			Evidence:    fmt.Sprintf("Expected: %s, Certificate CN: %s, SANs: %v", hostname, cert.Subject.CommonName, cert.DNSNames),
			Remediation: "Obtain a certificate that covers the target hostname.",
			Metadata: map[string]string{
				"hostname":    hostname,
				"common_name": cert.Subject.CommonName,
				"san_names":   strings.Join(cert.DNSNames, ", "),
			},
		})
	}
}

func checkSelfSigned(cert *x509.Certificate, chain []*x509.Certificate, result *types.ScanResult) {
	// A self-signed certificate has the same subject and issuer,
	// and the chain has only one certificate.
	if cert.Issuer.CommonName == cert.Subject.CommonName && len(chain) == 1 {
		result.Findings = append(result.Findings, types.Finding{
			Title:       "Self-signed certificate",
			Description: fmt.Sprintf("The certificate for %s is self-signed.", cert.Subject.CommonName),
			Severity:    types.SeverityMedium,
			Evidence:    fmt.Sprintf("Issuer: %s, Subject: %s", cert.Issuer.CommonName, cert.Subject.CommonName),
			Remediation: "Use a certificate issued by a trusted Certificate Authority (CA).",
			Metadata: map[string]string{
				"issuer":  cert.Issuer.CommonName,
				"subject": cert.Subject.CommonName,
			},
		})
	}
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown (0x%04x)", version)
	}
}

// isWeakCipher returns true for cipher suites considered weak.
func isWeakCipher(id uint16) bool {
	for _, suite := range tls.InsecureCipherSuites() {
		if suite.ID == id {
			return true
		}
	}
	return false
}
