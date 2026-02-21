package port

import (
	"fmt"
	"strconv"
	"strings"
)

// CommonPorts is a list of frequently used ports to scan by default.
var CommonPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
	993, 995, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888, 27017,
}

// ServiceMap maps common ports to their typical service names.
var ServiceMap = map[int]string{
	21:    "FTP",
	22:    "SSH",
	23:    "Telnet",
	25:    "SMTP",
	53:    "DNS",
	80:    "HTTP",
	110:   "POP3",
	111:   "RPC",
	135:   "MSRPC",
	139:   "NetBIOS",
	143:   "IMAP",
	443:   "HTTPS",
	445:   "SMB",
	993:   "IMAPS",
	995:   "POP3S",
	1723:  "PPTP",
	3306:  "MySQL",
	3389:  "RDP",
	5432:  "PostgreSQL",
	5900:  "VNC",
	6379:  "Redis",
	8080:  "HTTP-Alt",
	8443:  "HTTPS-Alt",
	8888:  "HTTP-Alt",
	27017: "MongoDB",
}

// IdentifyService returns the service name for a port, or "unknown".
func IdentifyService(port int) string {
	if svc, ok := ServiceMap[port]; ok {
		return svc
	}
	return "unknown"
}

// ParsePortRange parses a port specification string into a list of ports.
// Supported formats:
//   - "80"           -> [80]
//   - "80,443,8080"  -> [80, 443, 8080]
//   - "1-1024"       -> [1, 2, ..., 1024]
//   - "common"       -> CommonPorts
//   - ""             -> CommonPorts
func ParsePortRange(spec string) ([]int, error) {
	spec = strings.TrimSpace(spec)

	if spec == "" || spec == "common" {
		return CommonPorts, nil
	}

	// Comma-separated list (may include ranges).
	if strings.Contains(spec, ",") {
		var ports []int
		for _, part := range strings.Split(spec, ",") {
			p, err := parseSingleOrRange(strings.TrimSpace(part))
			if err != nil {
				return nil, err
			}
			ports = append(ports, p...)
		}
		return ports, nil
	}

	return parseSingleOrRange(spec)
}

func parseSingleOrRange(s string) ([]int, error) {
	if strings.Contains(s, "-") {
		parts := strings.SplitN(s, "-", 2)
		start, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil {
			return nil, fmt.Errorf("invalid port range start %q: %w", parts[0], err)
		}
		end, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil {
			return nil, fmt.Errorf("invalid port range end %q: %w", parts[1], err)
		}
		if start > end {
			return nil, fmt.Errorf("invalid port range: start %d > end %d", start, end)
		}
		if start < 1 || end > 65535 {
			return nil, fmt.Errorf("port range out of bounds (1-65535)")
		}

		ports := make([]int, 0, end-start+1)
		for p := start; p <= end; p++ {
			ports = append(ports, p)
		}
		return ports, nil
	}

	port, err := strconv.Atoi(s)
	if err != nil {
		return nil, fmt.Errorf("invalid port %q: %w", s, err)
	}
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("port %d out of range (1-65535)", port)
	}
	return []int{port}, nil
}
