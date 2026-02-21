package cli

import "github.com/spf13/cobra"

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Web application security scanning",
	Long:  "Scan a target for open ports, security headers, SSL issues, and more.",
}
