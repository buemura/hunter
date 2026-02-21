package cli

import (
	"github.com/buemura/hunter/internal/scanner"
	"github.com/buemura/hunter/internal/scanner/api"
	"github.com/buemura/hunter/internal/scanner/dirs"
	"github.com/buemura/hunter/internal/scanner/headers"
	"github.com/buemura/hunter/internal/scanner/port"
	"github.com/buemura/hunter/internal/scanner/ssl"
	"github.com/buemura/hunter/internal/scanner/vuln"
	"github.com/buemura/hunter/internal/tui"
	"github.com/spf13/cobra"
)

var interactiveCmd = &cobra.Command{
	Use:   "interactive",
	Short: "Launch interactive TUI mode",
	Long:  "Start an interactive terminal UI for selecting and running security scans.",
	RunE:  runInteractive,
}

func init() {
	rootCmd.AddCommand(interactiveCmd)
}

func runInteractive(cmd *cobra.Command, args []string) error {
	reg := scanner.NewRegistry()

	// Register all available scanners.
	reg.Register(port.New())
	reg.Register(headers.New())
	reg.Register(ssl.New())
	reg.Register(vuln.New())
	reg.Register(dirs.New())
	reg.Register(api.New())
	reg.Register(api.NewAuthScanner())
	reg.Register(api.NewCORSScanner())
	reg.Register(api.NewRateLimitScanner())

	return tui.Run(reg)
}
