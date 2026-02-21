package cli

import (
	"fmt"

	"github.com/buemura/hunter/internal/scanner"
	"github.com/buemura/hunter/internal/scanner/api"
	"github.com/buemura/hunter/internal/scanner/dirs"
	"github.com/buemura/hunter/internal/scanner/headers"
	"github.com/buemura/hunter/internal/scanner/port"
	"github.com/buemura/hunter/internal/scanner/ssl"
	"github.com/buemura/hunter/internal/scanner/vuln"
	"github.com/buemura/hunter/internal/web"
	"github.com/spf13/cobra"
)

var addrFlag string

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the Hunter web server",
	Long:  "Launches the Hunter web interface for running security scans from a browser.",
	RunE:  runServe,
}

func init() {
	serveCmd.Flags().StringVar(&addrFlag, "addr", ":3000", "listen address (host:port)")
	rootCmd.AddCommand(serveCmd)
}

func runServe(cmd *cobra.Command, args []string) error {
	reg := scanner.NewRegistry()

	reg.Register(port.New())
	reg.Register(headers.New())
	reg.Register(ssl.New())
	reg.Register(dirs.New())
	reg.Register(vuln.New())
	reg.Register(api.New())
	reg.Register(api.NewAuthScanner())
	reg.Register(api.NewCORSScanner())
	reg.Register(api.NewRateLimitScanner())

	s := web.NewServer(addrFlag, reg)
	fmt.Fprintf(cmd.OutOrStdout(), "Hunter web server listening on %s\n", addrFlag)
	return s.Start()
}
