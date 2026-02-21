package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/buemura/hunter/internal/output"
	"github.com/buemura/hunter/internal/scanner"
	"github.com/buemura/hunter/internal/scanner/dirs"
	"github.com/buemura/hunter/internal/scanner/headers"
	"github.com/buemura/hunter/internal/scanner/port"
	"github.com/buemura/hunter/internal/scanner/ssl"
	"github.com/buemura/hunter/internal/scanner/vuln"
	"github.com/buemura/hunter/pkg/types"
	"github.com/spf13/cobra"
)

// webScannerNames lists all web scanner names in execution order.
var webScannerNames = []string{"port", "headers", "ssl", "dirs", "vuln"}

var scanFullCmd = &cobra.Command{
	Use:   "full",
	Short: "Run all web scanners",
	Long:  "Runs every web scanner (port, headers, ssl, dirs, vuln) against the target concurrently.",
	RunE:  runScanFull,
}

func init() {
	scanCmd.AddCommand(scanFullCmd)
}

func runScanFull(cmd *cobra.Command, args []string) error {
	if targetFlag == "" {
		return fmt.Errorf("--target (-t) is required")
	}

	target, err := types.ParseTarget(targetFlag)
	if err != nil {
		return fmt.Errorf("invalid target: %w", err)
	}

	formatter, err := output.GetFormatter(outputFlag)
	if err != nil {
		return err
	}

	reg := scanner.NewRegistry()
	reg.Register(port.New())
	reg.Register(headers.New())
	reg.Register(ssl.New())
	reg.Register(dirs.New())
	reg.Register(vuln.New())

	runner := scanner.NewRunner(reg)
	opts := scanner.Options{
		Concurrency: concurrencyFlag,
		Timeout:     timeoutFlag,
		Verbose:     verboseFlag,
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeoutFlag*100)
	defer cancel()

	results := runner.RunAll(ctx, webScannerNames, target, opts)
	return formatter.Format(os.Stdout, results)
}
