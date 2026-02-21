package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/buemura/hunter/internal/output"
	"github.com/buemura/hunter/internal/scanner"
	"github.com/buemura/hunter/internal/scanner/api"
	"github.com/buemura/hunter/internal/scanner/dirs"
	"github.com/buemura/hunter/internal/scanner/headers"
	"github.com/buemura/hunter/internal/scanner/port"
	"github.com/buemura/hunter/internal/scanner/ssl"
	"github.com/buemura/hunter/internal/scanner/vuln"
	"github.com/buemura/hunter/pkg/types"
	"github.com/spf13/cobra"
)

// allScannerNames lists every scanner name for the combined profile.
var allScannerNames = append(append([]string{}, webScannerNames...), apiScannerNames...)

var allCmd = &cobra.Command{
	Use:   "all",
	Short: "Run all scanners",
	Long:  "Runs every web and API scanner against the target concurrently.",
	RunE:  runAll,
}

func init() {
	rootCmd.AddCommand(allCmd)
}

func runAll(cmd *cobra.Command, args []string) error {
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
	// Web scanners
	reg.Register(port.New())
	reg.Register(headers.New())
	reg.Register(ssl.New())
	reg.Register(dirs.New())
	reg.Register(vuln.New())
	// API scanners
	reg.Register(api.New())
	reg.Register(api.NewAuthScanner())
	reg.Register(api.NewCORSScanner())
	reg.Register(api.NewRateLimitScanner())

	runner := scanner.NewRunner(reg)
	opts := scanner.Options{
		Concurrency: concurrencyFlag,
		Timeout:     timeoutFlag,
		Verbose:     verboseFlag,
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeoutFlag*100)
	defer cancel()

	results := runner.RunAll(ctx, allScannerNames, target, opts)
	return formatter.Format(os.Stdout, results)
}
