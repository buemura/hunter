package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/buemura/hunter/internal/output"
	"github.com/buemura/hunter/internal/scanner"
	"github.com/buemura/hunter/internal/scanner/ssl"
	"github.com/buemura/hunter/pkg/types"
	"github.com/spf13/cobra"
)

var scanSSLCmd = &cobra.Command{
	Use:   "ssl",
	Short: "Check SSL/TLS configuration",
	Long:  "Performs SSL/TLS configuration checks including certificate validity, protocol version, and cipher strength.",
	RunE:  runSSLScan,
}

func init() {
	scanCmd.AddCommand(scanSSLCmd)
}

func runSSLScan(cmd *cobra.Command, args []string) error {
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
	reg.Register(ssl.New())

	runner := scanner.NewRunner(reg)
	opts := scanner.Options{
		Concurrency: concurrencyFlag,
		Timeout:     timeoutFlag,
		Verbose:     verboseFlag,
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeoutFlag*100)
	defer cancel()

	result, err := runner.RunOne(ctx, "ssl", target, opts)
	if err != nil {
		return err
	}

	return formatter.Format(os.Stdout, []types.ScanResult{*result})
}
