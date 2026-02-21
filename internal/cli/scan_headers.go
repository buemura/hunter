package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/buemura/hunter/internal/output"
	"github.com/buemura/hunter/internal/scanner"
	"github.com/buemura/hunter/internal/scanner/headers"
	"github.com/buemura/hunter/pkg/types"
	"github.com/spf13/cobra"
)

var scanHeadersCmd = &cobra.Command{
	Use:   "headers",
	Short: "Analyze HTTP security headers",
	Long:  "Checks the target for missing or misconfigured HTTP security headers.",
	RunE:  runHeadersScan,
}

func init() {
	scanCmd.AddCommand(scanHeadersCmd)
}

func runHeadersScan(cmd *cobra.Command, args []string) error {
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
	reg.Register(headers.New())

	runner := scanner.NewRunner(reg)
	opts := scanner.Options{
		Concurrency: concurrencyFlag,
		Timeout:     timeoutFlag,
		Verbose:     verboseFlag,
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeoutFlag*10)
	defer cancel()

	result, err := runner.RunOne(ctx, "headers", target, opts)
	if err != nil {
		return err
	}

	return formatter.Format(os.Stdout, []types.ScanResult{*result})
}
