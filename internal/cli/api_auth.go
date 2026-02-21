package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/buemura/hunter/internal/output"
	"github.com/buemura/hunter/internal/scanner"
	"github.com/buemura/hunter/internal/scanner/api"
	"github.com/buemura/hunter/pkg/types"
	"github.com/spf13/cobra"
)

var apiAuthCmd = &cobra.Command{
	Use:   "auth",
	Short: "Test API authentication",
	Long:  "Tests API endpoints for missing authentication, default credentials, and authentication bypass vulnerabilities.",
	RunE:  runAPIAuthScan,
}

func init() {
	apiCmd.AddCommand(apiAuthCmd)
}

func runAPIAuthScan(cmd *cobra.Command, args []string) error {
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
	reg.Register(api.NewAuthScanner())

	runner := scanner.NewRunner(reg)
	opts := scanner.Options{
		Concurrency: concurrencyFlag,
		Timeout:     timeoutFlag,
		Verbose:     verboseFlag,
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeoutFlag*20)
	defer cancel()

	result, err := runner.RunOne(ctx, "api-auth", target, opts)
	if err != nil {
		return err
	}

	return formatter.Format(os.Stdout, []types.ScanResult{*result})
}
