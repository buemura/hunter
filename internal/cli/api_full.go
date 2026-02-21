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

// apiScannerNames lists all API scanner names in execution order.
var apiScannerNames = []string{"api-discover", "api-auth", "api-cors", "api-ratelimit"}

var apiFullCmd = &cobra.Command{
	Use:   "full",
	Short: "Run all API scanners",
	Long:  "Runs every API scanner (discover, auth, cors, ratelimit) against the target concurrently.",
	RunE:  runAPIFull,
}

func init() {
	apiCmd.AddCommand(apiFullCmd)
}

func runAPIFull(cmd *cobra.Command, args []string) error {
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

	results := runner.RunAll(ctx, apiScannerNames, target, opts)
	return formatter.Format(os.Stdout, results)
}
