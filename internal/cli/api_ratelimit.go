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

var requestsFlag int

var apiRateLimitCmd = &cobra.Command{
	Use:   "ratelimit",
	Short: "Check for API rate limiting",
	Long:  "Sends rapid requests to a target endpoint to check whether rate limiting is enforced.",
	RunE:  runAPIRateLimit,
}

func init() {
	apiRateLimitCmd.Flags().IntVar(&requestsFlag, "requests", 50, "number of requests to send")
	apiCmd.AddCommand(apiRateLimitCmd)
}

func runAPIRateLimit(cmd *cobra.Command, args []string) error {
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
	reg.Register(api.NewRateLimitScanner())

	runner := scanner.NewRunner(reg)
	opts := scanner.Options{
		Concurrency: concurrencyFlag,
		Timeout:     timeoutFlag,
		Verbose:     verboseFlag,
		ExtraArgs:   map[string]interface{}{"requests": requestsFlag},
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeoutFlag*100)
	defer cancel()

	result, err := runner.RunOne(ctx, "api-ratelimit", target, opts)
	if err != nil {
		return err
	}

	return formatter.Format(os.Stdout, []types.ScanResult{*result})
}
