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

var apiCORSCmd = &cobra.Command{
	Use:   "cors",
	Short: "Detect CORS misconfigurations",
	Long:  "Tests a target for CORS misconfigurations including origin reflection, null origin, and credentials with permissive origins.",
	RunE:  runAPICORS,
}

func init() {
	apiCmd.AddCommand(apiCORSCmd)
}

func runAPICORS(cmd *cobra.Command, args []string) error {
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
	reg.Register(api.NewCORSScanner())

	runner := scanner.NewRunner(reg)
	opts := scanner.Options{
		Concurrency: concurrencyFlag,
		Timeout:     timeoutFlag,
		Verbose:     verboseFlag,
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeoutFlag*100)
	defer cancel()

	result, err := runner.RunOne(ctx, "api-cors", target, opts)
	if err != nil {
		return err
	}

	return formatter.Format(os.Stdout, []types.ScanResult{*result})
}
