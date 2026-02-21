package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/buemura/hunter/internal/output"
	"github.com/buemura/hunter/internal/scanner"
	"github.com/buemura/hunter/internal/scanner/vuln"
	"github.com/buemura/hunter/pkg/types"
	"github.com/spf13/cobra"
)

var vulnChecksFlag string

var scanVulnCmd = &cobra.Command{
	Use:   "vuln",
	Short: "Basic vulnerability detection",
	Long:  "Performs basic vulnerability detection checks including reflected XSS, SQL injection, and open redirect tests against the target.",
	RunE:  runVulnScan,
}

func init() {
	scanVulnCmd.Flags().StringVar(&vulnChecksFlag, "checks", "", "Comma-separated checks to run (default: all). Options: xss,sqli,redirect")
	scanCmd.AddCommand(scanVulnCmd)
}

func runVulnScan(cmd *cobra.Command, args []string) error {
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
	reg.Register(vuln.New())

	runner := scanner.NewRunner(reg)
	opts := scanner.Options{
		Concurrency: concurrencyFlag,
		Timeout:     timeoutFlag,
		Verbose:     verboseFlag,
	}

	if vulnChecksFlag != "" {
		opts.ExtraArgs = map[string]interface{}{
			"checks": vulnChecksFlag,
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeoutFlag*100)
	defer cancel()

	result, err := runner.RunOne(ctx, "vuln", target, opts)
	if err != nil {
		return err
	}

	return formatter.Format(os.Stdout, []types.ScanResult{*result})
}
