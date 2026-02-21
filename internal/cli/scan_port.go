package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/buemura/hunter/internal/output"
	"github.com/buemura/hunter/internal/scanner"
	"github.com/buemura/hunter/internal/scanner/port"
	"github.com/buemura/hunter/pkg/types"
	"github.com/spf13/cobra"
)

var portsFlag string

var scanPortCmd = &cobra.Command{
	Use:   "port",
	Short: "Scan for open TCP ports",
	Long:  "Performs a TCP connect scan to discover open ports on the target.",
	RunE:  runPortScan,
}

func init() {
	scanPortCmd.Flags().StringVar(&portsFlag, "ports", "common", "ports to scan: single, range (1-1024), comma-separated, or 'common'")
	scanCmd.AddCommand(scanPortCmd)
}

func runPortScan(cmd *cobra.Command, args []string) error {
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

	runner := scanner.NewRunner(reg)
	opts := scanner.Options{
		Concurrency: concurrencyFlag,
		Timeout:     timeoutFlag,
		Verbose:     verboseFlag,
		ExtraArgs:   map[string]interface{}{"ports": portsFlag},
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeoutFlag*100)
	defer cancel()

	result, err := runner.RunOne(ctx, "port", target, opts)
	if err != nil {
		return err
	}

	return formatter.Format(os.Stdout, []types.ScanResult{*result})
}
