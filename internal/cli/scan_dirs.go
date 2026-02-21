package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/buemura/hunter/internal/output"
	"github.com/buemura/hunter/internal/scanner"
	"github.com/buemura/hunter/internal/scanner/dirs"
	"github.com/buemura/hunter/pkg/types"
	"github.com/spf13/cobra"
)

var wordlistFlag string

var scanDirsCmd = &cobra.Command{
	Use:   "dirs",
	Short: "Enumerate directories and paths",
	Long:  "Scans the target for common directories, files, and paths using a wordlist.",
	RunE:  runDirsScan,
}

func init() {
	scanDirsCmd.Flags().StringVar(&wordlistFlag, "wordlist", "", "path to custom wordlist file (default: embedded wordlist)")
	scanCmd.AddCommand(scanDirsCmd)
}

func runDirsScan(cmd *cobra.Command, args []string) error {
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
	reg.Register(dirs.New())

	runner := scanner.NewRunner(reg)
	opts := scanner.Options{
		Concurrency: concurrencyFlag,
		Timeout:     timeoutFlag,
		Verbose:     verboseFlag,
		ExtraArgs:   map[string]interface{}{"wordlist": wordlistFlag},
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeoutFlag*100)
	defer cancel()

	result, err := runner.RunOne(ctx, "dirs", target, opts)
	if err != nil {
		return err
	}

	return formatter.Format(os.Stdout, []types.ScanResult{*result})
}
