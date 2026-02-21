package cli

import (
	"fmt"
	"time"

	"github.com/buemura/hunter/internal/config"
	"github.com/spf13/cobra"
)

var version = "dev"

var (
	targetFlag      string
	outputFlag      string
	verboseFlag     bool
	concurrencyFlag int
	timeoutFlag     time.Duration
)

// appConfig holds the loaded configuration, available after PersistentPreRunE.
var appConfig *config.Config

var rootCmd = &cobra.Command{
	Use:   "hunter",
	Short: "Hunter — CLI pentesting tool for developers",
	Long: `Hunter is a security scanning tool that helps developers find
vulnerabilities, misconfigurations, and security issues in their
web applications and APIs.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load()
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}

		config.ApplyFlags(cfg, cmd)

		// Sync config values back to flag variables so all existing commands
		// pick up config-file and env-var defaults transparently.
		targetFlag = cfg.DefaultTarget
		outputFlag = cfg.OutputFormat
		concurrencyFlag = cfg.Concurrency
		timeoutFlag = cfg.Timeout

		appConfig = cfg
		return nil
	},
}

// Execute runs the root command.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&targetFlag, "target", "t", "", "target host, IP, or URL")
	rootCmd.PersistentFlags().StringVarP(&outputFlag, "output", "o", "table", "output format: table, json, markdown, html")
	rootCmd.PersistentFlags().BoolVarP(&verboseFlag, "verbose", "v", false, "verbose output")
	rootCmd.PersistentFlags().IntVarP(&concurrencyFlag, "concurrency", "c", 10, "max concurrent operations")
	rootCmd.PersistentFlags().DurationVar(&timeoutFlag, "timeout", 5*time.Second, "connection timeout")

	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(versionCmd)
}
