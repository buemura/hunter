package cli

import "github.com/spf13/cobra"

var apiCmd = &cobra.Command{
	Use:   "api",
	Short: "API endpoint discovery and testing",
	Long:  "Discover and test API endpoints on a target, including REST, GraphQL, and OpenAPI.",
}

func init() {
	rootCmd.AddCommand(apiCmd)
}
