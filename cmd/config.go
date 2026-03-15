package cmd

import (
	"fmt"

	"github.com/chavakula/calvigil/internal/config"
	"github.com/spf13/cobra"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage scanner configuration",
	Long: `Manage configuration values like API keys.

Configuration is stored in ~/.calvigil.json.
Environment variables (OPENAI_API_KEY, NVD_API_KEY, GITHUB_TOKEN) take precedence.`,
}

var configSetCmd = &cobra.Command{
	Use:   "set <key> <value>",
	Short: "Set a configuration value",
	Long: `Set a configuration value. Available keys:
  openai-key     OpenAI API key for AI-powered code analysis
  openai-model   OpenAI model to use (default: gpt-4)
  nvd-key        NVD API key for vulnerability lookups
  github-token   GitHub token for advisory database access`,
	Example: `  calvigil config set openai-key sk-...
  calvigil config set openai-model gpt-4-turbo
  calvigil config set nvd-key xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := config.Set(args[0], args[1]); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Configuration updated: %s\n", args[0])
		return nil
	},
}

var configGetCmd = &cobra.Command{
	Use:     "get <key>",
	Short:   "Get a configuration value",
	Example: `  calvigil config get openai-model`,
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		val, err := config.Get(args[0])
		if err != nil {
			return err
		}
		fmt.Fprintln(cmd.OutOrStdout(), val)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(configCmd)
	configCmd.AddCommand(configSetCmd)
	configCmd.AddCommand(configGetCmd)
}
