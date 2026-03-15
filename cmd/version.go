package cmd

import (
	"fmt"
	"runtime/debug"

	"github.com/spf13/cobra"
)

var version = "dev"

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version of calvigil",
	Run: func(cmd *cobra.Command, args []string) {
		goVersion := "unknown"
		if info, ok := debug.ReadBuildInfo(); ok {
			goVersion = info.GoVersion
		}
		fmt.Fprintf(cmd.OutOrStdout(), "calvigil %s (built with %s)\n", version, goVersion)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
