// Package cli provides the command-line interface for the fixiac tool.
// It uses Cobra for command management and defines the root command along
// with all subcommands for scanning, fixing, suppressing, explaining,
// configuring, and version reporting.
package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	cfgFile    string
	verbose    bool
	quiet      bool
	outputFmt  string
	versionStr string
	commitStr  string
	dateStr    string
)

// SetVersionInfo sets the build-time version information injected via ldflags.
// It should be called from main before Execute.
func SetVersionInfo(version, commit, date string) {
	versionStr = version
	commitStr = commit
	dateStr = date
}

// Execute runs the root command and returns any resulting error.
// This is the main entry point for the CLI, called from main().
func Execute() error {
	return rootCmd.Execute()
}

var rootCmd = &cobra.Command{
	Use:   "fixiac",
	Short: "AI-native Terraform security remediation",
	Long: `fixiac scans your Terraform codebase for security misconfigurations,
understands your code patterns, and generates context-aware fixes
that look like your team wrote them.

Usage:
  fixiac scan [directory]     Scan and fix Terraform files
  fixiac fix [file]           Fix a specific finding
  fixiac explain [rule_id]    Explain a security rule
  fixiac suppress [rule_id]   Suppress a finding
  fixiac config               Manage configuration`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.fixiac.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "enable verbose output")
	rootCmd.PersistentFlags().BoolVarP(&quiet, "quiet", "q", false, "suppress non-essential output")
	rootCmd.PersistentFlags().StringVarP(&outputFmt, "output", "o", "terminal", "output format (terminal, json, sarif, markdown, patch)")

	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(fixCmd)
	rootCmd.AddCommand(suppressCmd)
	rootCmd.AddCommand(explainCmd)
	rootCmd.AddCommand(configCmd)
	rootCmd.AddCommand(versionCmd)

	rootCmd.SetOut(os.Stdout)
	rootCmd.SetErr(os.Stderr)

	// Disable the default completion command.
	rootCmd.CompletionOptions.DisableDefaultCmd = true

	// Set a custom usage template for a cleaner help output.
	rootCmd.SetUsageTemplate(fmt.Sprintf(`Usage:{{if .Runnable}}
  {{.UseLine}}{{end}}{{if .HasAvailableSubCommands}}
  {{.CommandPath}} [command]{{end}}{{if gt (len .Aliases) 0}}

Aliases:
  {{.NameAndAliases}}{{end}}{{if .HasAvailableSubCommands}}

Available Commands:{{range .Commands}}{{if (or .IsAvailableCommand (eq .Name "help"))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}

Flags:
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasAvailableInheritedFlags}}

Global Flags:
{{.InheritedFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasHelpSubCommands}}

Additional help topics:{{range .Commands}}{{if .IsAdditionalHelpTopicCommand}}
  {{rpad .CommandPath .CommandPathPadding}} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableSubCommands}}

Use "{{.CommandPath}} [command] --help" for more information about a command.{{end}}

Version: %s
`, versionStr))
}
