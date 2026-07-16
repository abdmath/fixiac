package cli

import (
	"fmt"
	"os"
	"sort"

	"github.com/abdma/fixiac/internal/output"
	"github.com/spf13/cobra"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage fixiac configuration",
	Long: `View and modify fixiac configuration values.
Configuration is stored in .fixiac.yaml in your home directory or project root.

Example:
  fixiac config set llm.provider openai
  fixiac config get llm.provider
  fixiac config list`,
}

var configSetCmd = &cobra.Command{
	Use:   "set <key> <value>",
	Short: "Set a configuration value",
	Args:  cobra.ExactArgs(2),
	RunE:  runConfigSet,
}

var configGetCmd = &cobra.Command{
	Use:   "get <key>",
	Short: "Get a configuration value",
	Args:  cobra.ExactArgs(1),
	RunE:  runConfigGet,
}

var configListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all configuration values",
	RunE:  runConfigList,
}

func init() {
	configCmd.AddCommand(configSetCmd)
	configCmd.AddCommand(configGetCmd)
	configCmd.AddCommand(configListCmd)
}

// runConfigSet sets a configuration key-value pair and persists it.
func runConfigSet(cmd *cobra.Command, args []string) error {
	key := args[0]
	value := args[1]

	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	cfg.Set(key, value)

	termOut := output.NewTerminalOutput(os.Stdout, !quiet)
	termOut.PrintSuccess(fmt.Sprintf("Set %s = %s", key, value))
	return nil
}

// runConfigGet retrieves and prints a single configuration value.
func runConfigGet(cmd *cobra.Command, args []string) error {
	key := args[0]

	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	value := cfg.Get(key)
	if value == "" {
		termOut := output.NewTerminalOutput(os.Stdout, !quiet)
		termOut.PrintWarning(fmt.Sprintf("Key %q is not set", key))
		return nil
	}

	fmt.Println(value)
	return nil
}

// runConfigList prints all configuration values sorted by key.
func runConfigList(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	all := cfg.GetAll()
	if len(all) == 0 {
		termOut := output.NewTerminalOutput(os.Stdout, !quiet)
		termOut.PrintInfo("No configuration values set")
		return nil
	}

	// Sort keys for deterministic output.
	keys := make([]string, 0, len(all))
	for k := range all {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		fmt.Printf("%s = %s\n", k, all[k])
	}

	return nil
}
