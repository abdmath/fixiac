package cli

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Long:  "Display the version, build commit, build date, Go version, and OS/architecture.",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("fixiac %s\n", versionStr)
		fmt.Printf("  commit:  %s\n", commitStr)
		fmt.Printf("  built:   %s\n", dateStr)
		fmt.Printf("  go:      %s\n", runtime.Version())
		fmt.Printf("  os/arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	},
}
