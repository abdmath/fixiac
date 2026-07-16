package cli

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/abdma/fixiac/internal/output"
	"github.com/abdma/fixiac/internal/suppress"
	"github.com/spf13/cobra"
)

var (
	suppressResource string
	suppressReason   string
	suppressExpires  string
)

var suppressCmd = &cobra.Command{
	Use:   "suppress [rule_id]",
	Short: "Suppress a finding with a reason",
	Long: `Suppress a security finding so it is excluded from future scans.
Every suppression requires a resource identifier and a reason.

Suppressions are stored in .fixiac-suppress.yaml in the target directory.

Example:
  fixiac suppress CKV_AWS_18 --resource aws_s3_bucket.logs --reason "Handled by external logging"
  fixiac suppress CKV_AWS_19 --resource aws_s3_bucket.data --reason "SSE-C used" --expires 90d`,
	Args: cobra.ExactArgs(1),
	RunE: runSuppress,
}

var suppressListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all active suppressions",
	RunE:  runSuppressList,
}

var suppressRemoveCmd = &cobra.Command{
	Use:   "remove [rule_id]",
	Short: "Remove a suppression",
	Args:  cobra.ExactArgs(1),
	RunE:  runSuppressRemove,
}

func init() {
	suppressCmd.Flags().StringVar(&suppressResource, "resource", "", "resource address to suppress (required)")
	suppressCmd.Flags().StringVar(&suppressReason, "reason", "", "reason for suppression (required)")
	suppressCmd.Flags().StringVar(&suppressExpires, "expires", "", "expiry duration (e.g., 90d, 6m) or date (YYYY-MM-DD)")
	_ = suppressCmd.MarkFlagRequired("resource")
	_ = suppressCmd.MarkFlagRequired("reason")

	suppressCmd.AddCommand(suppressListCmd)
	suppressCmd.AddCommand(suppressRemoveCmd)

	suppressRemoveCmd.Flags().StringVar(&suppressResource, "resource", "", "resource address to remove suppression for (required)")
	_ = suppressRemoveCmd.MarkFlagRequired("resource")
}

// runSuppress adds a new suppression entry for the given rule and resource.
func runSuppress(cmd *cobra.Command, args []string) error {
	ruleID := args[0]
	termOut := output.NewTerminalOutput(os.Stdout, !quiet)

	store := suppress.NewStore(".")
	if err := store.Load(); err != nil {
		if verbose {
			termOut.PrintWarning(fmt.Sprintf("Could not load existing suppressions: %v", err))
		}
	}

	// Parse expiry.
	var expiresAt *time.Time
	if suppressExpires != "" {
		parsed, err := parseExpiry(suppressExpires)
		if err != nil {
			return fmt.Errorf("invalid --expires value %q: %w", suppressExpires, err)
		}
		expiresAt = &parsed
	}

	entry := suppress.Suppression{
		RuleID:    ruleID,
		Resource:  suppressResource,
		Reason:    suppressReason,
		CreatedAt: time.Now(),
		CreatedBy: currentUser(),
		ExpiresAt: expiresAt,
	}

	if err := store.Add(entry); err != nil {
		return fmt.Errorf("adding suppression: %w", err)
	}

	if err := store.Save(); err != nil {
		return fmt.Errorf("saving suppressions: %w", err)
	}

	termOut.PrintSuccess(fmt.Sprintf("Suppressed %s for resource %s", ruleID, suppressResource))
	if expiresAt != nil {
		termOut.PrintInfo(fmt.Sprintf("Expires: %s", expiresAt.Format(time.DateOnly)))
	}

	return nil
}

// runSuppressList displays all active suppressions.
func runSuppressList(cmd *cobra.Command, args []string) error {
	termOut := output.NewTerminalOutput(os.Stdout, !quiet)

	store := suppress.NewStore(".")
	if err := store.Load(); err != nil {
		return fmt.Errorf("loading suppressions: %w", err)
	}

	entries := store.List()
	if len(entries) == 0 {
		termOut.PrintInfo("No active suppressions")
		return nil
	}

	termOut.PrintInfo(fmt.Sprintf("%d active suppression(s):", len(entries)))
	fmt.Println()
	for _, e := range entries {
		expires := "never"
		if e.ExpiresAt != nil {
			expires = e.ExpiresAt.Format(time.DateOnly)
		}
		fmt.Printf("  Rule:       %s\n", e.RuleID)
		fmt.Printf("  Resource:   %s\n", e.Resource)
		fmt.Printf("  Reason:     %s\n", e.Reason)
		fmt.Printf("  Suppressed: %s by %s\n", e.CreatedAt.Format(time.DateOnly), e.CreatedBy)
		fmt.Printf("  Expires:    %s\n", expires)
		fmt.Println()
	}

	return nil
}

// runSuppressRemove removes a suppression entry.
func runSuppressRemove(cmd *cobra.Command, args []string) error {
	ruleID := args[0]
	termOut := output.NewTerminalOutput(os.Stdout, !quiet)

	store := suppress.NewStore(".")
	if err := store.Load(); err != nil {
		return fmt.Errorf("loading suppressions: %w", err)
	}

	if err := store.Remove(ruleID, suppressResource); err != nil {
		termOut.PrintWarning(fmt.Sprintf("No suppression found for %s on %s: %v", ruleID, suppressResource, err))
		return nil
	}

	termOut.PrintSuccess(fmt.Sprintf("Removed suppression for %s on %s", ruleID, suppressResource))
	return nil
}

// parseExpiry parses a duration string (e.g., "90d", "6m") or a date string
// (YYYY-MM-DD) into a time.Time.
func parseExpiry(s string) (time.Time, error) {
	// Try date format first.
	if t, err := time.Parse(time.DateOnly, s); err == nil {
		return t, nil
	}

	// Try duration format: Nd (days) or Nm (months).
	s = strings.TrimSpace(s)
	if len(s) < 2 {
		return time.Time{}, fmt.Errorf("expected format like '90d', '6m', or 'YYYY-MM-DD'")
	}

	unit := s[len(s)-1]
	numStr := s[:len(s)-1]
	var days int
	if _, err := fmt.Sscanf(numStr, "%d", &days); err != nil {
		return time.Time{}, fmt.Errorf("expected numeric value, got %q", numStr)
	}

	now := time.Now()
	switch unit {
	case 'd', 'D':
		return now.AddDate(0, 0, days), nil
	case 'm', 'M':
		return now.AddDate(0, days, 0), nil
	case 'y', 'Y':
		return now.AddDate(days, 0, 0), nil
	default:
		return time.Time{}, fmt.Errorf("unknown time unit %q; use d (days), m (months), or y (years)", string(unit))
	}
}

// currentUser returns the current system username for audit purposes.
func currentUser() string {
	if user := os.Getenv("USER"); user != "" {
		return user
	}
	if user := os.Getenv("USERNAME"); user != "" {
		return user
	}
	return "unknown"
}
