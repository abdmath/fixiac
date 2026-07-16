package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/abdma/fixiac/internal/compliance"
	codebaseCtx "github.com/abdma/fixiac/internal/context"
	"github.com/abdma/fixiac/internal/llm"
	"github.com/abdma/fixiac/internal/output"
	"github.com/abdma/fixiac/internal/remediation"
	"github.com/abdma/fixiac/internal/scanner"
	"github.com/spf13/cobra"
)

var (
	fixRule     string
	fixApply    bool
	fixValidate bool
)

var fixCmd = &cobra.Command{
	Use:   "fix [file]",
	Short: "Fix a specific finding in a file",
	Long: `Generate an AI-powered fix for a specific security rule violation
in a Terraform file. This is useful when you know exactly which
file and rule you want to address.

Example:
  fixiac fix main.tf --rule CKV_AWS_18
  fixiac fix modules/s3/bucket.tf --rule CKV_AWS_19 --apply`,
	Args: cobra.ExactArgs(1),
	RunE: runFix,
}

func init() {
	fixCmd.Flags().StringVar(&fixRule, "rule", "", "rule ID to fix (required)")
	fixCmd.Flags().BoolVar(&fixApply, "apply", false, "apply the fix directly to the file")
	fixCmd.Flags().BoolVar(&fixValidate, "validate", true, "validate the generated fix with terraform validate")
	_ = fixCmd.MarkFlagRequired("rule")
}

// runFix generates a targeted fix for a specific file and rule combination.
func runFix(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Minute)
	defer cancel()

	// Load configuration.
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// Resolve the target file.
	targetFile := args[0]
	targetFile, err = filepath.Abs(targetFile)
	if err != nil {
		return fmt.Errorf("resolving file path: %w", err)
	}
	if info, statErr := os.Stat(targetFile); statErr != nil || info.IsDir() {
		return fmt.Errorf("%q is not a valid file", targetFile)
	}

	targetDir := filepath.Dir(targetFile)
	termOut := output.NewTerminalOutput(os.Stdout, !quiet)
	termOut.PrintBanner(versionStr)
	termOut.PrintInfo(fmt.Sprintf("Fixing rule %s in %s", fixRule, filepath.Base(targetFile)))

	// Create a scanner to find the specific issue.
	scannerName := cfg.Get("scanner")
	if scannerName == "" {
		scannerName = "checkov"
	}
	scanners, err := createScanners(scannerName, targetDir)
	if err != nil {
		return fmt.Errorf("creating scanner: %w", err)
	}

	// Scan the target directory.
	termOut.PrintStep("Scanning for findings...")
	multiScanner := scanner.NewMultiScanner(scanners...)
	findings, err := multiScanner.Scan(ctx, targetDir)
	if err != nil {
		return fmt.Errorf("scanning: %w", err)
	}

	// Filter to the specific file and rule.
	var matched []scanner.Finding
	for _, f := range findings {
		fileAbs, _ := filepath.Abs(f.GetFilePath())
		if fileAbs == targetFile && f.RuleID == fixRule {
			matched = append(matched, f)
		}
	}

	if len(matched) == 0 {
		termOut.PrintWarning(fmt.Sprintf("No finding for rule %s in %s", fixRule, filepath.Base(targetFile)))
		termOut.PrintInfo("The file may already be compliant, or the rule may not apply to resources in this file.")
		return nil
	}

	finding := matched[0]
	termOut.PrintFindings(matched)

	// Analyze codebase context.
	termOut.PrintStep("Analyzing codebase context...")
	analyzer := codebaseCtx.NewAnalyzer()
	codeCtx, err := analyzer.Analyze(ctx, targetDir)
	if err != nil {
		return fmt.Errorf("analyzing context: %w", err)
	}

	// Initialize LLM client.
	provider := cfg.Get("llm.provider")
	if provider == "" {
		provider = "openai"
	}
	model := cfg.Get("llm.model")
	if model == "" {
		model = "gpt-4o"
	}
	apiKey := cfg.Get("llm.api_key")
	if apiKey == "" {
		apiKey = os.Getenv("FIXIAC_API_KEY")
	}
	if apiKey == "" {
		apiKey = os.Getenv("OPENAI_API_KEY")
	}
	if apiKey == "" {
		return fmt.Errorf("no LLM API key found; set llm.api_key in config or FIXIAC_API_KEY env var")
	}
	endpoint := cfg.Get("llm.endpoint")

	llmClient, err := llm.NewClient(provider, model, apiKey, endpoint)
	if err != nil {
		return fmt.Errorf("creating LLM client: %w", err)
	}

	// Generate fix.
	termOut.PrintStep("Generating fix...")
	maxRetries := 3
	generator := remediation.NewGenerator(llmClient, maxRetries)
	prompt := llm.BuildFixPrompt(finding, codeCtx)

	fix, err := generator.Generate(ctx, finding, prompt)
	if err != nil {
		return fmt.Errorf("generating fix for %s: %w", fixRule, err)
	}

	// Enrich with compliance controls.
	mapper := compliance.NewMapper()
	mapping := mapper.MapFinding(finding.RuleID)
	fix.ComplianceControls = mapping

	// Validate if requested.
	if fixValidate {
		termOut.PrintStep("Validating fix...")
		tfPath := cfg.Get("terraform.path")
		if tfPath == "" {
			tfPath = "terraform"
		}
		validator := remediation.NewValidator(tfPath)
		valid, valErr := validator.Validate(ctx, targetDir, fix)
		if valErr != nil {
			termOut.PrintWarning(fmt.Sprintf("Validation error: %v", valErr))
		}
		fix.Validated = valid
		if valid {
			termOut.PrintSuccess("Fix validated successfully")
		} else {
			termOut.PrintWarning("Fix did not pass validation")
		}
	}

	// Display the fix.
	termOut.PrintFix(fix)

	// Apply if requested.
	if fixApply {
		termOut.PrintStep("Applying fix...")
		applier := remediation.NewApplier()
		if applyErr := applier.Apply(ctx, targetDir, []*remediation.Fix{fix}); applyErr != nil {
			return fmt.Errorf("applying fix: %w", applyErr)
		}
		termOut.PrintSuccess(fmt.Sprintf("Fix applied to %s", filepath.Base(targetFile)))
	}

	return nil
}
