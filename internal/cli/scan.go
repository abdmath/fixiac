package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/abdma/fixiac/internal/compliance"
	codebaseCtx "github.com/abdma/fixiac/internal/context"
	"github.com/abdma/fixiac/internal/config"
	"github.com/abdma/fixiac/internal/github"
	"github.com/abdma/fixiac/internal/interactive"
	"github.com/abdma/fixiac/internal/llm"
	"github.com/abdma/fixiac/internal/output"
	"github.com/abdma/fixiac/internal/remediation"
	"github.com/abdma/fixiac/internal/scanner"
	"github.com/abdma/fixiac/internal/suppress"
	"github.com/spf13/cobra"
)

var (
	scanApply       bool
	scanPR          bool
	scanRepo        string
	scanInteractive bool
	scanFramework   string
	scanSeverity    string
	scanScanner     string
	scanFix         bool
	scanValidate    bool
	scanMaxRetries  int
	scanInputFile   string
)

var scanCmd = &cobra.Command{
	Use:   "scan [directory]",
	Short: "Scan and fix Terraform files",
	Long: `Scan your Terraform codebase for security misconfigurations,
analyze codebase context, and generate AI-powered fixes.

The scan pipeline includes:
  1. Multi-engine scanning (Checkov / Trivy) or file input
  2. Context-aware code analysis
  3. LLM-powered fix generation
  4. Terraform validation of generated fixes
  5. Interactive review (optional)
  6. Automatic application and PR creation (optional)`,
	Args: cobra.MaximumNArgs(1),
	RunE: runScan,
}

func init() {
	scanCmd.Flags().BoolVar(&scanApply, "apply", false, "apply fixes to files and create a branch")
	scanCmd.Flags().BoolVar(&scanPR, "pr", false, "create a GitHub pull request with fixes")
	scanCmd.Flags().StringVar(&scanRepo, "repo", "origin", "git remote name for PR creation")
	scanCmd.Flags().BoolVarP(&scanInteractive, "interactive", "i", false, "interactively review each fix before applying")
	scanCmd.Flags().StringVar(&scanFramework, "framework", "", "filter by compliance framework (soc2, hipaa, iso27001, cis_aws)")
	scanCmd.Flags().StringVar(&scanSeverity, "severity", "LOW", "minimum severity to report (LOW, MEDIUM, HIGH, CRITICAL)")
	scanCmd.Flags().StringVar(&scanScanner, "scanner", "", "scanner to use (checkov, trivy, or both; default from config)")
	scanCmd.Flags().BoolVar(&scanFix, "fix", true, "generate AI-powered fixes for findings")
	scanCmd.Flags().BoolVar(&scanValidate, "validate", true, "validate generated fixes with terraform validate")
	scanCmd.Flags().IntVar(&scanMaxRetries, "max-retries", 3, "maximum retries for fix generation")
	scanCmd.Flags().StringVar(&scanInputFile, "input", "", "read checkov or trivy JSON output from file instead of running scanner CLI")
}

// runScan is the main orchestration function for the scan command.
// It drives the entire fixiac pipeline from scanning through fix application.
func runScan(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Minute)
	defer cancel()

	// ── Step 1: Load configuration ──────────────────────────────────────
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// ── Step 2: Determine target directory ──────────────────────────────
	targetDir := "."
	if len(args) > 0 {
		targetDir = args[0]
	}
	targetDir, err = filepath.Abs(targetDir)
	if err != nil {
		return fmt.Errorf("resolving target directory: %w", err)
	}
	if info, statErr := os.Stat(targetDir); statErr != nil || !info.IsDir() {
		return fmt.Errorf("target %q is not a valid directory", targetDir)
	}

	// ── Step 3: Initialize terminal output and print banner ─────────────
	isTerminalFmt := strings.ToLower(outputFmt) == "terminal" || outputFmt == ""
	var termWriter *os.File = os.Stdout
	if quiet || !isTerminalFmt {
		termWriter = os.Stderr
	}
	termOut := output.NewTerminalOutput(termWriter, !quiet)
	if isTerminalFmt && !quiet {
		termOut.PrintBanner(versionStr)
	}
	termOut.PrintScanStart(targetDir)

	// ── Step 4: Load suppression store ──────────────────────────────────
	suppressStore := suppress.NewStore(targetDir)
	if loadErr := suppressStore.Load(); loadErr != nil {
		if verbose {
			termOut.PrintWarning(fmt.Sprintf("Could not load suppressions: %v", loadErr))
		}
	}

	// ── Step 5: Acquire findings (Scanner or Input File) ────────────────
	var findings []scanner.Finding
	if scanInputFile != "" {
		termOut.PrintStep(fmt.Sprintf("Reading scanner output from file: %s", scanInputFile))
		data, err := os.ReadFile(scanInputFile)
		if err != nil {
			return fmt.Errorf("reading input file %q: %w", scanInputFile, err)
		}
		findings, err = scanner.ParseCheckovJSON(data)
		if err != nil || len(findings) == 0 {
			if trivyFindings, tErr := scanner.ParseTrivyJSON(data); tErr == nil && len(trivyFindings) > 0 {
				findings = trivyFindings
			}
		}
		termOut.PrintInfo(fmt.Sprintf("Loaded %d raw findings from file", len(findings)))
	} else {
		scannerName := scanScanner
		if scannerName == "" {
			scannerName = cfg.Get("scanner")
			if scannerName == "" {
				scannerName = "checkov"
			}
		}

		scanners, err := createScanners(scannerName, targetDir)
		if err != nil {
			return fmt.Errorf("creating scanners: %w", err)
		}

		termOut.PrintStep("Running security scan...")
		multiScanner := scanner.NewMultiScanner(scanners...)
		findings, err = multiScanner.Scan(ctx, targetDir)
		if err != nil {
			return fmt.Errorf("scanning: %w", err)
		}
		termOut.PrintInfo(fmt.Sprintf("Found %d raw findings", len(findings)))
	}

	// ── Step 7: Filter suppressed findings ──────────────────────────────
	findings = filterSuppressed(findings, suppressStore)

	// ── Step 8: Filter by severity and framework ────────────────────────
	findings = filterBySeverity(findings, scanSeverity)
	if scanFramework != "" {
		findings = filterByFramework(findings, scanFramework)
	}
	termOut.PrintInfo(fmt.Sprintf("%d findings after filtering", len(findings)))

	if len(findings) == 0 {
		termOut.PrintSuccess("No findings to remediate. Your code looks great!")
		return nil
	}

	// ── Step 9: Print findings summary ──────────────────────────────────
	if isTerminalFmt {
		termOut.PrintFindings(findings)
	}

	// ── Step 10: Generate fixes ─────────────────────────────────────────
	var fixes []*remediation.Fix
	if scanFix {
		fixes, err = generateFixes(ctx, cfg, targetDir, findings, termOut)
		if err != nil {
			return fmt.Errorf("generating fixes: %w", err)
		}
		termOut.PrintInfo(fmt.Sprintf("Generated %d fixes", len(fixes)))
	}

	// ── Step 11: Interactive review ─────────────────────────────────────
	if scanInteractive && len(fixes) > 0 {
		session := interactive.NewReviewSession(findings, fixes)
		reviewed, runErr := session.Run()
		if runErr != nil {
			return fmt.Errorf("interactive review: %w", runErr)
		}
		fixes = interactive.GetAcceptedFixes(reviewed)
		termOut.PrintInfo(fmt.Sprintf("%d fixes accepted after review", len(fixes)))
	}

	// ── Step 12: Output results ─────────────────────────────────────────
	if err := writeOutput(findings, fixes, targetDir); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}

	// ── Step 13: Apply fixes ────────────────────────────────────────────
	if scanApply && len(fixes) > 0 {
		termOut.PrintStep("Applying fixes...")
		applier := remediation.NewApplier()
		if applyErr := applier.Apply(ctx, targetDir, fixes); applyErr != nil {
			return fmt.Errorf("applying fixes: %w", applyErr)
		}
		termOut.PrintSuccess("Fixes applied successfully")
	}

	// ── Step 14: Create PR ──────────────────────────────────────────────
	if scanPR && len(fixes) > 0 {
		termOut.PrintStep("Creating pull request...")
		if prErr := createPR(ctx, cfg, targetDir, fixes); prErr != nil {
			return fmt.Errorf("creating PR: %w", prErr)
		}
		termOut.PrintSuccess("Pull request created")
	}

	// ── Step 15: Print summary ──────────────────────────────────────────
	if isTerminalFmt {
		termOut.PrintScanSummary(len(findings), len(fixes), scanApply, scanPR)
	}
	return nil
}

// loadConfig attempts to load configuration from the specified config file or
// from default locations (~/.fixiac.yaml, .fixiac.yaml).
func loadConfig() (*config.Config, error) {
	if cfgFile != "" {
		return config.Load(cfgFile)
	}
	// Try default paths: .fixiac.yaml in current dir, then home dir.
	if cfg, err := config.Load(".fixiac.yaml"); err == nil {
		return cfg, nil
	}
	home, err := os.UserHomeDir()
	if err == nil {
		if cfg, loadErr := config.Load(filepath.Join(home, ".fixiac.yaml")); loadErr == nil {
			return cfg, nil
		}
	}
	// Return empty config if no file found — all values will use defaults.
	return config.Load("")
}

// createScanners builds scanner instances based on the scanner flag.
func createScanners(name, targetDir string) ([]scanner.Scanner, error) {
	var scanners []scanner.Scanner
	switch strings.ToLower(name) {
	case "checkov":
		scanners = append(scanners, scanner.NewCheckovScanner(targetDir))
	case "trivy":
		scanners = append(scanners, scanner.NewTrivyScanner(targetDir))
	case "both", "all":
		scanners = append(scanners,
			scanner.NewCheckovScanner(targetDir),
			scanner.NewTrivyScanner(targetDir),
		)
	default:
		return nil, fmt.Errorf("unknown scanner %q; supported: checkov, trivy, both", name)
	}
	return scanners, nil
}

// filterSuppressed removes findings that match suppression rules.
func filterSuppressed(findings []scanner.Finding, store *suppress.Store) []scanner.Finding {
	filtered := make([]scanner.Finding, 0, len(findings))
	for _, f := range findings {
		suppressed, _ := store.IsSuppressed(f.RuleID, f.Resource)
		if !suppressed {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

// filterBySeverity keeps only findings at or above the specified severity.
func filterBySeverity(findings []scanner.Finding, minSeverity string) []scanner.Finding {
	minLevel := scanner.ParseSeverity(minSeverity)
	filtered := make([]scanner.Finding, 0, len(findings))
	for _, f := range findings {
		if f.Severity >= minLevel {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

// filterByFramework keeps only findings that have mappings to the specified
// compliance framework.
func filterByFramework(findings []scanner.Finding, framework string) []scanner.Finding {
	mapper := compliance.NewMapper()
	filtered := make([]scanner.Finding, 0, len(findings))
	for _, f := range findings {
		mapping := mapper.MapFinding(f.RuleID)
		for _, ctrl := range mapping {
			if strings.EqualFold(ctrl.Framework, framework) {
				filtered = append(filtered, f)
				break
			}
		}
	}
	return filtered
}

// generateFixes runs context analysis, initializes the LLM client, and
// generates a fix for each finding.
func generateFixes(
	ctx context.Context,
	cfg *config.Config,
	targetDir string,
	findings []scanner.Finding,
	termOut *output.TerminalOutput,
) ([]*remediation.Fix, error) {
	// Run context analysis.
	termOut.PrintStep("Analyzing codebase context...")
	analyzer := codebaseCtx.NewAnalyzer()
	codeCtx, err := analyzer.Analyze(ctx, targetDir)
	if err != nil {
		return nil, fmt.Errorf("analyzing codebase context: %w", err)
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
		return nil, fmt.Errorf("no LLM API key found; set llm.api_key in config or FIXIAC_API_KEY env var")
	}
	endpoint := cfg.Get("llm.endpoint")

	llmClient, err := llm.NewClient(provider, model, apiKey, endpoint)
	if err != nil {
		return nil, fmt.Errorf("creating LLM client: %w", err)
	}

	// Initialize compliance mapper and fix generator.
	mapper := compliance.NewMapper()
	generator := remediation.NewGenerator(llmClient, scanMaxRetries)

	tfPath := cfg.Get("terraform.path")
	if tfPath == "" {
		tfPath = "terraform"
	}
	var validator *remediation.Validator
	if scanValidate {
		validator = remediation.NewValidator(tfPath)
	}

	// Generate fixes for each finding.
	var fixes []*remediation.Fix
	for i, finding := range findings {
		termOut.PrintStep(fmt.Sprintf("Generating fix %d/%d: %s", i+1, len(findings), finding.RuleID))

		prompt := llm.BuildFixPrompt(finding, codeCtx)
		fix, genErr := generator.Generate(ctx, finding, prompt)
		if genErr != nil {
			termOut.PrintWarning(fmt.Sprintf("Could not generate fix for %s: %v", finding.RuleID, genErr))
			continue
		}

		// Enrich with compliance controls.
		mapping := mapper.MapFinding(finding.RuleID)
		fix.ComplianceControls = mapping

		// Validate the fix if enabled.
		if validator != nil {
			valid, valErr := validator.Validate(ctx, targetDir, fix)
			if valErr != nil {
				termOut.PrintWarning(fmt.Sprintf("Validation error for %s: %v", finding.RuleID, valErr))
			}
			fix.Validated = valid
		}

		fixes = append(fixes, fix)
	}

	return fixes, nil
}

// writeOutput writes findings and fixes using the configured output format.
func writeOutput(findings []scanner.Finding, fixes []*remediation.Fix, targetDir string) error {
	switch strings.ToLower(outputFmt) {
	case "terminal", "":
		// Terminal output was already handled inline.
		return nil
	case "json":
		return output.NewJSONOutput(os.Stdout).Write(findings, fixes)
	case "sarif":
		return output.NewSARIFOutput(os.Stdout).Write(findings, fixes)
	case "markdown":
		return output.NewMarkdownOutput(os.Stdout).Write(findings, fixes)
	case "patch":
		return output.NewPatchOutput(targetDir).Write(findings, fixes)
	default:
		return fmt.Errorf("unsupported output format: %s", outputFmt)
	}
}

// createPR creates a GitHub pull request with the applied fixes.
func createPR(ctx context.Context, cfg *config.Config, targetDir string, fixes []*remediation.Fix) error {
	token := cfg.Get("github.token")
	if token == "" {
		token = os.Getenv("GITHUB_TOKEN")
	}
	if token == "" {
		return fmt.Errorf("no GitHub token found; set github.token in config or GITHUB_TOKEN env var")
	}

	owner := cfg.Get("github.owner")
	repo := cfg.Get("github.repo")
	if owner == "" || repo == "" {
		return fmt.Errorf("github.owner and github.repo must be set in config for PR creation")
	}

	creator := github.NewPRCreator(token, owner, repo)
	return creator.CreateFixPR(ctx, targetDir, fixes)
}
