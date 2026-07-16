package cli

import (
	"context"
	"fmt"
	"os"
	"time"

	codebaseCtx "github.com/abdma/fixiac/internal/context"
	"github.com/abdma/fixiac/internal/llm"
	"github.com/abdma/fixiac/internal/output"
	"github.com/spf13/cobra"
)

var explainContextFile string

var explainCmd = &cobra.Command{
	Use:   "explain [rule_id]",
	Short: "Explain a security rule in plain English",
	Long: `Get a clear, plain-English explanation of what a security rule checks,
why it matters, and how to fix it. Optionally provide a file path for
a context-aware explanation tailored to your specific code.

Example:
  fixiac explain CKV_AWS_18
  fixiac explain CKV_AWS_19 --context modules/s3/bucket.tf`,
	Args: cobra.ExactArgs(1),
	RunE: runExplain,
}

func init() {
	explainCmd.Flags().StringVar(&explainContextFile, "context", "", "file path for context-aware explanation")
}

// runExplain generates a plain-English explanation of the specified security
// rule, optionally enriched with codebase context from the provided file.
func runExplain(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Minute)
	defer cancel()

	ruleID := args[0]
	termOut := output.NewTerminalOutput(os.Stdout, !quiet)
	termOut.PrintBanner(versionStr)

	// Load config for LLM settings.
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
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

	// Optionally load codebase context.
	var codeCtx *codebaseCtx.CodebaseContext
	if explainContextFile != "" {
		termOut.PrintStep("Analyzing codebase context...")
		analyzer := codebaseCtx.NewAnalyzer()
		analysisCtx, analysisErr := analyzer.AnalyzeFile(ctx, explainContextFile)
		if analysisErr != nil {
			termOut.PrintWarning(fmt.Sprintf("Could not analyze context: %v", analysisErr))
		} else {
			codeCtx = analysisCtx
		}
	}

	// Build the explanation prompt and call the LLM.
	termOut.PrintStep(fmt.Sprintf("Explaining rule %s...", ruleID))
	prompt := llm.BuildExplainPrompt(ruleID, codeCtx)
	explanation, err := llmClient.Complete(ctx, prompt)
	if err != nil {
		return fmt.Errorf("generating explanation: %w", err)
	}

	// Print the explanation.
	fmt.Println()
	termOut.PrintInfo(fmt.Sprintf("Rule: %s", ruleID))
	fmt.Println()
	fmt.Println(explanation)
	fmt.Println()

	return nil
}
