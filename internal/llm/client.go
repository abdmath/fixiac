// Package llm provides LLM client interfaces and implementations for generating
// Terraform security remediations.
package llm

import (
	"context"
	"fmt"
	"strings"

	codebaseCtx "github.com/abdma/fixiac/internal/context"
	"github.com/abdma/fixiac/internal/scanner"
)

// GenerateRequest represents a request to generate text from an LLM.
type GenerateRequest struct {
	SystemPrompt string  `json:"system_prompt"`
	UserPrompt   string  `json:"user_prompt"`
	MaxTokens    int     `json:"max_tokens"`
	Temperature  float64 `json:"temperature"`
}

// GenerateResponse represents the response from an LLM generation request.
type GenerateResponse struct {
	Content      string `json:"content"`
	TokensUsed   int    `json:"tokens_used"`
	Model        string `json:"model"`
	Provider     string `json:"provider"`
	FinishReason string `json:"finish_reason"`
}

// Client is the interface that all LLM provider clients must implement.
type Client interface {
	// Generate sends a prompt to the LLM and returns the generated response.
	Generate(ctx context.Context, req *GenerateRequest) (*GenerateResponse, error)

	// Complete sends a simple user prompt and returns only the generated string.
	Complete(ctx context.Context, prompt string) (string, error)

	// Name returns the display name of the LLM provider.
	Name() string

	// Available returns true if the LLM provider is reachable and ready.
	Available() bool
}

// NewClient creates a new LLM client for the specified provider.
// Supported providers: groq, openai, anthropic, ollama, lmstudio.
func NewClient(provider, model, apiKey, endpoint string) (Client, error) {
	switch provider {
	case "groq":
		return newGroqClient(model, apiKey, endpoint), nil
	case "openai":
		return newOpenAIClient(model, apiKey, endpoint), nil
	case "anthropic":
		return newAnthropicClient(model, apiKey, endpoint), nil
	case "ollama":
		return newOllamaClient(model, endpoint), nil
	case "lmstudio":
		return newLMStudioClient(model, endpoint), nil
	default:
		return nil, fmt.Errorf("unknown LLM provider %q: supported providers are groq, openai, anthropic, ollama, lmstudio", provider)
	}
}

// BuildExplainPrompt creates a prompt for explaining a security rule in plain English.
func BuildExplainPrompt(ruleID string, codeCtx *codebaseCtx.CodebaseContext) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Please provide a clear, plain-English explanation of the Infrastructure-as-Code security check with Rule ID: %s.\n\n", ruleID))
	sb.WriteString("Include:\n1. What exact security vulnerability or misconfiguration this rule checks for.\n2. Why this is dangerous or bad practice (potential attack vectors or operational risks).\n3. How to remediate or fix this issue in Terraform HCL.\n")
	if codeCtx != nil && codeCtx.RootDir != "" {
		sb.WriteString(fmt.Sprintf("\nContext: The user's project is at %s.\n", codeCtx.RootDir))
	}
	return sb.String()
}

// BuildFixPrompt creates a detailed prompt for generating a remediation fix for a finding.
func BuildFixPrompt(finding scanner.Finding, codeCtx *codebaseCtx.CodebaseContext) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Please generate a valid, idiomatic Terraform HCL fix for the following security issue:\n\nRule ID: %s\nIssue: %s\nResource: %s (%s)\nFile: %s:%d-%d\n", finding.RuleID, finding.Description, finding.Resource, finding.ResourceType, finding.GetFile(), finding.LineStart, finding.LineEnd))
	if finding.Guideline != "" {
		sb.WriteString(fmt.Sprintf("Guideline: %s\n", finding.Guideline))
	}
	if finding.CodeBlock != "" {
		sb.WriteString(fmt.Sprintf("\nOriginal Code:\n```hcl\n%s\n```\n", finding.CodeBlock))
	}
	if codeCtx != nil {
		if codeCtx.Conventions != nil && codeCtx.Conventions.Pattern != "" {
			sb.WriteString(fmt.Sprintf("\nProject Naming Convention: Pattern=%s, Separator=%s\n", codeCtx.Conventions.Pattern, codeCtx.Conventions.Separator))
		}
		if codeCtx.TagStandard != nil && len(codeCtx.TagStandard.CommonKeys) > 0 {
			sb.WriteString(fmt.Sprintf("Project Common Tags: %s\n", strings.Join(codeCtx.TagStandard.CommonKeys, ", ")))
		}
	}
	sb.WriteString("\nPlease output ONLY the complete fixed HCL block inside ```hcl ... ``` followed by an Explanation and Blast Radius section.")
	return sb.String()
}
