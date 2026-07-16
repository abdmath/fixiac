package remediation

import (
	"context"
	"fmt"
	"strings"

	"github.com/abdma/fixiac/internal/llm"
	"github.com/abdma/fixiac/internal/scanner"
)

// Generator handles AI-powered remediation generation using an LLM client.
type Generator struct {
	client     llm.Client
	maxRetries int
}

// NewGenerator creates a new Generator with the specified LLM client and retry limit.
func NewGenerator(client llm.Client, maxRetries int) *Generator {
	if maxRetries <= 0 {
		maxRetries = 3
	}
	return &Generator{
		client:     client,
		maxRetries: maxRetries,
	}
}

// Generate requests a fix from the LLM for the given finding using the provided prompt.
func (g *Generator) Generate(ctx context.Context, finding scanner.Finding, prompt string) (*Fix, error) {
	if g.client == nil {
		return nil, fmt.Errorf("no LLM client configured")
	}

	req := &llm.GenerateRequest{
		SystemPrompt: "You are fixiac, an AI-native Terraform security remediation expert. Given a security finding and codebase context, generate valid, idiomatic Terraform HCL code that fixes the misconfiguration while matching existing naming conventions and patterns. Output ONLY the fixed code inside a ```hcl ... ``` block, followed by an explanation and blast radius assessment.",
		UserPrompt:   prompt,
		Temperature:  0.2,
		MaxTokens:    4096,
	}

	var lastErr error
	for attempt := 1; attempt <= g.maxRetries; attempt++ {
		resp, err := g.client.Generate(ctx, req)
		if err != nil {
			lastErr = err
			continue
		}

		fix, parseErr := parseLLMResponse(finding, resp.Content, attempt)
		if parseErr != nil {
			lastErr = parseErr
			continue
		}

		return fix, nil
	}

	return nil, fmt.Errorf("failed to generate fix after %d retries: %w", g.maxRetries, lastErr)
}

func parseLLMResponse(finding scanner.Finding, content string, retryCount int) (*Fix, error) {
	// Extract HCL code block
	fixedCode := extractCodeBlock(content, "hcl")
	if fixedCode == "" {
		fixedCode = extractCodeBlock(content, "terraform")
	}
	if fixedCode == "" {
		// Try generic code block
		fixedCode = extractCodeBlock(content, "")
	}
	if fixedCode == "" {
		return nil, fmt.Errorf("LLM response did not contain a code block")
	}

	explanation := extractSection(content, "Explanation")
	if explanation == "" {
		explanation = fmt.Sprintf("AI-generated fix for %s (%s)", finding.RuleID, finding.Description)
	}

	blastRadiusStr := extractSection(content, "Blast Radius")
	var blastRadius []string
	if blastRadiusStr != "" {
		for _, line := range strings.Split(blastRadiusStr, "\n") {
			line = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "-"))
			line = strings.TrimPrefix(line, "*")
			line = strings.TrimSpace(line)
			if line != "" {
				blastRadius = append(blastRadius, line)
			}
		}
	}

	return &Fix{
		Finding:       finding,
		OriginalCode:  finding.CodeBlock,
		FixedCode:     strings.TrimSpace(fixedCode),
		IsReplacement: true,
		Explanation:   strings.TrimSpace(explanation),
		BlastRadius:   blastRadius,
		RetryCount:    retryCount,
	}, nil
}

func extractCodeBlock(content, lang string) string {
	startTag := "```" + lang
	startIdx := strings.Index(strings.ToLower(content), startTag)
	if startIdx == -1 && lang == "" {
		startIdx = strings.Index(content, "```")
		startTag = "```"
	}
	if startIdx == -1 {
		return ""
	}
	start := startIdx + len(startTag)
	endIdx := strings.Index(content[start:], "```")
	if endIdx == -1 {
		return strings.TrimSpace(content[start:])
	}
	return strings.TrimSpace(content[start : start+endIdx])
}

func extractSection(content, header string) string {
	lowerContent := strings.ToLower(content)
	lowerHeader := strings.ToLower(header)
	idx := strings.Index(lowerContent, lowerHeader)
	if idx == -1 {
		return ""
	}
	start := idx + len(header)
	eol := strings.Index(content[start:], "\n")
	if eol != -1 {
		start += eol + 1
	}
	end := len(content)
	nextHeader := strings.Index(content[start:], "\n#")
	if nextHeader != -1 {
		end = start + nextHeader
	}
	return strings.TrimSpace(content[start:end])
}
