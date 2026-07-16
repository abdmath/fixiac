package output

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/abdma/fixiac/internal/remediation"
	"github.com/abdma/fixiac/internal/scanner"
)

// MarkdownOutput formats scan results as Markdown, primarily for use in
// GitHub Pull Request comments and review summaries.
type MarkdownOutput struct {
	w io.Writer
}

// NewMarkdownOutput creates a new MarkdownOutput formatter.
func NewMarkdownOutput(w ...io.Writer) *MarkdownOutput {
	var writer io.Writer
	if len(w) > 0 && w[0] != nil {
		writer = w[0]
	}
	return &MarkdownOutput{w: writer}
}

// Write writes formatted Markdown output to the configured writer.
func (m *MarkdownOutput) Write(findings []scanner.Finding, fixes []*remediation.Fix) error {
	return m.WriteWithWriter(m.w, findings, fixes)
}

// WriteWithWriter writes formatted Markdown output to the provided writer.
func (m *MarkdownOutput) WriteWithWriter(w io.Writer, findings []scanner.Finding, fixes []*remediation.Fix) error {
	if w == nil {
		return fmt.Errorf("no writer provided for Markdown output")
	}
	content := m.FormatPRComment(findings, fixes)
	if _, err := w.Write([]byte(content)); err != nil {
		return fmt.Errorf("writing Markdown output: %w", err)
	}
	return nil
}

// FormatPRComment generates a complete PR comment body containing a summary
// table with severity counts, detailed findings with proposed fixes in diff
// format, compliance controls, and a timestamp footer.
func (m *MarkdownOutput) FormatPRComment(findings []scanner.Finding, fixes []*remediation.Fix) string {
	var b strings.Builder

	// Header
	b.WriteString("## 🔒 fixiac Security Scan Results\n\n")

	if len(findings) == 0 {
		b.WriteString("✅ **No security issues found!** Your infrastructure code looks good.\n\n")
		b.WriteString(m.footer())
		return b.String()
	}

	// Build fix lookup
	fixByRuleID := make(map[string]*remediation.Fix)
	for _, fix := range fixes {
		if fix != nil {
			fixByRuleID[fix.Finding.RuleID] = fix
		}
	}

	// Summary table
	b.WriteString("### 📊 Summary\n\n")
	b.WriteString(m.buildSummaryTable(findings, fixes))
	b.WriteString("\n")

	// Findings
	b.WriteString("### 🔍 Findings\n\n")

	for i, f := range findings {
		fix := fixByRuleID[f.RuleID]
		b.WriteString(m.formatSingleFinding(i+1, f, fix))
		b.WriteString("\n")
	}

	// Compliance controls section
	controls := m.collectControls(findings)
	if len(controls) > 0 {
		b.WriteString("### 📋 Compliance Controls\n\n")
		b.WriteString(m.buildControlsTable(controls))
		b.WriteString("\n")
	}

	// Footer
	b.WriteString(m.footer())

	return b.String()
}

// FormatFindingComment generates a single finding comment suitable for inline
// PR review comments on a specific file and line.
func (m *MarkdownOutput) FormatFindingComment(finding scanner.Finding, fix *remediation.Fix) string {
	var b strings.Builder

	// Severity badge and description
	b.WriteString(fmt.Sprintf("**%s** %s\n\n", m.severityEmoji(finding.Severity), finding.Description))

	// Details
	b.WriteString(fmt.Sprintf("- **Rule:** `%s`\n", finding.RuleID))
	b.WriteString(fmt.Sprintf("- **Severity:** %s %s\n", m.severityEmoji(finding.Severity), string(finding.Severity)))

	if finding.Resource != "" {
		b.WriteString(fmt.Sprintf("- **Resource:** `%s`\n", finding.Resource))
	}
	if finding.ResourceType != "" {
		b.WriteString(fmt.Sprintf("- **Type:** `%s`\n", finding.ResourceType))
	}

	// Guideline
	if finding.Guideline != "" {
		b.WriteString(fmt.Sprintf("- **Guideline:** [View](%s)\n", finding.Guideline))
	}

	// Compliance controls
	if len(finding.FrameworkControls) > 0 {
		b.WriteString("\n**Compliance:**\n")
		for _, ctrl := range finding.FrameworkControls {
			b.WriteString(fmt.Sprintf("- `%s %s` — %s\n", ctrl.Framework, ctrl.ControlID, ctrl.Description))
		}
	}

	// Fix
	if fix != nil {
		b.WriteString("\n**🔧 Suggested Fix:**\n\n")
		b.WriteString(fmt.Sprintf("> %s\n\n", fix.Explanation))

		if fix.IsReplacement && fix.OriginalCode != "" {
			b.WriteString("```diff\n")
			for _, line := range strings.Split(fix.OriginalCode, "\n") {
				b.WriteString(fmt.Sprintf("- %s\n", line))
			}
			for _, line := range strings.Split(fix.FixedCode, "\n") {
				b.WriteString(fmt.Sprintf("+ %s\n", line))
			}
			b.WriteString("```\n")
		} else if fix.FixedCode != "" {
			b.WriteString("```hcl\n")
			b.WriteString(fix.FixedCode)
			if !strings.HasSuffix(fix.FixedCode, "\n") {
				b.WriteString("\n")
			}
			b.WriteString("```\n")
		}

		// Validation status
		if fix.Validated {
			b.WriteString("\n✅ Fix validated successfully")
			if fix.ValidationMsg != "" {
				b.WriteString(fmt.Sprintf(" — %s", fix.ValidationMsg))
			}
			b.WriteString("\n")
		}

		// Blast radius
		if len(fix.BlastRadius) > 0 {
			b.WriteString("\n⚠️ **Blast Radius:**\n")
			for _, item := range fix.BlastRadius {
				b.WriteString(fmt.Sprintf("- %s\n", item))
			}
		}
	}

	return b.String()
}

// buildSummaryTable creates a markdown table summarizing findings by severity
// and fix/validation statistics.
func (m *MarkdownOutput) buildSummaryTable(findings []scanner.Finding, fixes []*remediation.Fix) string {
	// Count by severity
	counts := map[scanner.Severity]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}

	validated := 0
	for _, fix := range fixes {
		if fix != nil && fix.Validated {
			validated++
		}
	}

	var b strings.Builder

	b.WriteString("| Metric | Count |\n")
	b.WriteString("|--------|-------|\n")

	severities := []scanner.Severity{scanner.CRITICAL, scanner.HIGH, scanner.MEDIUM, scanner.LOW, scanner.INFO}
	for _, sev := range severities {
		if count, ok := counts[sev]; ok && count > 0 {
			b.WriteString(fmt.Sprintf("| %s %s | %d |\n", m.severityEmoji(sev), string(sev), count))
		}
	}

	b.WriteString(fmt.Sprintf("| **Total Findings** | **%d** |\n", len(findings)))
	b.WriteString(fmt.Sprintf("| Fixes Generated | %d |\n", len(fixes)))
	b.WriteString(fmt.Sprintf("| Fixes Validated | %d |\n", validated))

	return b.String()
}

// formatSingleFinding renders a single finding with its fix as a collapsible
// details section.
func (m *MarkdownOutput) formatSingleFinding(index int, f scanner.Finding, fix *remediation.Fix) string {
	var b strings.Builder

	// Collapsible details block
	summary := fmt.Sprintf("%s `%s` — %s", m.severityEmoji(f.Severity), f.RuleID, truncate(f.Description, 80))
	b.WriteString(fmt.Sprintf("<details>\n<summary>%d. %s</summary>\n\n", index, summary))

	// Finding details
	b.WriteString(fmt.Sprintf("**Severity:** %s %s\n\n", m.severityEmoji(f.Severity), string(f.Severity)))
	b.WriteString(fmt.Sprintf("**Description:** %s\n\n", f.Description))

	if f.Resource != "" {
		b.WriteString(fmt.Sprintf("**Resource:** `%s`\n\n", f.Resource))
	}

	location := fmt.Sprintf("`%s:%d`", f.File, f.LineStart)
	if f.LineEnd > f.LineStart {
		location = fmt.Sprintf("`%s:%d-%d`", f.File, f.LineStart, f.LineEnd)
	}
	b.WriteString(fmt.Sprintf("**Location:** %s\n\n", location))

	if f.Guideline != "" {
		b.WriteString(fmt.Sprintf("**Guideline:** [View documentation](%s)\n\n", f.Guideline))
	}

	// Compliance
	if len(f.FrameworkControls) > 0 {
		b.WriteString("**Compliance Controls:**\n")
		for _, ctrl := range f.FrameworkControls {
			b.WriteString(fmt.Sprintf("- `%s %s` — %s\n", ctrl.Framework, ctrl.ControlID, ctrl.Description))
		}
		b.WriteString("\n")
	}

	// Fix section
	if fix != nil {
		b.WriteString("#### 🔧 Proposed Fix\n\n")
		b.WriteString(fmt.Sprintf("> %s\n\n", fix.Explanation))

		if fix.IsReplacement && fix.OriginalCode != "" {
			b.WriteString("```diff\n")
			for _, line := range strings.Split(fix.OriginalCode, "\n") {
				b.WriteString(fmt.Sprintf("- %s\n", line))
			}
			for _, line := range strings.Split(fix.FixedCode, "\n") {
				b.WriteString(fmt.Sprintf("+ %s\n", line))
			}
			b.WriteString("```\n\n")
		} else if fix.FixedCode != "" {
			b.WriteString("```hcl\n")
			b.WriteString(fix.FixedCode)
			if !strings.HasSuffix(fix.FixedCode, "\n") {
				b.WriteString("\n")
			}
			b.WriteString("```\n\n")
		}

		if fix.Validated {
			b.WriteString("✅ Fix validated\n\n")
		}

		if len(fix.BlastRadius) > 0 {
			b.WriteString("⚠️ **Blast Radius:**\n")
			for _, item := range fix.BlastRadius {
				b.WriteString(fmt.Sprintf("- %s\n", item))
			}
			b.WriteString("\n")
		}
	}

	b.WriteString("</details>\n")
	return b.String()
}

// collectControls extracts all unique framework controls from findings.
func (m *MarkdownOutput) collectControls(findings []scanner.Finding) []controlEntry {
	seen := make(map[string]bool)
	var controls []controlEntry

	for _, f := range findings {
		for _, ctrl := range f.FrameworkControls {
			key := ctrl.Framework + ":" + ctrl.ControlID
			if !seen[key] {
				seen[key] = true
				controls = append(controls, controlEntry{
					Framework:   ctrl.Framework,
					ControlID:   ctrl.ControlID,
					Description: ctrl.Description,
					RuleID:      f.RuleID,
				})
			}
		}
	}

	return controls
}

// controlEntry associates a framework control with the rule that references it.
type controlEntry struct {
	Framework   string
	ControlID   string
	Description string
	RuleID      string
}

// buildControlsTable generates a markdown table of compliance controls.
func (m *MarkdownOutput) buildControlsTable(controls []controlEntry) string {
	var b strings.Builder

	b.WriteString("| Framework | Control | Description | Rule |\n")
	b.WriteString("|-----------|---------|-------------|------|\n")

	for _, c := range controls {
		b.WriteString(fmt.Sprintf("| %s | %s | %s | `%s` |\n",
			c.Framework, c.ControlID, c.Description, c.RuleID))
	}

	return b.String()
}

// severityEmoji returns an emoji indicator for the given severity level.
func (m *MarkdownOutput) severityEmoji(sev scanner.Severity) string {
	switch sev {
	case scanner.CRITICAL:
		return "🔴"
	case scanner.HIGH:
		return "🟠"
	case scanner.MEDIUM:
		return "🟡"
	case scanner.LOW:
		return "🔵"
	case scanner.INFO:
		return "⚪"
	default:
		return "⚪"
	}
}

// footer generates the standard fixiac PR comment footer with timestamp.
func (m *MarkdownOutput) footer() string {
	var b strings.Builder
	b.WriteString("---\n")
	b.WriteString(fmt.Sprintf("*Generated by [fixiac](https://github.com/abdma/fixiac) v%s at %s*\n",
		version, time.Now().UTC().Format("2006-01-02 15:04:05 UTC")))
	return b.String()
}

// truncate shortens a string to the specified maximum length, appending
// an ellipsis if truncation occurred.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
