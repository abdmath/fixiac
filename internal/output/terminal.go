package output

import (
	"fmt"
	"strings"

	"github.com/abdma/fixiac/internal/remediation"
	"github.com/abdma/fixiac/internal/scanner"
	"github.com/charmbracelet/lipgloss"
)

const version = "0.1.0"

// TerminalOutput provides rich, styled terminal output for fixiac scan results
// using the lipgloss styling library. It renders findings, fixes, summaries,
// and status messages with color-coded severity badges and box layouts.
type TerminalOutput struct {
	// Style definitions
	titleStyle      lipgloss.Style
	subtitleStyle   lipgloss.Style
	borderStyle     lipgloss.Style
	severityStyles  map[scanner.Severity]lipgloss.Style
	successStyle    lipgloss.Style
	errorStyle      lipgloss.Style
	warningStyle    lipgloss.Style
	diffAddStyle    lipgloss.Style
	diffRemStyle    lipgloss.Style
	diffCtxStyle    lipgloss.Style
	labelStyle      lipgloss.Style
	valueStyle      lipgloss.Style
	dimStyle        lipgloss.Style
	headerStyle     lipgloss.Style
	footerStyle     lipgloss.Style
	findingBoxStyle lipgloss.Style
	fixBoxStyle     lipgloss.Style
	summaryBoxStyle lipgloss.Style
	bannerStyle     lipgloss.Style
}

// NewTerminalOutput creates a new TerminalOutput with pre-configured lipgloss
// styles for all UI elements including severity badges, diff formatting, and
// boxed layouts.
func NewTerminalOutput(opts ...interface{}) *TerminalOutput {
	t := &TerminalOutput{}

	// Core palette
	purple := lipgloss.Color("#7C3AED")
	cyan := lipgloss.Color("#06B6D4")
	dimWhite := lipgloss.Color("#94A3B8")
	white := lipgloss.Color("#F8FAFC")

	t.titleStyle = lipgloss.NewStyle().
		Bold(true).
		Foreground(white).
		Background(purple).
		Padding(0, 2)

	t.subtitleStyle = lipgloss.NewStyle().
		Foreground(cyan).
		Bold(true)

	t.borderStyle = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#475569")).
		Padding(1, 2)

	// Severity badge styles
	t.severityStyles = map[scanner.Severity]lipgloss.Style{
		scanner.CRITICAL: lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(lipgloss.Color("#DC2626")).
			Padding(0, 1),
		scanner.HIGH: lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(lipgloss.Color("#EA580C")).
			Padding(0, 1),
		scanner.MEDIUM: lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#1E293B")).
			Background(lipgloss.Color("#EAB308")).
			Padding(0, 1),
		scanner.LOW: lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(lipgloss.Color("#2563EB")).
			Padding(0, 1),
		scanner.INFO: lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(lipgloss.Color("#64748B")).
			Padding(0, 1),
	}

	t.successStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#22C55E")).
		Bold(true)

	t.errorStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#EF4444")).
		Bold(true)

	t.warningStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#F59E0B")).
		Bold(true)

	t.diffAddStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#22C55E"))

	t.diffRemStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#EF4444"))

	t.diffCtxStyle = lipgloss.NewStyle().
		Foreground(dimWhite)

	t.labelStyle = lipgloss.NewStyle().
		Foreground(cyan).
		Bold(true).
		Width(14)

	t.valueStyle = lipgloss.NewStyle().
		Foreground(white)

	t.dimStyle = lipgloss.NewStyle().
		Foreground(dimWhite)

	t.headerStyle = lipgloss.NewStyle().
		Foreground(white).
		Bold(true).
		BorderStyle(lipgloss.NormalBorder()).
		BorderBottom(true).
		BorderForeground(lipgloss.Color("#475569")).
		MarginBottom(1).
		PaddingBottom(0)

	t.footerStyle = lipgloss.NewStyle().
		Foreground(dimWhite).
		MarginTop(1)

	t.findingBoxStyle = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#475569")).
		Padding(1, 2).
		MarginBottom(1)

	t.fixBoxStyle = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#22C55E")).
		Padding(1, 2).
		MarginBottom(1)

	t.summaryBoxStyle = lipgloss.NewStyle().
		Border(lipgloss.DoubleBorder()).
		BorderForeground(purple).
		Padding(1, 3).
		MarginTop(1).
		MarginBottom(1)

	t.bannerStyle = lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#7C3AED")).
		MarginBottom(1)

	return t
}

// PrintBanner renders the fixiac ASCII art banner with version information.
func (t *TerminalOutput) PrintBanner(opts ...string) {
	banner := `
  ██████╗ ██╗██╗  ██╗██╗ █████╗  ██████╗
  ██╔═══╝ ██║╚██╗██╔╝██║██╔══██╗██╔════╝
  █████╗  ██║ ╚███╔╝ ██║███████║██║     
  ██╔══╝  ██║ ██╔██╗ ██║██╔══██║██║     
  ██║     ██║██╔╝ ██╗██║██║  ██║╚██████╗
  ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═╝ ╚═════╝`

	fmt.Println(t.bannerStyle.Render(banner))

	tagline := t.dimStyle.Render("  AI-native Terraform security remediation")
	ver := t.dimStyle.Render(fmt.Sprintf("  v%s", version))
	fmt.Println(tagline)
	fmt.Println(ver)
	fmt.Println()
}

// PrintScanStart renders a styled scan initiation message showing the target
// directory and scanner being used.
func (t *TerminalOutput) PrintScanStart(dir string, scannerOpts ...string) {
	scannerName := "checkov"
	if len(scannerOpts) > 0 && scannerOpts[0] != "" {
		scannerName = scannerOpts[0]
	}
	header := t.subtitleStyle.Render("⚡ Starting scan")
	fmt.Println(header)
	fmt.Println(t.renderField("Directory", dir))
	fmt.Println(t.renderField("Scanner", scannerName))
	fmt.Println(t.dimStyle.Render(strings.Repeat("─", 60)))
	fmt.Println()
}

// PrintFinding renders a single finding in a styled box with severity badge,
// resource information, file location, description, and compliance controls.
func (t *TerminalOutput) PrintFinding(index, total int, finding scanner.Finding) {
	var b strings.Builder

	// Header with index and severity
	counter := t.dimStyle.Render(fmt.Sprintf("Finding %d/%d", index, total))
	badge := t.renderSeverityBadge(finding.Severity)
	b.WriteString(fmt.Sprintf("%s  %s\n", counter, badge))
	b.WriteString("\n")

	// Rule ID
	b.WriteString(t.renderField("Rule", finding.RuleID))
	b.WriteString("\n")

	// Description
	b.WriteString(t.renderField("Issue", finding.Description))
	b.WriteString("\n")

	// Resource
	if finding.Resource != "" {
		b.WriteString(t.renderField("Resource", finding.Resource))
		b.WriteString("\n")
	}

	// Resource Type
	if finding.ResourceType != "" {
		b.WriteString(t.renderField("Type", finding.ResourceType))
		b.WriteString("\n")
	}

	// File location
	location := fmt.Sprintf("%s:%d", finding.File, finding.LineStart)
	if finding.LineEnd > finding.LineStart {
		location = fmt.Sprintf("%s:%d-%d", finding.File, finding.LineStart, finding.LineEnd)
	}
	b.WriteString(t.renderField("Location", location))
	b.WriteString("\n")

	// Guideline
	if finding.Guideline != "" {
		b.WriteString(t.renderField("Guideline", finding.Guideline))
		b.WriteString("\n")
	}

	// Compliance controls
	if len(finding.FrameworkControls) > 0 {
		b.WriteString("\n")
		b.WriteString(t.subtitleStyle.Render("Compliance Controls"))
		b.WriteString("\n")
		for _, ctrl := range finding.FrameworkControls {
			ctrlBadge := lipgloss.NewStyle().
				Foreground(lipgloss.Color("#A78BFA")).
				Bold(true).
				Render(fmt.Sprintf("[%s %s]", ctrl.Framework, ctrl.ControlID))
			b.WriteString(fmt.Sprintf("  %s %s\n", ctrlBadge, t.dimStyle.Render(ctrl.Description)))
		}
	}

	// Code block
	if finding.CodeBlock != "" {
		b.WriteString("\n")
		b.WriteString(t.subtitleStyle.Render("Code"))
		b.WriteString("\n")
		codeStyle := lipgloss.NewStyle().
			Foreground(lipgloss.Color("#94A3B8")).
			MarginLeft(2)
		for _, line := range strings.Split(finding.CodeBlock, "\n") {
			b.WriteString(codeStyle.Render(line))
			b.WriteString("\n")
		}
	}

	// Set border color by severity
	boxStyle := t.findingBoxStyle
	switch finding.Severity {
	case scanner.CRITICAL:
		boxStyle = boxStyle.BorderForeground(lipgloss.Color("#DC2626"))
	case scanner.HIGH:
		boxStyle = boxStyle.BorderForeground(lipgloss.Color("#EA580C"))
	case scanner.MEDIUM:
		boxStyle = boxStyle.BorderForeground(lipgloss.Color("#EAB308"))
	case scanner.LOW:
		boxStyle = boxStyle.BorderForeground(lipgloss.Color("#2563EB"))
	case scanner.INFO:
		boxStyle = boxStyle.BorderForeground(lipgloss.Color("#64748B"))
	}

	fmt.Println(boxStyle.Render(b.String()))
}

// PrintFix renders a proposed fix in diff format with green additions and red
// removals, including the explanation and blast radius assessment.
func (t *TerminalOutput) PrintFix(fix *remediation.Fix) {
	if fix == nil {
		return
	}

	var b strings.Builder

	// Header
	b.WriteString(t.subtitleStyle.Render("🔧 Proposed Fix"))
	b.WriteString("\n\n")

	// Explanation
	b.WriteString(t.renderField("Explanation", fix.Explanation))
	b.WriteString("\n")

	// Validation status
	if fix.Validated {
		b.WriteString(t.successStyle.Render("  ✓ Validated"))
		if fix.ValidationMsg != "" {
			b.WriteString(t.dimStyle.Render(fmt.Sprintf(" — %s", fix.ValidationMsg)))
		}
	} else {
		b.WriteString(t.warningStyle.Render("  ⚠ Not validated"))
		if fix.ValidationMsg != "" {
			b.WriteString(t.dimStyle.Render(fmt.Sprintf(" — %s", fix.ValidationMsg)))
		}
	}
	b.WriteString("\n\n")

	// Diff view
	b.WriteString(t.dimStyle.Render("  ── Changes ──"))
	b.WriteString("\n")

	if fix.IsReplacement && fix.OriginalCode != "" {
		// Show removal lines
		for _, line := range strings.Split(fix.OriginalCode, "\n") {
			b.WriteString(t.diffRemStyle.Render(fmt.Sprintf("  - %s", line)))
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}

	// Show addition lines
	if fix.FixedCode != "" {
		for _, line := range strings.Split(fix.FixedCode, "\n") {
			b.WriteString(t.diffAddStyle.Render(fmt.Sprintf("  + %s", line)))
			b.WriteString("\n")
		}
	}

	// Blast radius
	if len(fix.BlastRadius) > 0 {
		b.WriteString("\n")
		b.WriteString(t.warningStyle.Render("  ⚠ Blast Radius"))
		b.WriteString("\n")
		for _, item := range fix.BlastRadius {
			b.WriteString(t.dimStyle.Render(fmt.Sprintf("    • %s", item)))
			b.WriteString("\n")
		}
	}

	// Retry info
	if fix.RetryCount > 0 {
		b.WriteString(t.dimStyle.Render(fmt.Sprintf("\n  Retries: %d", fix.RetryCount)))
		b.WriteString("\n")
	}

	fmt.Println(t.fixBoxStyle.Render(b.String()))
}

// PrintScanSummary renders a concise summary of scan and remediation metrics.
func (t *TerminalOutput) PrintScanSummary(totalFindings, totalFixes int, applied bool, prCreated bool) {
	var b strings.Builder
	b.WriteString(t.titleStyle.Render(" SCAN SUMMARY "))
	b.WriteString("\n\n")
	b.WriteString(fmt.Sprintf("  %s %s\n", t.labelStyle.Render("Total Findings:"), t.valueStyle.Render(fmt.Sprintf("%d", totalFindings))))
	b.WriteString(fmt.Sprintf("  %s %s\n", t.labelStyle.Render("Fixes Generated:"), t.valueStyle.Render(fmt.Sprintf("%d", totalFixes))))
	if applied {
		b.WriteString(fmt.Sprintf("  %s %s\n", t.labelStyle.Render("Fixes Applied:"), t.valueStyle.Render("Yes ✅")))
	}
	if prCreated {
		b.WriteString(fmt.Sprintf("  %s %s\n", t.labelStyle.Render("PR Created:"), t.valueStyle.Render("Yes 🚀")))
	}
	b.WriteString("\n")
	fmt.Println(t.summaryBoxStyle.Render(b.String()))
}

// PrintSummary renders a comprehensive scan summary with severity breakdown,
// fix generation stats, and validation results in a double-bordered box.
func (t *TerminalOutput) PrintSummary(findings []scanner.Finding, fixes []*remediation.Fix) {
	var b strings.Builder

	// Title
	b.WriteString(t.titleStyle.Render(" SCAN SUMMARY "))
	b.WriteString("\n\n")

	// Count by severity
	counts := map[scanner.Severity]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}

	// Severity table
	severities := []scanner.Severity{scanner.CRITICAL, scanner.HIGH, scanner.MEDIUM, scanner.LOW, scanner.INFO}
	for _, sev := range severities {
		count := counts[sev]
		if count == 0 {
			continue
		}
		badge := t.renderSeverityBadge(sev)
		bar := t.renderBar(count, len(findings))
		b.WriteString(fmt.Sprintf("  %s  %s %s\n",
			badge,
			bar,
			t.dimStyle.Render(fmt.Sprintf("%d", count)),
		))
	}

	b.WriteString("\n")
	b.WriteString(t.dimStyle.Render(strings.Repeat("─", 50)))
	b.WriteString("\n\n")

	// Totals
	totalFindings := len(findings)
	totalFixes := len(fixes)
	validated := 0
	for _, fix := range fixes {
		if fix != nil && fix.Validated {
			validated++
		}
	}

	statStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#F8FAFC"))

	b.WriteString(fmt.Sprintf("  %s  %s\n",
		t.labelStyle.Render("Findings"),
		statStyle.Render(fmt.Sprintf("%d", totalFindings)),
	))
	b.WriteString(fmt.Sprintf("  %s  %s\n",
		t.labelStyle.Render("Fixes"),
		statStyle.Render(fmt.Sprintf("%d", totalFixes)),
	))
	b.WriteString(fmt.Sprintf("  %s  %s\n",
		t.labelStyle.Render("Validated"),
		t.successStyle.Render(fmt.Sprintf("%d", validated)),
	))

	// Coverage percentage
	if totalFindings > 0 {
		pct := float64(totalFixes) / float64(totalFindings) * 100
		b.WriteString(fmt.Sprintf("  %s  %s\n",
			t.labelStyle.Render("Coverage"),
			statStyle.Render(fmt.Sprintf("%.0f%%", pct)),
		))
	}

	fmt.Println(t.summaryBoxStyle.Render(b.String()))
}

// PrintValidationResult renders the validation status of a fix with a
// success or failure indicator and any validation messages.
func (t *TerminalOutput) PrintValidationResult(fix *remediation.Fix) {
	if fix == nil {
		return
	}

	if fix.Validated {
		msg := fmt.Sprintf("✓ Fix validated for %s", fix.Finding.RuleID)
		if fix.ValidationMsg != "" {
			msg += fmt.Sprintf(" — %s", fix.ValidationMsg)
		}
		fmt.Println(t.successStyle.Render(msg))
	} else {
		msg := fmt.Sprintf("✗ Validation failed for %s", fix.Finding.RuleID)
		if fix.ValidationMsg != "" {
			msg += fmt.Sprintf(" — %s", fix.ValidationMsg)
		}
		fmt.Println(t.errorStyle.Render(msg))
	}
}

// PrintError renders an error message with a red indicator.
func (t *TerminalOutput) PrintError(msg string) {
	fmt.Println(t.errorStyle.Render(fmt.Sprintf("✗ Error: %s", msg)))
}

// PrintSuccess renders a success message with a green indicator.
func (t *TerminalOutput) PrintSuccess(msg string) {
	fmt.Println(t.successStyle.Render(fmt.Sprintf("✓ %s", msg)))
}

// PrintWarning renders a warning message with a yellow indicator.
func (t *TerminalOutput) PrintWarning(msg string) {
	fmt.Println(t.warningStyle.Render(fmt.Sprintf("⚠ %s", msg)))
}

// PrintInfo renders an info message with a dim indicator.
func (t *TerminalOutput) PrintInfo(msg string) {
	fmt.Println(t.dimStyle.Render(fmt.Sprintf("ℹ %s", msg)))
}

// PrintStep renders a step progress message.
func (t *TerminalOutput) PrintStep(msg string) {
	fmt.Println(t.subtitleStyle.Render("▸ " + msg))
}

// PrintFindings renders all findings in the slice.
func (t *TerminalOutput) PrintFindings(findings []scanner.Finding) {
	for i, f := range findings {
		t.PrintFinding(i+1, len(findings), f)
	}
}

// renderSeverityBadge returns a styled severity badge string.
func (t *TerminalOutput) renderSeverityBadge(sev scanner.Severity) string {
	style, ok := t.severityStyles[sev]
	if !ok {
		style = t.severityStyles[scanner.INFO]
	}
	return style.Render(string(sev))
}

// renderField returns a styled label: value pair.
func (t *TerminalOutput) renderField(label, value string) string {
	return fmt.Sprintf("  %s %s",
		t.labelStyle.Render(label+":"),
		t.valueStyle.Render(value),
	)
}

// renderBar generates a proportional horizontal bar visualization.
func (t *TerminalOutput) renderBar(count, total int) string {
	if total == 0 {
		return ""
	}

	maxWidth := 20
	filled := (count * maxWidth) / total
	if filled == 0 && count > 0 {
		filled = 1
	}

	bar := strings.Repeat("█", filled) + strings.Repeat("░", maxWidth-filled)
	return t.dimStyle.Render(bar)
}
