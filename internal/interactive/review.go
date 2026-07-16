package interactive

import (
	"fmt"
	"strings"

	"github.com/abdma/fixiac/internal/remediation"
	"github.com/abdma/fixiac/internal/scanner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type ReviewAction string

const (
	ActionApply   ReviewAction = "apply"
	ActionSkip    ReviewAction = "skip"
	ActionReject  ReviewAction = "reject"
	ActionExplain ReviewAction = "explain"
)

type ReviewResult struct {
	Finding scanner.Finding
	Fix     *remediation.Fix
	Action  ReviewAction
	Reason  string // for reject
}

type ReviewSession struct {
	findings []scanner.Finding
	fixes    []*remediation.Fix
	results  []ReviewResult
}

// NewReviewSession creates an interactive TUI review session for generated fixes.
func NewReviewSession(findings []scanner.Finding, fixes []*remediation.Fix) *ReviewSession {
	return &ReviewSession{
		findings: findings,
		fixes:    fixes,
		results:  make([]ReviewResult, 0, len(findings)),
	}
}

// Run launches the Bubble Tea interactive review terminal interface.
func (r *ReviewSession) Run() ([]ReviewResult, error) {
	if len(r.findings) == 0 || len(r.fixes) == 0 {
		return nil, nil
	}

	m := &reviewModel{
		findings: r.findings,
		fixes:    r.fixes,
		current:  0,
		results:  make([]ReviewResult, 0, len(r.findings)),
	}

	p := tea.NewProgram(m)
	finalModel, err := p.Run()
	if err != nil {
		return nil, fmt.Errorf("running interactive review TUI: %w", err)
	}

	if resModel, ok := finalModel.(*reviewModel); ok {
		return resModel.results, nil
	}

	return m.results, nil
}

// GetAcceptedFixes returns a slice of Fix pointers for all review results
// where the user selected ActionApply.
func GetAcceptedFixes(results []ReviewResult) []*remediation.Fix {
	var accepted []*remediation.Fix
	for _, res := range results {
		if res.Action == ActionApply && res.Fix != nil {
			accepted = append(accepted, res.Fix)
		}
	}
	return accepted
}

type reviewModel struct {
	findings   []scanner.Finding
	fixes      []*remediation.Fix
	current    int
	results    []ReviewResult
	rejecting  bool
	reasonBuf  string
	explaining bool
}

func (m *reviewModel) Init() tea.Cmd {
	return nil
}

func (m *reviewModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if m.rejecting {
			switch msg.String() {
			case "enter":
				m.results = append(m.results, ReviewResult{
					Finding: m.findings[m.current],
					Fix:     m.fixes[m.current],
					Action:  ActionReject,
					Reason:  strings.TrimSpace(m.reasonBuf),
				})
				m.rejecting = false
				m.reasonBuf = ""
				m.current++
				if m.current >= len(m.findings) || m.current >= len(m.fixes) {
					return m, tea.Quit
				}
			case "esc":
				m.rejecting = false
				m.reasonBuf = ""
			case "backspace":
				if len(m.reasonBuf) > 0 {
					m.reasonBuf = m.reasonBuf[:len(m.reasonBuf)-1]
				}
			default:
				if len(msg.String()) == 1 {
					m.reasonBuf += msg.String()
				}
			}
			return m, nil
		}

		if m.explaining {
			if msg.String() == "esc" || msg.String() == "q" || msg.String() == "enter" {
				m.explaining = false
			}
			return m, nil
		}

		switch strings.ToLower(msg.String()) {
		case "ctrl+c", "q":
			return m, tea.Quit
		case "a":
			m.results = append(m.results, ReviewResult{
				Finding: m.findings[m.current],
				Fix:     m.fixes[m.current],
				Action:  ActionApply,
			})
			m.current++
			if m.current >= len(m.findings) || m.current >= len(m.fixes) {
				return m, tea.Quit
			}
		case "s":
			m.results = append(m.results, ReviewResult{
				Finding: m.findings[m.current],
				Fix:     m.fixes[m.current],
				Action:  ActionSkip,
			})
			m.current++
			if m.current >= len(m.findings) || m.current >= len(m.fixes) {
				return m, tea.Quit
			}
		case "r":
			m.rejecting = true
		case "e":
			m.explaining = true
		}
	}
	return m, nil
}

func (m *reviewModel) View() string {
	if m.current >= len(m.findings) || m.current >= len(m.fixes) {
		return lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Bold(true).Render("\n  ✓ Review completed! Applying selected fixes...\n\n")
	}

	finding := m.findings[m.current]
	fix := m.fixes[m.current]

	var b strings.Builder

	// Header box
	headerStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("63")).
		Padding(0, 1).
		Width(80)

	sevColor := "240"
	switch finding.Severity {
	case scanner.SeverityCritical:
		sevColor = "196"
	case scanner.SeverityHigh:
		sevColor = "208"
	case scanner.SeverityMedium:
		sevColor = "220"
	case scanner.SeverityLow:
		sevColor = "39"
	}

	badge := lipgloss.NewStyle().Background(lipgloss.Color(sevColor)).Foreground(lipgloss.Color("15")).Bold(true).Padding(0, 1).Render(string(finding.Severity))
	headerText := fmt.Sprintf("Finding %d of %d  |  %s  |  Rule: %s", m.current+1, len(m.findings), badge, finding.RuleID)
	b.WriteString(headerStyle.Render(headerText))
	b.WriteString("\n\n")

	// Resource details
	b.WriteString(lipgloss.NewStyle().Bold(true).Render(fmt.Sprintf("Resource: %s (%s)", finding.Resource, finding.ResourceType)) + "\n")
	b.WriteString(fmt.Sprintf("File: %s (Lines %d-%d)\n", finding.File, finding.LineStart, finding.LineEnd))
	b.WriteString(fmt.Sprintf("Description: %s\n\n", finding.Description))

	if m.explaining {
		explainStyle := lipgloss.NewStyle().Border(lipgloss.NormalBorder()).BorderForeground(lipgloss.Color("220")).Padding(1).Width(78)
		explainText := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("220")).Render("Explanation of Proposed Fix:\n\n") + fix.Explanation
		b.WriteString(explainStyle.Render(explainText) + "\n\nPress [ESC] or [ENTER] to return to review.\n")
		return b.String()
	}

	if m.rejecting {
		rejectStyle := lipgloss.NewStyle().Border(lipgloss.NormalBorder()).BorderForeground(lipgloss.Color("196")).Padding(1).Width(78)
		prompt := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("196")).Render("Enter rejection reason (for suppression/logging):") + "\n\n> " + m.reasonBuf
		b.WriteString(rejectStyle.Render(prompt) + "\n\nPress [ENTER] to submit, [ESC] to cancel.\n")
		return b.String()
	}

	// Diff view
	diffHeader := lipgloss.NewStyle().Foreground(lipgloss.Color("246")).Render("Proposed Remediation Diff:")
	b.WriteString(diffHeader + "\n")

	diffStyle := lipgloss.NewStyle().Border(lipgloss.NormalBorder()).BorderForeground(lipgloss.Color("240")).Padding(1).Width(78)
	var diffBuf strings.Builder
	for _, line := range strings.Split(fix.OriginalCode, "\n") {
		if strings.TrimSpace(line) != "" {
			diffBuf.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Render("- "+line) + "\n")
		}
	}
	for _, line := range strings.Split(fix.FixedCode, "\n") {
		if strings.TrimSpace(line) != "" {
			diffBuf.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Render("+ "+line) + "\n")
		}
	}
	b.WriteString(diffStyle.Render(diffBuf.String()))
	b.WriteString("\n\n")

	// Controls
	footerStyle := lipgloss.NewStyle().Background(lipgloss.Color("236")).Foreground(lipgloss.Color("252")).Padding(0, 1).Width(80)
	footerText := "[A]pply Fix   [S]kip Finding   [R]eject (Suppress)   [E]xplain Fix   [Q]uit Review"
	b.WriteString(footerStyle.Render(footerText))
	b.WriteString("\n")

	return b.String()
}
