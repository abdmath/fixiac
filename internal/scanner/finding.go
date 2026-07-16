// Package scanner defines the core data models and interfaces for IaC security scans.
package scanner

import "strings"

// Severity represents the severity level of a security finding.
type Severity string

const (
	// SeverityCritical / CRITICAL indicates a critical security issue.
	SeverityCritical Severity = "CRITICAL"
	CRITICAL         Severity = "CRITICAL"

	// SeverityHigh / HIGH indicates a high-severity security issue.
	SeverityHigh Severity = "HIGH"
	HIGH         Severity = "HIGH"

	// SeverityMedium / MEDIUM indicates a medium-severity security issue.
	SeverityMedium Severity = "MEDIUM"
	MEDIUM         Severity = "MEDIUM"

	// SeverityLow / LOW indicates a low-severity security issue.
	SeverityLow Severity = "LOW"
	LOW         Severity = "LOW"

	// SeverityInfo / INFO indicates an informational finding.
	SeverityInfo Severity = "INFO"
	INFO         Severity = "INFO"
)

// Weight returns a numeric weight for the severity level, useful for sorting and
// prioritization. CRITICAL = 5, HIGH = 4, MEDIUM = 3, LOW = 2, INFO = 1.
func (s Severity) Weight() int {
	switch strings.ToUpper(string(s)) {
	case "CRITICAL":
		return 5
	case "HIGH":
		return 4
	case "MEDIUM":
		return 3
	case "LOW":
		return 2
	case "INFO":
		return 1
	default:
		return 0
	}
}

// ParseSeverity converts a case-insensitive string to a Severity constant.
func ParseSeverity(s string) Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return SeverityCritical
	case "HIGH":
		return SeverityHigh
	case "MEDIUM":
		return SeverityMedium
	case "LOW":
		return SeverityLow
	case "INFO":
		return SeverityInfo
	default:
		return SeverityInfo
	}
}

// FrameworkControl associates a finding with a specific compliance framework control.
type FrameworkControl struct {
	Framework   string `json:"framework" yaml:"framework"`
	ControlID   string `json:"control_id" yaml:"control_id"`
	Description string `json:"description" yaml:"description"`
}

// Finding represents a single security finding reported by an IaC scanner.
type Finding struct {
	RuleID            string             `json:"rule_id" yaml:"rule_id"`
	Source            string             `json:"source" yaml:"source"`
	Resource          string             `json:"resource" yaml:"resource"`
	ResourceType      string             `json:"resource_type" yaml:"resource_type"`
	File              string             `json:"file" yaml:"file"`
	FilePath          string             `json:"file_path,omitempty" yaml:"file_path,omitempty"`
	LineStart         int                `json:"line_start" yaml:"line_start"`
	LineEnd           int                `json:"line_end" yaml:"line_end"`
	Description       string             `json:"description" yaml:"description"`
	Severity          Severity           `json:"severity" yaml:"severity"`
	Guideline         string             `json:"guideline" yaml:"guideline"`
	FrameworkControls []FrameworkControl `json:"framework_controls,omitempty" yaml:"framework_controls,omitempty"`
	CodeBlock         string             `json:"code_block,omitempty" yaml:"code_block,omitempty"`
	Suppressed        bool               `json:"suppressed,omitempty" yaml:"suppressed,omitempty"`
	SuppressionReason string             `json:"suppression_reason,omitempty" yaml:"suppression_reason,omitempty"`
}

// ResourceName extracts the name part from a fully-qualified resource address.
func (f *Finding) ResourceName() string {
	parts := strings.SplitN(f.Resource, ".", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return f.Resource
}

// ResourceTypeName extracts the type part from a fully-qualified resource address.
func (f *Finding) ResourceTypeName() string {
	parts := strings.SplitN(f.Resource, ".", 2)
	if len(parts) >= 1 {
		return parts[0]
	}
	return f.Resource
}

// GetFile returns the file path of the finding, checking File first then FilePath.
func (f *Finding) GetFile() string {
	if f.File != "" {
		return f.File
	}
	return f.FilePath
}

// GetFilePath returns the file path of the finding, checking FilePath first then File.
func (f *Finding) GetFilePath() string {
	if f.FilePath != "" {
		return f.FilePath
	}
	return f.File
}
