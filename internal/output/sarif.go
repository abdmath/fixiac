package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/abdma/fixiac/internal/remediation"
	"github.com/abdma/fixiac/internal/scanner"
)

const (
	sarifSchemaURL = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
	sarifVersion   = "2.1.0"
	toolName       = "fixiac"
)

// SARIFOutput formats scan results as SARIF 2.1.0 (Static Analysis Results
// Interchange Format) for integration with GitHub Advanced Security, Azure
// DevOps, and other platforms that consume SARIF.
type SARIFOutput struct {
	w io.Writer
}

// SARIFReport is the top-level SARIF document containing the schema reference,
// version, and one or more analysis runs.
type SARIFReport struct {
	// Schema is the URI of the SARIF JSON schema.
	Schema string `json:"$schema"`

	// Version is the SARIF specification version (always "2.1.0").
	Version string `json:"version"`

	// Runs contains the list of analysis tool runs and their results.
	Runs []SARIFRun `json:"runs"`
}

// SARIFRun represents a single invocation of an analysis tool and its results.
type SARIFRun struct {
	// Tool describes the analysis tool that produced the results.
	Tool SARIFTool `json:"tool"`

	// Results is the list of findings produced by the tool.
	Results []SARIFResult `json:"results"`

	// Invocations describes the tool invocation details.
	Invocations []SARIFInvocation `json:"invocations,omitempty"`
}

// SARIFTool describes the analysis tool, including its driver component.
type SARIFTool struct {
	// Driver is the primary component of the tool.
	Driver SARIFDriver `json:"driver"`
}

// SARIFDriver describes the tool's primary component including its rules.
type SARIFDriver struct {
	// Name is the name of the tool.
	Name string `json:"name"`

	// Version is the tool version string.
	Version string `json:"version"`

	// InformationURI is a link to the tool's homepage or documentation.
	InformationURI string `json:"informationUri,omitempty"`

	// Rules defines the set of analysis rules used by the tool.
	Rules []SARIFRule `json:"rules,omitempty"`
}

// SARIFRule describes a single analysis rule.
type SARIFRule struct {
	// ID is the stable, unique identifier for the rule.
	ID string `json:"id"`

	// Name is the human-readable rule name.
	Name string `json:"name,omitempty"`

	// ShortDescription is a brief description of the rule.
	ShortDescription *SARIFMessage `json:"shortDescription,omitempty"`

	// FullDescription is the complete rule description.
	FullDescription *SARIFMessage `json:"fullDescription,omitempty"`

	// HelpURI is a link to detailed help for the rule.
	HelpURI string `json:"helpUri,omitempty"`

	// DefaultConfiguration provides the default severity configuration.
	DefaultConfiguration *SARIFRuleConfiguration `json:"defaultConfiguration,omitempty"`

	// Properties contains additional rule metadata.
	Properties *SARIFRuleProperties `json:"properties,omitempty"`
}

// SARIFRuleConfiguration specifies the default configuration for a rule.
type SARIFRuleConfiguration struct {
	// Level is the default severity level for the rule.
	Level string `json:"level"`
}

// SARIFRuleProperties holds additional metadata for a rule, such as tags
// and compliance framework mappings.
type SARIFRuleProperties struct {
	// Tags is a list of descriptive tags for the rule.
	Tags []string `json:"tags,omitempty"`

	// SecuritySeverity is the CVSS-like severity score as a string.
	SecuritySeverity string `json:"security-severity,omitempty"`
}

// SARIFResult represents a single finding result from the analysis.
type SARIFResult struct {
	// RuleID references the rule that produced this result.
	RuleID string `json:"ruleId"`

	// RuleIndex is the index of the rule in the driver's rules array.
	RuleIndex int `json:"ruleIndex"`

	// Level is the severity level of the result.
	Level string `json:"level"`

	// Message describes the finding.
	Message SARIFMessage `json:"message"`

	// Locations identifies where the finding was detected.
	Locations []SARIFLocation `json:"locations,omitempty"`

	// Fixes describes proposed automatic fixes for the result.
	Fixes []SARIFFix `json:"fixes,omitempty"`

	// Properties contains additional result metadata.
	Properties *SARIFResultProperties `json:"properties,omitempty"`
}

// SARIFMessage is a localizable string message.
type SARIFMessage struct {
	// Text is the plain text message content.
	Text string `json:"text"`
}

// SARIFLocation identifies a specific location in a source file.
type SARIFLocation struct {
	// PhysicalLocation specifies the file and region of the finding.
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`

	// LogicalLocations provides semantic location information.
	LogicalLocations []SARIFLogicalLocation `json:"logicalLocations,omitempty"`
}

// SARIFPhysicalLocation specifies a file artifact and region within it.
type SARIFPhysicalLocation struct {
	// ArtifactLocation identifies the file.
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`

	// Region specifies the line/column range of the finding.
	Region SARIFRegion `json:"region"`
}

// SARIFArtifactLocation identifies a file by its URI.
type SARIFArtifactLocation struct {
	// URI is the file path, typically relative to the repository root.
	URI string `json:"uri"`
}

// SARIFRegion specifies a range within a source file.
type SARIFRegion struct {
	// StartLine is the 1-based starting line number.
	StartLine int `json:"startLine"`

	// EndLine is the 1-based ending line number.
	EndLine int `json:"endLine,omitempty"`

	// Snippet provides the source code text for the region.
	Snippet *SARIFSnippet `json:"snippet,omitempty"`
}

// SARIFSnippet contains a text snippet from the source file.
type SARIFSnippet struct {
	// Text is the source code content.
	Text string `json:"text"`
}

// SARIFLogicalLocation provides semantic information about the location.
type SARIFLogicalLocation struct {
	// Name is the logical name of the location (e.g., resource name).
	Name string `json:"name,omitempty"`

	// FullyQualifiedName is the fully qualified logical location name.
	FullyQualifiedName string `json:"fullyQualifiedName,omitempty"`

	// Kind identifies the type of logical location (e.g., "resource").
	Kind string `json:"kind,omitempty"`
}

// SARIFFix describes a proposed automatic fix for a finding.
type SARIFFix struct {
	// Description describes what the fix does.
	Description SARIFMessage `json:"description"`

	// ArtifactChanges lists the file changes that constitute the fix.
	ArtifactChanges []SARIFArtifactChange `json:"artifactChanges"`
}

// SARIFArtifactChange describes changes to a single file.
type SARIFArtifactChange struct {
	// ArtifactLocation identifies the file being changed.
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`

	// Replacements lists the text replacements within the file.
	Replacements []SARIFReplacement `json:"replacements"`
}

// SARIFReplacement describes a single text replacement in a file.
type SARIFReplacement struct {
	// DeletedRegion identifies the region of text to remove.
	DeletedRegion SARIFRegion `json:"deletedRegion"`

	// InsertedContent specifies the text to insert.
	InsertedContent *SARIFInsertedContent `json:"insertedContent,omitempty"`
}

// SARIFInsertedContent contains the text to insert at a replacement point.
type SARIFInsertedContent struct {
	// Text is the replacement text content.
	Text string `json:"text"`
}

// SARIFInvocation describes a single invocation of the tool.
type SARIFInvocation struct {
	// ExecutionSuccessful indicates whether the tool invocation succeeded.
	ExecutionSuccessful bool `json:"executionSuccessful"`
}

// SARIFResultProperties holds additional metadata for a result.
type SARIFResultProperties struct {
	// Resource is the infrastructure resource affected by the finding.
	Resource string `json:"resource,omitempty"`

	// ResourceType is the type of the infrastructure resource.
	ResourceType string `json:"resourceType,omitempty"`

	// Source identifies the original scanner that produced the finding.
	Source string `json:"source,omitempty"`

	// FrameworkControls lists compliance framework controls for the finding.
	FrameworkControls []scanner.FrameworkControl `json:"frameworkControls,omitempty"`
}

// NewSARIFOutput creates a new SARIFOutput formatter.
func NewSARIFOutput(w ...io.Writer) *SARIFOutput {
	var writer io.Writer
	if len(w) > 0 && w[0] != nil {
		writer = w[0]
	}
	return &SARIFOutput{w: writer}
}

// Format serializes findings and fixes into a SARIF 2.1.0 JSON byte slice.
// Each unique rule ID from the findings is registered in the tool driver's
// rules array, and each finding maps to a SARIF result with optional fix data.
func (s *SARIFOutput) Format(findings []scanner.Finding, fixes []*remediation.Fix) ([]byte, error) {
	report := s.buildReport(findings, fixes)

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshaling SARIF output: %w", err)
	}

	return data, nil
}

// Write serializes findings and fixes as SARIF 2.1.0 JSON and writes the
// output to the configured writer.
func (s *SARIFOutput) Write(findings []scanner.Finding, fixes []*remediation.Fix) error {
	return s.WriteWithWriter(s.w, findings, fixes)
}

// WriteWithWriter serializes findings and fixes as SARIF 2.1.0 JSON and writes the
// output to the provided writer.
func (s *SARIFOutput) WriteWithWriter(w io.Writer, findings []scanner.Finding, fixes []*remediation.Fix) error {
	if w == nil {
		return fmt.Errorf("no writer provided for SARIF output")
	}
	data, err := s.Format(findings, fixes)
	if err != nil {
		return fmt.Errorf("formatting SARIF output: %w", err)
	}

	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("writing SARIF output: %w", err)
	}

	if _, err := w.Write([]byte("\n")); err != nil {
		return fmt.Errorf("writing SARIF trailing newline: %w", err)
	}

	return nil
}

// buildReport constructs the complete SARIF report from findings and fixes.
func (s *SARIFOutput) buildReport(findings []scanner.Finding, fixes []*remediation.Fix) SARIFReport {
	// Build fix lookup by rule ID for matching
	fixByRuleID := make(map[string]*remediation.Fix)
	for _, fix := range fixes {
		if fix != nil {
			fixByRuleID[fix.Finding.RuleID] = fix
		}
	}

	// Collect unique rules and build rule index
	ruleIndex := make(map[string]int)
	var rules []SARIFRule

	for _, f := range findings {
		if _, exists := ruleIndex[f.RuleID]; exists {
			continue
		}
		idx := len(rules)
		ruleIndex[f.RuleID] = idx

		rule := SARIFRule{
			ID:   f.RuleID,
			Name: f.RuleID,
			ShortDescription: &SARIFMessage{
				Text: f.Description,
			},
			FullDescription: &SARIFMessage{
				Text: f.Description,
			},
			DefaultConfiguration: &SARIFRuleConfiguration{
				Level: severityToSARIFLevel(f.Severity),
			},
			Properties: &SARIFRuleProperties{
				Tags:             s.buildTags(f),
				SecuritySeverity: severityToScore(f.Severity),
			},
		}

		if f.Guideline != "" {
			rule.HelpURI = f.Guideline
		}

		rules = append(rules, rule)
	}

	// Build results
	var results []SARIFResult
	for _, f := range findings {
		result := SARIFResult{
			RuleID:    f.RuleID,
			RuleIndex: ruleIndex[f.RuleID],
			Level:     severityToSARIFLevel(f.Severity),
			Message: SARIFMessage{
				Text: f.Description,
			},
			Locations: []SARIFLocation{
				{
					PhysicalLocation: SARIFPhysicalLocation{
						ArtifactLocation: SARIFArtifactLocation{
							URI: normalizeFilePath(f.File),
						},
						Region: SARIFRegion{
							StartLine: f.LineStart,
							EndLine:   f.LineEnd,
						},
					},
					LogicalLocations: []SARIFLogicalLocation{
						{
							Name:               f.Resource,
							FullyQualifiedName: f.ResourceType + "." + f.Resource,
							Kind:               "resource",
						},
					},
				},
			},
			Properties: &SARIFResultProperties{
				Resource:          f.Resource,
				ResourceType:      f.ResourceType,
				Source:            f.Source,
				FrameworkControls: f.FrameworkControls,
			},
		}

		// Add code snippet if available
		if f.CodeBlock != "" {
			result.Locations[0].PhysicalLocation.Region.Snippet = &SARIFSnippet{
				Text: f.CodeBlock,
			}
		}

		// Attach fix if one exists for this finding
		if fix, ok := fixByRuleID[f.RuleID]; ok {
			result.Fixes = []SARIFFix{
				{
					Description: SARIFMessage{
						Text: fix.Explanation,
					},
					ArtifactChanges: []SARIFArtifactChange{
						{
							ArtifactLocation: SARIFArtifactLocation{
								URI: normalizeFilePath(f.File),
							},
							Replacements: []SARIFReplacement{
								{
									DeletedRegion: SARIFRegion{
										StartLine: f.LineStart,
										EndLine:   f.LineEnd,
									},
									InsertedContent: &SARIFInsertedContent{
										Text: fix.FixedCode,
									},
								},
							},
						},
					},
				},
			}
		}

		results = append(results, result)
	}

	if results == nil {
		results = []SARIFResult{}
	}
	if rules == nil {
		rules = []SARIFRule{}
	}

	return SARIFReport{
		Schema:  sarifSchemaURL,
		Version: sarifVersion,
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:           toolName,
						Version:        version,
						InformationURI: "https://github.com/abdma/fixiac",
						Rules:          rules,
					},
				},
				Results: results,
				Invocations: []SARIFInvocation{
					{
						ExecutionSuccessful: true,
					},
				},
			},
		},
	}
}

// buildTags creates a tag list from the finding's source and framework controls.
func (s *SARIFOutput) buildTags(f scanner.Finding) []string {
	tags := []string{"security", "iac"}

	if f.Source != "" {
		tags = append(tags, f.Source)
	}
	if f.ResourceType != "" {
		tags = append(tags, f.ResourceType)
	}

	for _, ctrl := range f.FrameworkControls {
		tags = append(tags, fmt.Sprintf("%s:%s", ctrl.Framework, ctrl.ControlID))
	}

	return tags
}

// severityToSARIFLevel converts a scanner severity to a SARIF level string.
func severityToSARIFLevel(sev scanner.Severity) string {
	switch sev {
	case scanner.CRITICAL, scanner.HIGH:
		return "error"
	case scanner.MEDIUM:
		return "warning"
	case scanner.LOW, scanner.INFO:
		return "note"
	default:
		return "none"
	}
}

// severityToScore converts a scanner severity to a CVSS-like score string
// for the security-severity SARIF property.
func severityToScore(sev scanner.Severity) string {
	switch sev {
	case scanner.CRITICAL:
		return "9.5"
	case scanner.HIGH:
		return "8.0"
	case scanner.MEDIUM:
		return "5.5"
	case scanner.LOW:
		return "3.0"
	case scanner.INFO:
		return "1.0"
	default:
		return "0.0"
	}
}

// normalizeFilePath converts backslashes to forward slashes for SARIF URIs.
func normalizeFilePath(path string) string {
	return strings.ReplaceAll(path, "\\", "/")
}
