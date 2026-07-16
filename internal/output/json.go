package output

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/abdma/fixiac/internal/remediation"
	"github.com/abdma/fixiac/internal/scanner"
)

// JSONOutput formats scan results as structured JSON for machine consumption,
// CI/CD integration, and programmatic processing.
type JSONOutput struct {
	w io.Writer
}

// ScanResult is the top-level JSON structure containing all scan output:
// findings, generated fixes, summary statistics, and scan metadata.
type ScanResult struct {
	// Findings is the list of security findings discovered during the scan.
	Findings []scanner.Finding `json:"findings"`

	// Fixes is the list of proposed remediations for the findings.
	Fixes []*remediation.Fix `json:"fixes"`

	// Summary contains aggregate statistics about the scan results.
	Summary ResultSummary `json:"summary"`

	// Metadata contains information about the scan execution environment.
	Metadata ScanMetadata `json:"metadata"`
}

// ResultSummary contains aggregate statistics about the scan results including
// counts by severity, fix generation, and validation metrics.
type ResultSummary struct {
	// TotalFindings is the total number of security findings discovered.
	TotalFindings int `json:"total_findings"`

	// BySeverity maps severity level strings to their respective finding counts.
	BySeverity map[string]int `json:"by_severity"`

	// FixesGenerated is the number of fixes that were successfully generated.
	FixesGenerated int `json:"fixes_generated"`

	// FixesValidated is the number of fixes that passed validation.
	FixesValidated int `json:"fixes_validated"`

	// Suppressed is the number of findings that were suppressed by configuration.
	Suppressed int `json:"suppressed"`
}

// ScanMetadata contains contextual information about the scan execution
// including the scanner used, target directory, and timing information.
type ScanMetadata struct {
	// Scanner is the name of the scanner used (e.g., "checkov", "tfsec").
	Scanner string `json:"scanner"`

	// Directory is the target directory that was scanned.
	Directory string `json:"directory"`

	// Timestamp is the ISO 8601 timestamp of when the scan was executed.
	Timestamp string `json:"timestamp"`

	// Version is the fixiac version that produced this output.
	Version string `json:"version"`
}

// NewJSONOutput creates a new JSONOutput formatter.
func NewJSONOutput(w ...io.Writer) *JSONOutput {
	var writer io.Writer
	if len(w) > 0 && w[0] != nil {
		writer = w[0]
	}
	return &JSONOutput{w: writer}
}

// Format serializes the scan findings, fixes, and metadata into a
// pretty-printed JSON byte slice. It computes summary statistics from the
// provided findings and fixes.
func (j *JSONOutput) Format(findings []scanner.Finding, fixes []*remediation.Fix, meta ScanMetadata) ([]byte, error) {
	result := j.buildResult(findings, fixes, meta)

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshaling JSON output: %w", err)
	}

	return data, nil
}

// Write serializes the scan results as pretty-printed JSON and writes them
// to the configured writer.
func (j *JSONOutput) Write(findings []scanner.Finding, fixes []*remediation.Fix) error {
	return j.WriteWithWriter(j.w, findings, fixes, ScanMetadata{})
}

// WriteWithWriter serializes the scan results as pretty-printed JSON and writes them
// to the provided writer.
func (j *JSONOutput) WriteWithWriter(w io.Writer, findings []scanner.Finding, fixes []*remediation.Fix, meta ScanMetadata) error {
	if w == nil {
		return fmt.Errorf("no writer provided for JSON output")
	}
	data, err := j.Format(findings, fixes, meta)
	if err != nil {
		return fmt.Errorf("formatting JSON output: %w", err)
	}

	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("writing JSON output: %w", err)
	}

	// Trailing newline for clean file output
	if _, err := w.Write([]byte("\n")); err != nil {
		return fmt.Errorf("writing JSON trailing newline: %w", err)
	}

	return nil
}

// buildResult constructs the complete ScanResult with computed summary stats.
func (j *JSONOutput) buildResult(findings []scanner.Finding, fixes []*remediation.Fix, meta ScanMetadata) ScanResult {
	// Ensure timestamp is populated
	if meta.Timestamp == "" {
		meta.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	if meta.Version == "" {
		meta.Version = version
	}

	// Compute severity counts
	bySeverity := make(map[string]int)
	for _, f := range findings {
		bySeverity[string(f.Severity)]++
	}

	// Count validated fixes
	validated := 0
	for _, fix := range fixes {
		if fix != nil && fix.Validated {
			validated++
		}
	}

	// Ensure non-nil slices for clean JSON output
	if findings == nil {
		findings = []scanner.Finding{}
	}
	if fixes == nil {
		fixes = []*remediation.Fix{}
	}

	return ScanResult{
		Findings: findings,
		Fixes:    fixes,
		Summary: ResultSummary{
			TotalFindings:  len(findings),
			BySeverity:     bySeverity,
			FixesGenerated: len(fixes),
			FixesValidated: validated,
			Suppressed:     0,
		},
		Metadata: meta,
	}
}
