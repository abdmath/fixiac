package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// TrivyScanner wraps the trivy CLI tool for infrastructure-as-code scanning.
type TrivyScanner struct {
	trivyPath string
}

// NewTrivyScanner creates a TrivyScanner. If path is empty, it defaults to
// "trivy" which will be resolved via PATH.
func NewTrivyScanner(path string) *TrivyScanner {
	if path == "" {
		path = "trivy"
	}
	return &TrivyScanner{trivyPath: path}
}

// Name returns the scanner's human-readable name.
func (t *TrivyScanner) Name() string {
	return "trivy"
}

// Available reports whether trivy is installed and reachable on PATH.
func (t *TrivyScanner) Available() bool {
	_, err := exec.LookPath(t.trivyPath)
	return err == nil
}

// trivyOutput represents the top-level JSON output from trivy config.
type trivyOutput struct {
	Results []trivyResult `json:"Results"`
}

// trivyResult represents a single result target from trivy.
type trivyResult struct {
	Target            string                  `json:"Target"`
	Misconfigurations []trivyMisconfiguration `json:"Misconfigurations"`
}

// trivyMisconfiguration represents a single misconfiguration finding.
type trivyMisconfiguration struct {
	ID          string            `json:"ID"`
	Title       string            `json:"Title"`
	Description string            `json:"Description"`
	Severity    string            `json:"Severity"`
	Status      string            `json:"Status"`
	Resolution  string            `json:"Resolution"`
	CauseMeta   trivyCauseMetadata `json:"CauseMetadata"`
}

// trivyCauseMetadata contains location and resource info for a misconfiguration.
type trivyCauseMetadata struct {
	Resource  string `json:"Resource"`
	Provider  string `json:"Provider"`
	Service   string `json:"Service"`
	StartLine int    `json:"StartLine"`
	EndLine   int    `json:"EndLine"`
	Code      trivyCode `json:"Code"`
}

// trivyCode holds the code context from trivy output.
type trivyCode struct {
	Lines []trivyCodeLine `json:"Lines"`
}

// trivyCodeLine represents a single line of code context.
type trivyCodeLine struct {
	Number  int    `json:"Number"`
	Content string `json:"Content"`
}

// Scan runs trivy config scan against the given directory and returns findings.
func (t *TrivyScanner) Scan(ctx context.Context, dir string) ([]Finding, error) {
	cmd := exec.CommandContext(ctx, t.trivyPath, "config", dir, "-f", "json", "-q")

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	// trivy exits non-zero when it finds issues — that is expected.
	if err != nil && stdout.Len() == 0 {
		return nil, fmt.Errorf("trivy execution failed: %w: %s", err, stderr.String())
	}

	output := bytes.TrimSpace(stdout.Bytes())
	if len(output) == 0 {
		return nil, nil
	}

	findings, err := parseTrivyOutput(output)
	if err != nil {
		return nil, fmt.Errorf("parsing trivy output: %w", err)
	}

	return findings, nil
}

// ParseTrivyJSON parses raw JSON output from trivy into Finding structs.
func ParseTrivyJSON(data []byte) ([]Finding, error) {
	return parseTrivyOutput(data)
}

// parseTrivyOutput parses the JSON output from trivy and converts
// FAIL-status misconfigurations into Finding structs.
func parseTrivyOutput(data []byte) ([]Finding, error) {
	var output trivyOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, fmt.Errorf("unmarshalling trivy JSON: %w", err)
	}

	var findings []Finding
	for _, result := range output.Results {
		for _, mc := range result.Misconfigurations {
			if !strings.EqualFold(mc.Status, "FAIL") {
				continue
			}

			f := Finding{
				RuleID:      mc.ID,
				Source:      "trivy",
				Severity:    ParseSeverity(mc.Severity),
				File:        result.Target,
				LineStart:   mc.CauseMeta.StartLine,
				LineEnd:     mc.CauseMeta.EndLine,
				Resource:    mc.CauseMeta.Resource,
				Description: mc.Title,
				Guideline:   mc.Resolution,
				CodeBlock:   buildTrivyCodeBlock(mc.CauseMeta.Code),
			}

			// Fall back to description if title is empty.
			if f.Description == "" {
				f.Description = mc.Description
			}

			findings = append(findings, f)
		}
	}

	return findings, nil
}

// buildTrivyCodeBlock converts trivy's code lines into a single code block string.
func buildTrivyCodeBlock(code trivyCode) string {
	if len(code.Lines) == 0 {
		return ""
	}

	var sb strings.Builder
	for _, line := range code.Lines {
		fmt.Fprintf(&sb, "%d: %s\n", line.Number, line.Content)
	}
	return sb.String()
}
