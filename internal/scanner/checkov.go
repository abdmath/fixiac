package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// CheckovScanner wraps the checkov CLI tool.
type CheckovScanner struct {
	checkovPath string
}

// NewCheckovScanner creates a CheckovScanner. If path is empty, it defaults to
// "checkov" which will be resolved via PATH.
func NewCheckovScanner(path string) *CheckovScanner {
	if path == "" {
		path = "checkov"
	}
	return &CheckovScanner{checkovPath: path}
}

// Name returns the scanner's human-readable name.
func (c *CheckovScanner) Name() string {
	return "checkov"
}

// Available reports whether checkov is installed and reachable on PATH.
func (c *CheckovScanner) Available() bool {
	_, err := exec.LookPath(c.checkovPath)
	return err == nil
}

// checkovOutput represents the top-level JSON object in checkov's output array.
type checkovOutput struct {
	CheckType string       `json:"check_type"`
	Results   checkovResults `json:"results"`
}

// checkovResults holds the passed and failed check arrays.
type checkovResults struct {
	FailedChecks []checkovFailedCheck `json:"failed_checks"`
}

// checkovFailedCheck represents a single failed check from checkov output.
type checkovFailedCheck struct {
	CheckID     string          `json:"check_id"`
	CheckName   string          `json:"check_name"`
	CheckResult checkovResult   `json:"check_result"`
	FilePath    string          `json:"file_path"`
	FileLineRange []int         `json:"file_line_range"`
	Resource    string          `json:"resource"`
	Guideline   string          `json:"guideline"`
	CodeBlock   json.RawMessage `json:"code_block"`
}

// checkovResult holds the result status string.
type checkovResult struct {
	Result string `json:"result"`
}

// Scan runs checkov against the given directory and returns findings.
func (c *CheckovScanner) Scan(ctx context.Context, dir string) ([]Finding, error) {
	cmd := exec.CommandContext(ctx, c.checkovPath, "-d", dir, "-o", "json", "--compact", "--quiet")

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	// checkov exits non-zero when it finds failures — that is expected.
	// Only treat it as an error if we got no stdout at all.
	if err != nil && stdout.Len() == 0 {
		return nil, fmt.Errorf("checkov execution failed: %w: %s", err, stderr.String())
	}

	output := bytes.TrimSpace(stdout.Bytes())
	if len(output) == 0 {
		return nil, nil
	}

	findings, err := parseCheckovOutput(output)
	if err != nil {
		return nil, fmt.Errorf("parsing checkov output: %w", err)
	}

	return findings, nil
}

// ParseCheckovJSON parses raw JSON output from checkov into Finding structs.
func ParseCheckovJSON(data []byte) ([]Finding, error) {
	return parseCheckovOutput(data)
}

// parseCheckovOutput handles both array and single-object JSON from checkov.
func parseCheckovOutput(data []byte) ([]Finding, error) {
	var outputs []checkovOutput

	// Checkov may return a JSON array or a single object.
	if data[0] == '[' {
		if err := json.Unmarshal(data, &outputs); err != nil {
			return nil, fmt.Errorf("unmarshalling checkov JSON array: %w", err)
		}
	} else {
		var single checkovOutput
		if err := json.Unmarshal(data, &single); err != nil {
			return nil, fmt.Errorf("unmarshalling checkov JSON object: %w", err)
		}
		outputs = append(outputs, single)
	}

	var findings []Finding
	for _, o := range outputs {
		for _, fc := range o.Results.FailedChecks {
			f := convertCheckovFinding(fc)
			findings = append(findings, f)
		}
	}

	return findings, nil
}

// convertCheckovFinding converts a single checkov failed check into a Finding.
func convertCheckovFinding(fc checkovFailedCheck) Finding {
	startLine := 0
	endLine := 0
	if len(fc.FileLineRange) >= 2 {
		startLine = fc.FileLineRange[0]
		endLine = fc.FileLineRange[1]
	} else if len(fc.FileLineRange) == 1 {
		startLine = fc.FileLineRange[0]
		endLine = fc.FileLineRange[0]
	}

	return Finding{
		RuleID:      fc.CheckID,
		Source:      "checkov",
		Severity:    checkovSeverity(fc.CheckID),
		File:        normalizeFilePath(fc.FilePath),
		LineStart:   startLine,
		LineEnd:     endLine,
		Resource:    fc.Resource,
		Description: fc.CheckName,
		Guideline:   fc.Guideline,
		CodeBlock:   parseCodeBlock(fc.CodeBlock),
	}
}

// normalizeFilePath cleans up checkov's file path which often starts with "/".
func normalizeFilePath(p string) string {
	return strings.TrimPrefix(p, "/")
}

// checkovSeverity infers severity from a checkov check ID based on common
// patterns. Encryption, public access, and IAM checks are HIGH; logging
// checks are MEDIUM; description checks are LOW; everything else is MEDIUM.
func checkovSeverity(checkID string) Severity {
	upper := strings.ToUpper(checkID)

	// IAM-related checks.
	if strings.Contains(upper, "IAM") {
		return SeverityHigh
	}

	// Specific CKV_AWS pattern matching.
	if strings.HasPrefix(upper, "CKV_AWS_") || strings.HasPrefix(upper, "CKV_AZURE_") || strings.HasPrefix(upper, "CKV_GCP_") {
		lower := strings.ToLower(checkID)
		switch {
		case containsAny(lower, "encrypt", "public_access", "public-access", "publicly", "ssl", "tls", "kms"):
			return SeverityHigh
		case containsAny(lower, "iam", "policy", "privilege", "admin", "root"):
			return SeverityHigh
		case containsAny(lower, "log", "monitor", "trail", "audit"):
			return SeverityMedium
		case containsAny(lower, "description", "tag", "naming"):
			return SeverityLow
		}
	}

	// Check well-known high-severity check IDs by numeric ranges.
	knownHigh := map[string]bool{
		"CKV_AWS_19": true, "CKV_AWS_20": true, "CKV_AWS_21": true,
		"CKV_AWS_23": true, "CKV_AWS_24": true, "CKV_AWS_25": true,
		"CKV_AWS_26": true, "CKV_AWS_27": true, "CKV_AWS_33": true,
		"CKV_AWS_40": true, "CKV_AWS_41": true, "CKV_AWS_45": true,
		"CKV_AWS_46": true, "CKV_AWS_53": true, "CKV_AWS_54": true,
		"CKV_AWS_55": true, "CKV_AWS_57": true, "CKV_AWS_58": true,
		"CKV_AWS_70": true, "CKV_AWS_144": true, "CKV_AWS_145": true,
	}

	knownMedium := map[string]bool{
		"CKV_AWS_18": true, "CKV_AWS_35": true, "CKV_AWS_36": true,
		"CKV_AWS_37": true, "CKV_AWS_48": true, "CKV_AWS_50": true,
		"CKV_AWS_67": true,
	}

	if knownHigh[upper] {
		return SeverityHigh
	}
	if knownMedium[upper] {
		return SeverityMedium
	}

	return SeverityMedium
}

// containsAny checks if s contains any of the given substrings.
func containsAny(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// parseCodeBlock converts checkov's code_block JSON (array of [line_num, content]
// pairs) into a single string. Each pair becomes "line_num: content\n".
func parseCodeBlock(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}

	// code_block is an array of arrays: [[line_num, "content"], ...]
	var blocks [][]json.RawMessage
	if err := json.Unmarshal(raw, &blocks); err != nil {
		return ""
	}

	var sb strings.Builder
	for _, pair := range blocks {
		if len(pair) < 2 {
			continue
		}

		var lineNum json.Number
		var content string

		if err := json.Unmarshal(pair[0], &lineNum); err != nil {
			continue
		}
		if err := json.Unmarshal(pair[1], &content); err != nil {
			continue
		}

		sb.WriteString(lineNum.String())
		sb.WriteString(": ")
		sb.WriteString(content)
		if !strings.HasSuffix(content, "\n") {
			sb.WriteByte('\n')
		}
	}

	return sb.String()
}
