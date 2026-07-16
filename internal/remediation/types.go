// Package remediation provides AI-powered security fix generation and validation
// for Infrastructure-as-Code findings.
package remediation

import "github.com/abdma/fixiac/internal/scanner"

// Fix represents a proposed remediation for a security finding, including the
// original and fixed code, validation status, and risk assessment.
type Fix struct {
	// Finding is the security finding that this fix addresses.
	Finding scanner.Finding `json:"finding"`

	// OriginalCode is the original source code that contains the security issue.
	OriginalCode string `json:"original_code"`

	// FixedCode is the remediated source code with the security issue resolved.
	FixedCode string `json:"fixed_code"`

	// IsReplacement indicates whether this fix is a direct replacement of the
	// original code (true) or an addition/insertion (false).
	IsReplacement bool `json:"is_replacement"`

	// Explanation describes what the fix does and why it resolves the finding.
	Explanation string `json:"explanation"`

	// BlastRadius lists the resources or components that may be affected by
	// applying this fix.
	BlastRadius []string `json:"blast_radius,omitempty"`

	// RetryCount tracks how many times fix generation was retried for this finding.
	RetryCount int `json:"retry_count"`

	// ComplianceControls holds framework controls mapped to this fix/finding.
	ComplianceControls []scanner.FrameworkControl `json:"compliance_controls,omitempty"`

	// Validated indicates whether the fix has been validated (e.g., by HCL parsing).
	Validated bool `json:"validated"`

	// ValidationMsg contains the validation result message, including any errors.
	ValidationMsg string `json:"validation_msg,omitempty"`
}
