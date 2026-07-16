// Package compliance provides compliance framework definitions and a mapping
// engine that associates IaC scanner rule IDs with specific compliance controls.
package compliance

// Framework represents a compliance standard (e.g. CIS AWS Foundations Benchmark).
type Framework struct {
	// ID is a short machine-readable identifier (e.g. "cis_aws").
	ID string `yaml:"id"`
	// Name is the human-readable framework name.
	Name string `yaml:"name"`
	// Version is the framework specification version.
	Version string `yaml:"version"`
	// Controls is the list of controls defined by this framework.
	Controls []Control `yaml:"controls"`
}

// Control represents a single control within a compliance framework.
type Control struct {
	// ID is the control identifier (e.g. "2.1.1").
	ID string `yaml:"id"`
	// Name is a short name for the control.
	Name string `yaml:"name"`
	// Description is a detailed description of what the control requires.
	Description string `yaml:"description"`
	// Category groups related controls (e.g. "Logging", "Encryption").
	Category string `yaml:"category"`
}

// RuleMapping associates a scanner rule ID with compliance controls and metadata.
type RuleMapping struct {
	// RuleID is the scanner-specific rule identifier (e.g. "CKV_AWS_18").
	RuleID string `yaml:"rule_id"`
	// Description is a human-readable description of the rule.
	Description string `yaml:"description"`
	// Severity is the severity level of findings triggered by this rule.
	Severity string `yaml:"severity"`
	// ResourceType is the Terraform resource type this rule applies to.
	ResourceType string `yaml:"resource_type"`
	// Controls lists the compliance controls this rule maps to.
	Controls []ControlRef `yaml:"controls"`
}

// ControlRef is a lightweight reference to a control within a specific framework.
type ControlRef struct {
	// Framework is the framework ID this control belongs to.
	Framework string `yaml:"framework"`
	// ControlID is the control identifier within the framework.
	ControlID string `yaml:"control_id"`
}
