// Package suppress provides finding suppression management, allowing users to
// mark specific rule/resource combinations as acknowledged and excluded from
// remediation workflows.
package suppress

import "time"

// Suppression represents a deliberate decision to suppress a specific finding
// for a given resource. Suppressions can optionally expire.
type Suppression struct {
	// RuleID is the scanner rule identifier to suppress (e.g. "CKV_AWS_18").
	RuleID string `yaml:"rule_id" json:"rule_id"`
	// Resource is the full resource address to suppress (e.g. "aws_s3_bucket.logs").
	Resource string `yaml:"resource" json:"resource"`
	// Reason is a human-readable justification for the suppression.
	Reason string `yaml:"reason" json:"reason"`
	// CreatedAt is the timestamp when the suppression was created.
	CreatedAt time.Time `yaml:"created_at" json:"created_at"`
	// ExpiresAt is an optional expiry timestamp. A nil value means no expiry.
	ExpiresAt *time.Time `yaml:"expires_at,omitempty" json:"expires_at,omitempty"`
	// CreatedBy identifies who created the suppression.
	CreatedBy string `yaml:"created_by" json:"created_by"`
}

// IsExpired returns true if the suppression has an expiry time that is in the past.
func (s *Suppression) IsExpired() bool {
	if s.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*s.ExpiresAt)
}

// Matches returns true if this suppression applies to the given ruleID and
// resource combination. Both fields must match exactly.
func (s *Suppression) Matches(ruleID, resource string) bool {
	return s.RuleID == ruleID && s.Resource == resource
}
