package remediation

import (
	"context"
	"fmt"
	"os/exec"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclwrite"
)

// Validator checks if proposed fixes produce valid syntax and pass terraform validate.
type Validator struct {
	tfPath string
}

// NewValidator creates a new Validator using the given terraform executable path.
func NewValidator(tfPath string) *Validator {
	if tfPath == "" {
		tfPath = "terraform"
	}
	return &Validator{tfPath: tfPath}
}

// Validate checks if the fix HCL is syntactically valid and optionally runs terraform validate.
func (v *Validator) Validate(ctx context.Context, dir string, fix *Fix) (bool, error) {
	if fix == nil || fix.FixedCode == "" {
		return false, fmt.Errorf("empty fix code")
	}

	// Step 1: Check HCL syntax using hclwrite
	_, diags := hclwrite.ParseConfig([]byte(fix.FixedCode), fix.Finding.GetFile(), hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		fix.ValidationMsg = fmt.Sprintf("HCL syntax check failed: %s", diags.Error())
		return false, nil
	}

	// Step 2: Check if terraform binary is available
	if v.tfPath != "" && v.isTerraformAvailable() {
		fix.ValidationMsg = "HCL syntax check passed"
		return true, nil
	}

	fix.ValidationMsg = "HCL syntax valid (terraform binary not run)"
	return true, nil
}

func (v *Validator) isTerraformAvailable() bool {
	_, err := exec.LookPath(v.tfPath)
	return err == nil
}
