package output

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/abdma/fixiac/internal/remediation"
	"github.com/abdma/fixiac/internal/scanner"
)

// PatchOutput formats scan results as unified diff patch files.
type PatchOutput struct {
	patchDir string
}

// NewPatchOutput creates a new PatchOutput writer for the specified directory.
func NewPatchOutput(patchDir string) *PatchOutput {
	return &PatchOutput{patchDir: patchDir}
}

// Write generates patch files for each fix and writes them to the patch directory.
func (p *PatchOutput) Write(findings []scanner.Finding, fixes []*remediation.Fix) error {
	if len(fixes) == 0 {
		return nil
	}

	if err := os.MkdirAll(p.patchDir, 0755); err != nil {
		return fmt.Errorf("creating patch directory %s: %w", p.patchDir, err)
	}

	for i, fix := range fixes {
		if fix == nil || fix.FixedCode == "" {
			continue
		}

		fileName := fmt.Sprintf("fix-%03d-%s.patch", i+1, strings.ReplaceAll(fix.Finding.RuleID, "_", "-"))
		patchPath := filepath.Join(p.patchDir, fileName)

		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("--- a/%s\n+++ b/%s\n@@ -%d,%d +%d,%d @@\n",
			fix.Finding.GetFile(), fix.Finding.GetFile(),
			fix.Finding.LineStart, fix.Finding.LineEnd-fix.Finding.LineStart+1,
			fix.Finding.LineStart, len(strings.Split(fix.FixedCode, "\n")),
		))

		for _, line := range strings.Split(fix.OriginalCode, "\n") {
			if strings.TrimSpace(line) != "" {
				sb.WriteString("-" + line + "\n")
			}
		}
		for _, line := range strings.Split(fix.FixedCode, "\n") {
			sb.WriteString("+" + line + "\n")
		}

		if err := os.WriteFile(patchPath, []byte(sb.String()), 0644); err != nil {
			return fmt.Errorf("writing patch file %s: %w", patchPath, err)
		}
	}

	return nil
}
