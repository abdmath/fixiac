package remediation

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Applier applies validated fixes directly to the target Terraform files or creates patches.
type Applier struct{}

// NewApplier creates a new Applier instance.
func NewApplier() *Applier {
	return &Applier{}
}

// Apply applies a slice of Fix pointers to their respective target files.
func (a *Applier) Apply(ctx context.Context, dir string, fixes []*Fix) error {
	for _, fix := range fixes {
		if fix == nil || fix.FixedCode == "" {
			continue
		}
		if err := a.applySingle(dir, fix); err != nil {
			return err
		}
	}
	return nil
}

// ApplyValueSlice applies a slice of Fix values to their respective target files.
func (a *Applier) ApplyValueSlice(ctx context.Context, dir string, fixes []Fix) error {
	for i := range fixes {
		if err := a.applySingle(dir, &fixes[i]); err != nil {
			return err
		}
	}
	return nil
}

func (a *Applier) applySingle(dir string, fix *Fix) error {
	filePath := fix.Finding.GetFile()
	if !filepath.IsAbs(filePath) {
		filePath = filepath.Join(dir, filePath)
	}

	contentBytes, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("reading file %s: %w", filePath, err)
	}
	content := string(contentBytes)

	if fix.IsReplacement && fix.OriginalCode != "" {
		if strings.Contains(content, fix.OriginalCode) {
			newContent := strings.Replace(content, fix.OriginalCode, fix.FixedCode, 1)
			return os.WriteFile(filePath, []byte(newContent), 0644)
		}
	}

	// If line numbers are valid, replace line range
	if fix.Finding.LineStart > 0 && fix.Finding.LineEnd >= fix.Finding.LineStart {
		lines := strings.Split(content, "\n")
		if fix.Finding.LineEnd <= len(lines) {
			var newLines []string
			newLines = append(newLines, lines[:fix.Finding.LineStart-1]...)
			newLines = append(newLines, fix.FixedCode)
			if fix.Finding.LineEnd < len(lines) {
				newLines = append(newLines, lines[fix.Finding.LineEnd:]...)
			}
			return os.WriteFile(filePath, []byte(strings.Join(newLines, "\n")), 0644)
		}
	}

	return fmt.Errorf("could not locate exact block to replace in %s", filePath)
}
