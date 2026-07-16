package context

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hashicorp/hcl/v2/hclwrite"
)

// ExtractModules finds all module blocks in .tf files under dir and returns
// their metadata including source, version, and inputs.
func ExtractModules(dir string) ([]ModuleUsage, error) {
	tfFiles, err := findTFFiles(dir)
	if err != nil {
		return nil, fmt.Errorf("finding .tf files: %w", err)
	}

	var modules []ModuleUsage
	for _, path := range tfFiles {
		mods, err := extractModulesFromFile(path, dir)
		if err != nil {
			// Non-fatal: skip files that fail to parse.
			continue
		}
		modules = append(modules, mods...)
	}

	return modules, nil
}

// extractModulesFromFile parses a single .tf file and returns its module blocks.
func extractModulesFromFile(path, rootDir string) ([]ModuleUsage, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}

	file, diags := hclwrite.ParseConfig(data, path, hclPos())
	if diags.HasErrors() {
		return nil, fmt.Errorf("parsing HCL: %s", diags.Error())
	}

	relPath, err := filepath.Rel(rootDir, path)
	if err != nil {
		relPath = path
	}
	relPath = filepath.ToSlash(relPath)

	var modules []ModuleUsage
	for _, block := range file.Body().Blocks() {
		if block.Type() != "module" {
			continue
		}

		labels := block.Labels()
		if len(labels) == 0 {
			continue
		}

		m := ModuleUsage{
			Name:   labels[0],
			File:   relPath,
			Inputs: make(map[string]string),
		}

		body := block.Body()

		// Extract known attributes.
		if attr := body.GetAttribute("source"); attr != nil {
			m.Source = extractTokenValue(attr)
		}

		if attr := body.GetAttribute("version"); attr != nil {
			m.Version = extractTokenValue(attr)
		}

		// Detect local modules.
		m.IsLocal = strings.HasPrefix(m.Source, "./") || strings.HasPrefix(m.Source, "../")

		// Extract all other attributes as inputs.
		for name, attr := range body.Attributes() {
			if name == "source" || name == "version" || name == "providers" {
				continue
			}
			m.Inputs[name] = extractTokenValue(attr)
		}

		modules = append(modules, m)
	}

	return modules, nil
}
