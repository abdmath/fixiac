package context

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hashicorp/hcl/v2/hclwrite"
)

// ExtractVariables reads all .tf files in dir to find variable blocks,
// and reads .tfvars files to resolve actual values.
func ExtractVariables(dir string) ([]Variable, error) {
	tfFiles, err := findTFFiles(dir)
	if err != nil {
		return nil, fmt.Errorf("finding .tf files: %w", err)
	}

	// First pass: extract variable declarations from .tf files.
	var variables []Variable
	for _, path := range tfFiles {
		vars, err := extractVariablesFromFile(path, dir)
		if err != nil {
			return nil, fmt.Errorf("extracting variables from %s: %w", path, err)
		}
		variables = append(variables, vars...)
	}

	// Second pass: read .tfvars for actual values.
	tfvarsFiles, err := findTFVarsFiles(dir)
	if err != nil {
		return nil, fmt.Errorf("finding .tfvars files: %w", err)
	}

	values := make(map[string]string)
	for _, path := range tfvarsFiles {
		fileValues, err := extractTFVarsValues(path)
		if err != nil {
			// Non-fatal: continue with partial values.
			continue
		}
		for k, v := range fileValues {
			values[k] = v
		}
	}

	// Merge values into variables.
	for i := range variables {
		if val, ok := values[variables[i].Name]; ok {
			variables[i].Value = val
		}
	}

	return variables, nil
}

// extractVariablesFromFile parses a single .tf file and returns its variable blocks.
func extractVariablesFromFile(path, rootDir string) ([]Variable, error) {
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

	var variables []Variable
	for _, block := range file.Body().Blocks() {
		if block.Type() != "variable" {
			continue
		}

		labels := block.Labels()
		if len(labels) == 0 {
			continue
		}

		v := Variable{
			Name: labels[0],
			File: relPath,
		}

		body := block.Body()

		if attr := body.GetAttribute("type"); attr != nil {
			v.Type = extractTokenValue(attr)
		}

		if attr := body.GetAttribute("default"); attr != nil {
			v.Default = extractTokenValue(attr)
		}

		if attr := body.GetAttribute("description"); attr != nil {
			v.Description = extractTokenValue(attr)
		}

		variables = append(variables, v)
	}

	return variables, nil
}

// extractTFVarsValues parses a .tfvars file and returns a map of name -> value.
func extractTFVarsValues(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading tfvars file: %w", err)
	}

	file, diags := hclwrite.ParseConfig(data, path, hclPos())
	if diags.HasErrors() {
		return nil, fmt.Errorf("parsing tfvars HCL: %s", diags.Error())
	}

	values := make(map[string]string)
	for name, attr := range file.Body().Attributes() {
		values[name] = extractTokenValue(attr)
	}

	return values, nil
}

// extractTokenValue extracts the raw text value of an HCL attribute by
// reading its expression tokens. It strips quotes from string literals.
func extractTokenValue(attr *hclwrite.Attribute) string {
	tokens := attr.Expr().BuildTokens(nil)
	var sb strings.Builder
	for _, t := range tokens {
		sb.Write(t.Bytes)
	}
	val := strings.TrimSpace(sb.String())
	// Strip surrounding quotes if present.
	if len(val) >= 2 && val[0] == '"' && val[len(val)-1] == '"' {
		val = val[1 : len(val)-1]
	}
	return val
}
