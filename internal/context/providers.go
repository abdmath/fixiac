package context

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hashicorp/hcl/v2/hclwrite"
)

// ExtractProviders parses provider blocks and terraform blocks from .tf files
// under dir and returns the provider configurations and terraform config.
func ExtractProviders(dir string) ([]ProviderConfig, *TerraformConfig, error) {
	tfFiles, err := findTFFiles(dir)
	if err != nil {
		return nil, nil, fmt.Errorf("finding .tf files: %w", err)
	}

	var providers []ProviderConfig
	tfConfig := &TerraformConfig{
		RequiredProviders: make(map[string]string),
	}

	for _, path := range tfFiles {
		p, tc, err := extractProvidersFromFile(path, dir)
		if err != nil {
			// Non-fatal: skip files that fail to parse.
			continue
		}
		providers = append(providers, p...)
		mergeTerraformConfig(tfConfig, tc)
	}

	return providers, tfConfig, nil
}

// extractProvidersFromFile parses a single .tf file for provider and
// terraform blocks.
func extractProvidersFromFile(path, rootDir string) ([]ProviderConfig, *TerraformConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("reading file: %w", err)
	}

	file, diags := hclwrite.ParseConfig(data, path, hclPos())
	if diags.HasErrors() {
		return nil, nil, fmt.Errorf("parsing HCL: %s", diags.Error())
	}

	relPath, err := filepath.Rel(rootDir, path)
	if err != nil {
		relPath = path
	}
	relPath = filepath.ToSlash(relPath)

	var providers []ProviderConfig
	tfConfig := &TerraformConfig{
		RequiredProviders: make(map[string]string),
	}

	for _, block := range file.Body().Blocks() {
		switch block.Type() {
		case "provider":
			p := parseProviderBlock(block, relPath)
			providers = append(providers, p)
		case "terraform":
			parseTerraformBlock(block, tfConfig)
		}
	}

	return providers, tfConfig, nil
}

// parseProviderBlock extracts configuration from a provider block.
func parseProviderBlock(block *hclwrite.Block, file string) ProviderConfig {
	labels := block.Labels()
	p := ProviderConfig{
		File: file,
	}
	if len(labels) > 0 {
		p.Name = labels[0]
	}

	body := block.Body()

	if attr := body.GetAttribute("region"); attr != nil {
		p.Region = extractTokenValue(attr)
	}

	if attr := body.GetAttribute("alias"); attr != nil {
		p.Alias = extractTokenValue(attr)
	}

	if attr := body.GetAttribute("version"); attr != nil {
		p.Version = extractTokenValue(attr)
	}

	return p
}

// parseTerraformBlock extracts configuration from a terraform block.
func parseTerraformBlock(block *hclwrite.Block, cfg *TerraformConfig) {
	body := block.Body()

	if attr := body.GetAttribute("required_version"); attr != nil {
		cfg.RequiredVersion = extractTokenValue(attr)
	}

	// Parse nested blocks: backend and required_providers.
	for _, nested := range body.Blocks() {
		switch nested.Type() {
		case "backend":
			labels := nested.Labels()
			if len(labels) > 0 {
				cfg.Backend = labels[0]
			}
		case "required_providers":
			nestedBody := nested.Body()
			for name, attr := range nestedBody.Attributes() {
				val := extractTokenValue(attr)
				// Try to extract version from the object expression.
				// e.g., { source = "hashicorp/aws", version = "~> 5.0" }
				if versionStr := extractVersionFromProviderExpr(val); versionStr != "" {
					cfg.RequiredProviders[name] = versionStr
				} else {
					cfg.RequiredProviders[name] = val
				}
			}
		}
	}
}

// extractVersionFromProviderExpr tries to extract a version string from
// a required_providers attribute expression like:
// { source = "hashicorp/aws" version = "~> 5.0" }
func extractVersionFromProviderExpr(expr string) string {
	// Look for version = "..." pattern in the expression.
	idx := strings.Index(expr, "version")
	if idx == -1 {
		return ""
	}

	rest := expr[idx+len("version"):]
	rest = strings.TrimLeft(rest, " =")

	// Find quoted version string.
	if len(rest) > 0 && rest[0] == '"' {
		end := strings.Index(rest[1:], "\"")
		if end != -1 {
			return rest[1 : end+1]
		}
	}

	return ""
}

// mergeTerraformConfig merges a source TerraformConfig into a destination.
func mergeTerraformConfig(dst, src *TerraformConfig) {
	if src == nil {
		return
	}
	if src.RequiredVersion != "" {
		dst.RequiredVersion = src.RequiredVersion
	}
	if src.Backend != "" {
		dst.Backend = src.Backend
	}
	for k, v := range src.RequiredProviders {
		dst.RequiredProviders[k] = v
	}
}
