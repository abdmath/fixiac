package context

import (
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/hcl/v2/hclwrite"
)

// DetectTagStandard scans all resources in .tf files under dir for tags blocks,
// determines common tag keys and value patterns.
func DetectTagStandard(dir string) (*TagStandard, error) {
	tfFiles, err := findTFFiles(dir)
	if err != nil {
		return nil, fmt.Errorf("finding .tf files: %w", err)
	}

	totalResources := 0
	taggedResources := 0
	// keyFreq tracks how many tagged resources use each tag key.
	keyFreq := make(map[string]int)
	// keyValues tracks sample values for each tag key for pattern detection.
	keyValues := make(map[string][]string)

	for _, path := range tfFiles {
		resources, err := extractTagsFromFile(path)
		if err != nil {
			continue
		}
		for _, res := range resources {
			totalResources++
			if len(res.tags) > 0 {
				taggedResources++
				for key, val := range res.tags {
					keyFreq[key]++
					keyValues[key] = append(keyValues[key], val)
				}
			}
		}
	}

	standard := &TagStandard{
		Template: make(map[string]string),
	}

	if totalResources == 0 {
		standard.Coverage = 0
		return standard, nil
	}

	standard.Coverage = float64(taggedResources) / float64(totalResources)

	// Keys appearing in >50% of tagged resources are "common".
	threshold := taggedResources / 2
	if threshold == 0 {
		threshold = 1
	}

	for key, freq := range keyFreq {
		if freq >= threshold {
			standard.CommonKeys = append(standard.CommonKeys, key)
		}
	}

	// Detect value patterns for common keys.
	for _, key := range standard.CommonKeys {
		values := keyValues[key]
		standard.Template[key] = detectValuePattern(values)
	}

	return standard, nil
}

// resourceTags holds tag data extracted from a single resource block.
type resourceTags struct {
	resourceType string
	resourceName string
	tags         map[string]string
}

// extractTagsFromFile parses a .tf file and returns tag data for each resource.
func extractTagsFromFile(path string) ([]resourceTags, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}

	file, diags := hclwrite.ParseConfig(data, path, hclPos())
	if diags.HasErrors() {
		return nil, fmt.Errorf("parsing HCL: %s", diags.Error())
	}

	var results []resourceTags
	for _, block := range file.Body().Blocks() {
		if block.Type() != "resource" {
			continue
		}

		labels := block.Labels()
		if len(labels) < 2 {
			continue
		}

		res := resourceTags{
			resourceType: labels[0],
			resourceName: labels[1],
			tags:         make(map[string]string),
		}

		body := block.Body()

		// Check for "tags" attribute (map literal).
		if attr := body.GetAttribute("tags"); attr != nil {
			res.tags = extractMapTokenValues(attr)
		}

		// Check for nested "tags" block (less common but possible).
		for _, nested := range body.Blocks() {
			if nested.Type() == "tags" {
				for name, attr := range nested.Body().Attributes() {
					res.tags[name] = extractTokenValue(attr)
				}
			}
		}

		results = append(results, res)
	}

	return results, nil
}

// extractMapTokenValues extracts key-value pairs from an attribute that holds
// a map expression, by parsing the raw tokens.
func extractMapTokenValues(attr *hclwrite.Attribute) map[string]string {
	tokens := attr.Expr().BuildTokens(nil)
	raw := tokensToString(tokens)

	result := make(map[string]string)

	// Strip outer braces if present.
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(raw, "{") && strings.HasSuffix(raw, "}") {
		raw = raw[1 : len(raw)-1]
	}

	// Parse key = value pairs, handling quoted strings.
	lines := strings.Split(raw, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}

		// Split on first "=".
		eqIdx := strings.Index(line, "=")
		if eqIdx == -1 {
			continue
		}

		key := strings.TrimSpace(line[:eqIdx])
		val := strings.TrimSpace(line[eqIdx+1:])

		// Strip trailing comma.
		val = strings.TrimRight(val, ",")
		val = strings.TrimSpace(val)

		// Strip quotes from key and value.
		key = strings.Trim(key, "\"")
		if len(val) >= 2 && val[0] == '"' && val[len(val)-1] == '"' {
			val = val[1 : len(val)-1]
		}

		if key != "" {
			result[key] = val
		}
	}

	return result
}

// tokensToString converts HCL write tokens back to a string.
func tokensToString(tokens hclwrite.Tokens) string {
	var sb strings.Builder
	for _, t := range tokens {
		sb.Write(t.Bytes)
	}
	return sb.String()
}

// detectValuePattern analyzes a set of tag values and returns a pattern string.
func detectValuePattern(values []string) string {
	if len(values) == 0 {
		return ""
	}

	varRefCount := 0
	literalValues := make(map[string]int)

	for _, v := range values {
		if strings.Contains(v, "var.") || strings.Contains(v, "local.") || strings.Contains(v, "${") {
			varRefCount++
		} else {
			literalValues[v]++
		}
	}

	// Majority are variable references.
	if varRefCount > len(values)/2 {
		return "var_reference"
	}

	// All the same literal.
	if len(literalValues) == 1 {
		for v := range literalValues {
			return fmt.Sprintf("literal:%s", v)
		}
	}

	// Mixed.
	return "mixed"
}
