package context

import (
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/hcl/v2/hclwrite"
)

// DetectConventions reads all resource block names in .tf files under dir
// and detects the dominant naming convention.
func DetectConventions(dir string) (*NamingConventions, error) {
	tfFiles, err := findTFFiles(dir)
	if err != nil {
		return nil, fmt.Errorf("finding .tf files: %w", err)
	}

	var resourceNames []string
	for _, path := range tfFiles {
		names, err := extractResourceNames(path)
		if err != nil {
			continue
		}
		resourceNames = append(resourceNames, names...)
	}

	if len(resourceNames) == 0 {
		return &NamingConventions{
			Confidence: 0,
		}, nil
	}

	return analyzeNamingConventions(resourceNames), nil
}

// extractResourceNames returns all resource block label names from a .tf file.
func extractResourceNames(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}

	file, diags := hclwrite.ParseConfig(data, path, hclPos())
	if diags.HasErrors() {
		return nil, fmt.Errorf("parsing HCL: %s", diags.Error())
	}

	var names []string
	for _, block := range file.Body().Blocks() {
		if block.Type() != "resource" {
			continue
		}
		labels := block.Labels()
		if len(labels) >= 2 {
			names = append(names, labels[1]) // resource name is the second label
		}
	}

	return names, nil
}

// analyzeNamingConventions examines resource names and detects the dominant pattern.
func analyzeNamingConventions(names []string) *NamingConventions {
	conv := &NamingConventions{}

	// Count separator usage.
	hyphenCount := 0
	underscoreCount := 0
	usesVarsCount := 0

	for _, name := range names {
		if strings.Contains(name, "-") {
			hyphenCount++
		}
		if strings.Contains(name, "_") {
			underscoreCount++
		}
		// Check for variable interpolation patterns: var. or local.
		if strings.Contains(name, "var.") || strings.Contains(name, "local.") ||
			strings.Contains(name, "${") {
			usesVarsCount++
		}
	}

	// Determine dominant separator.
	// Note: Terraform resource names can only use underscores in the resource
	// name label, but the naming convention might refer to the "name" attribute
	// value patterns. We check both.
	if hyphenCount > underscoreCount {
		conv.Separator = "-"
	} else if underscoreCount > 0 {
		conv.Separator = "_"
	} else {
		conv.Separator = "_" // default for Terraform
	}

	conv.UsesVars = usesVarsCount > len(names)/2

	// Detect common patterns by analyzing name segments.
	conv.Pattern = detectPattern(names, conv.Separator)
	conv.Confidence = calculateConfidence(names, conv.Separator)

	// Collect examples (up to 5).
	maxExamples := 5
	if len(names) < maxExamples {
		maxExamples = len(names)
	}
	conv.Examples = make([]string, maxExamples)
	copy(conv.Examples, names[:maxExamples])

	return conv
}

// detectPattern analyzes names split by separator and builds a pattern string.
func detectPattern(names []string, sep string) string {
	if len(names) == 0 {
		return ""
	}

	// Count segment lengths.
	segmentCounts := make(map[int]int)
	for _, name := range names {
		parts := strings.Split(name, sep)
		segmentCounts[len(parts)]++
	}

	// Find the most common segment count.
	maxCount := 0
	dominantSegments := 1
	for segs, count := range segmentCounts {
		if count > maxCount {
			maxCount = count
			dominantSegments = segs
		}
	}

	// Collect names with the dominant segment count.
	var matching []string
	for _, name := range names {
		parts := strings.Split(name, sep)
		if len(parts) == dominantSegments {
			matching = append(matching, name)
		}
	}

	// Analyze each segment position for common prefixes/labels.
	if dominantSegments == 1 {
		return "{name}"
	}

	patternParts := make([]string, dominantSegments)
	for i := 0; i < dominantSegments; i++ {
		label := analyzeSegment(matching, sep, i)
		patternParts[i] = "{" + label + "}"
	}

	return strings.Join(patternParts, sep)
}

// analyzeSegment looks at the i-th segment across all names and tries to
// identify what it represents.
func analyzeSegment(names []string, sep string, idx int) string {
	values := make(map[string]int)
	for _, name := range names {
		parts := strings.Split(name, sep)
		if idx < len(parts) {
			values[parts[idx]]++
		}
	}

	// If all values are the same, it's a fixed prefix.
	if len(values) == 1 {
		for v := range values {
			return v
		}
	}

	// Check if values match common patterns.
	envKeywords := map[string]bool{
		"dev": true, "staging": true, "prod": true, "production": true,
		"test": true, "qa": true, "uat": true, "sandbox": true,
	}

	typeKeywords := map[string]bool{
		"sg": true, "vpc": true, "subnet": true, "ec2": true, "rds": true,
		"s3": true, "iam": true, "lambda": true, "alb": true, "nlb": true,
		"ecs": true, "eks": true, "db": true, "cache": true, "queue": true,
	}

	envMatch := 0
	typeMatch := 0
	for v, count := range values {
		if envKeywords[strings.ToLower(v)] {
			envMatch += count
		}
		if typeKeywords[strings.ToLower(v)] {
			typeMatch += count
		}
	}

	total := len(names)
	if envMatch > total/2 {
		return "env"
	}
	if typeMatch > total/2 {
		return "type"
	}

	// Default labels based on position.
	switch idx {
	case 0:
		return "prefix"
	case 1:
		return "name"
	case 2:
		return "suffix"
	default:
		return fmt.Sprintf("part%d", idx+1)
	}
}

// calculateConfidence computes how consistently names follow the dominant pattern.
func calculateConfidence(names []string, sep string) float64 {
	if len(names) == 0 {
		return 0
	}

	// Count segment lengths.
	segmentCounts := make(map[int]int)
	for _, name := range names {
		parts := strings.Split(name, sep)
		segmentCounts[len(parts)]++
	}

	// Confidence = fraction of names matching the dominant pattern.
	maxCount := 0
	for _, count := range segmentCounts {
		if count > maxCount {
			maxCount = count
		}
	}

	return float64(maxCount) / float64(len(names))
}
