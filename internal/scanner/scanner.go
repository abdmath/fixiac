// Package scanner provides a unified interface for running multiple Terraform
// security scanning tools and merging their results.
package scanner

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// Scanner is the interface that detection backends implement.
// Each scanner wraps an external tool (e.g. checkov, trivy) and converts
// its output into a normalized []Finding slice.
type Scanner interface {
	// Name returns the human-readable name of the scanner.
	Name() string
	// Available reports whether the scanner's underlying tool is installed
	// and reachable on the current system.
	Available() bool
	// Scan runs the scanner against the given directory and returns any
	// security findings. The context can be used for cancellation/timeouts.
	Scan(ctx context.Context, dir string) ([]Finding, error)
}

// MultiScanner runs multiple scanners and merges/deduplicates their findings.
type MultiScanner struct {
	scanners []Scanner
}

// NewMultiScanner creates a MultiScanner from the provided scanners.
// Scanners that are not available are silently skipped during scans.
func NewMultiScanner(scanners ...Scanner) *MultiScanner {
	return &MultiScanner{scanners: scanners}
}

// Scan executes all available scanners against dir, merges results, deduplicates
// overlapping findings, and returns the sorted result set.
// If all scanners fail the first encountered error is returned.
// If at least one scanner succeeds, partial results are returned without error.
func (ms *MultiScanner) Scan(ctx context.Context, dir string) ([]Finding, error) {
	var (
		allFindings []Finding
		firstErr    error
		anySuccess  bool
	)

	for _, s := range ms.scanners {
		if !s.Available() {
			continue
		}

		findings, err := s.Scan(ctx, dir)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("scanner %s: %w", s.Name(), err)
			}
			continue
		}

		anySuccess = true
		allFindings = append(allFindings, findings...)
	}

	if !anySuccess && firstErr != nil {
		return nil, firstErr
	}

	deduped := deduplicateFindings(allFindings)
	sortFindings(deduped)

	return deduped, nil
}

// severityRank returns a numeric rank for severity, higher means more severe.
func severityRank(sev Severity) int {
	return sev.Weight()
}

// dedupKey builds a deduplication key from the finding's resource and file.
func dedupKey(f Finding) string {
	return f.Resource + "|" + f.File
}

// descriptionsOverlap checks whether two descriptions are overlapping by
// testing if one is a substring of the other, or if they share significant
// common content (>60% word overlap).
func descriptionsOverlap(a, b string) bool {
	la := strings.ToLower(a)
	lb := strings.ToLower(b)

	if strings.Contains(la, lb) || strings.Contains(lb, la) {
		return true
	}

	wordsA := strings.Fields(la)
	wordsB := strings.Fields(lb)
	if len(wordsA) == 0 || len(wordsB) == 0 {
		return false
	}

	wordSet := make(map[string]struct{}, len(wordsA))
	for _, w := range wordsA {
		wordSet[w] = struct{}{}
	}

	overlap := 0
	for _, w := range wordsB {
		if _, ok := wordSet[w]; ok {
			overlap++
		}
	}

	minLen := len(wordsA)
	if len(wordsB) < minLen {
		minLen = len(wordsB)
	}

	return float64(overlap)/float64(minLen) > 0.6
}

// deduplicateFindings removes duplicate findings. Two findings are considered
// duplicates if they share the same resource, the same file, and have
// overlapping descriptions. The finding with higher severity is kept.
func deduplicateFindings(findings []Finding) []Finding {
	if len(findings) == 0 {
		return findings
	}

	// Group by resource+file key.
	type group struct {
		findings []Finding
	}
	groups := make(map[string]*group)
	var order []string

	for _, f := range findings {
		key := dedupKey(f)
		g, ok := groups[key]
		if !ok {
			g = &group{}
			groups[key] = g
			order = append(order, key)
		}
		g.findings = append(g.findings, f)
	}

	var result []Finding
	for _, key := range order {
		g := groups[key]
		kept := deduplicateGroup(g.findings)
		result = append(result, kept...)
	}

	return result
}

// deduplicateGroup deduplicates findings within the same resource+file group.
func deduplicateGroup(findings []Finding) []Finding {
	if len(findings) <= 1 {
		return findings
	}

	// Sort by severity descending so the highest severity is checked first.
	sort.Slice(findings, func(i, j int) bool {
		return severityRank(findings[i].Severity) > severityRank(findings[j].Severity)
	})

	var kept []Finding
	removed := make(map[int]bool)

	for i := 0; i < len(findings); i++ {
		if removed[i] {
			continue
		}
		for j := i + 1; j < len(findings); j++ {
			if removed[j] {
				continue
			}
			if descriptionsOverlap(findings[i].Description, findings[j].Description) {
				// Keep the higher severity one (index i, since sorted desc).
				removed[j] = true
			}
		}
		kept = append(kept, findings[i])
	}

	return kept
}

// sortFindings sorts findings by severity (CRITICAL first), then by file
// path, then by line number.
func sortFindings(findings []Finding) {
	sort.Slice(findings, func(i, j int) bool {
		ri := severityRank(findings[i].Severity)
		rj := severityRank(findings[j].Severity)
		if ri != rj {
			return ri > rj
		}
		if findings[i].File != findings[j].File {
			return findings[i].File < findings[j].File
		}
		return findings[i].LineStart < findings[j].LineStart
	})
}
