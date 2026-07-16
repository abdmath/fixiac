package context

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/hashicorp/hcl/v2/hclwrite"
)

// resourceRefPattern matches Terraform resource references like:
// aws_instance.web.id or module.vpc.vpc_id
var resourceRefPattern = regexp.MustCompile(`\b([a-z][a-z0-9_]*\.[a-z][a-z0-9_]*)\.[a-z][a-z0-9_]*\b`)

// BuildDependencyGraph parses all resource blocks in .tf files under dir,
// scans attribute values for references to other resources, and builds a
// bidirectional dependency graph.
func BuildDependencyGraph(dir string) (*DependencyGraph, error) {
	tfFiles, err := findTFFiles(dir)
	if err != nil {
		return nil, fmt.Errorf("finding .tf files: %w", err)
	}

	graph := &DependencyGraph{
		Nodes: make(map[string]*ResourceNode),
	}

	// First pass: collect all resource declarations.
	type rawResource struct {
		key      string
		node     *ResourceNode
		rawAttrs string // raw attribute text for reference scanning
	}

	var resources []rawResource
	for _, path := range tfFiles {
		raws, err := extractResourcesForGraph(path, dir)
		if err != nil {
			continue
		}
		for _, r := range raws {
			graph.Nodes[r.key] = r.node
			resources = append(resources, r)
		}
	}

	// Second pass: scan attribute values for references.
	knownResources := make(map[string]bool, len(graph.Nodes))
	for key := range graph.Nodes {
		knownResources[key] = true
	}

	for _, r := range resources {
		refs := findResourceReferences(r.rawAttrs, knownResources)
		for _, ref := range refs {
			if ref == r.key {
				continue // skip self-references
			}
			r.node.DependsOn = appendUnique(r.node.DependsOn, ref)
			if target, ok := graph.Nodes[ref]; ok {
				target.ReferencedBy = appendUnique(target.ReferencedBy, r.key)
			}
		}
	}

	return graph, nil
}

// BlastRadius returns all directly and transitively dependent resources
// (i.e., resources that reference the given resource, directly or indirectly).
func (g *DependencyGraph) BlastRadius(resource string) []string {
	if g == nil || g.Nodes == nil {
		return nil
	}

	node, ok := g.Nodes[resource]
	if !ok {
		return nil
	}

	visited := make(map[string]bool)
	var result []string
	queue := make([]string, len(node.ReferencedBy))
	copy(queue, node.ReferencedBy)

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		if visited[current] {
			continue
		}
		visited[current] = true
		result = append(result, current)

		if n, ok := g.Nodes[current]; ok {
			for _, ref := range n.ReferencedBy {
				if !visited[ref] {
					queue = append(queue, ref)
				}
			}
		}
	}

	return result
}

// DependsOn returns all resources that the given resource directly and
// transitively depends on.
func (g *DependencyGraph) DependsOn(resource string) []string {
	if g == nil || g.Nodes == nil {
		return nil
	}

	node, ok := g.Nodes[resource]
	if !ok {
		return nil
	}

	visited := make(map[string]bool)
	var result []string
	queue := make([]string, len(node.DependsOn))
	copy(queue, node.DependsOn)

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		if visited[current] {
			continue
		}
		visited[current] = true
		result = append(result, current)

		if n, ok := g.Nodes[current]; ok {
			for _, dep := range n.DependsOn {
				if !visited[dep] {
					queue = append(queue, dep)
				}
			}
		}
	}

	return result
}

// extractResourcesForGraph parses a .tf file and returns raw resource data
// for graph construction.
func extractResourcesForGraph(path, rootDir string) ([]struct {
	key      string
	node     *ResourceNode
	rawAttrs string
}, error) {
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

	type rawRes struct {
		key      string
		node     *ResourceNode
		rawAttrs string
	}

	var results []rawRes
	for _, block := range file.Body().Blocks() {
		if block.Type() != "resource" {
			continue
		}

		labels := block.Labels()
		if len(labels) < 2 {
			continue
		}

		key := labels[0] + "." + labels[1]
		node := &ResourceNode{
			Type: labels[0],
			Name: labels[1],
			File: relPath,
		}

		// Collect all attribute text for reference scanning.
		rawAttrs := collectBlockTokenText(block)

		results = append(results, rawRes{
			key:      key,
			node:     node,
			rawAttrs: rawAttrs,
		})
	}

	// Convert to the return type.
	ret := make([]struct {
		key      string
		node     *ResourceNode
		rawAttrs string
	}, len(results))
	for i, r := range results {
		ret[i].key = r.key
		ret[i].node = r.node
		ret[i].rawAttrs = r.rawAttrs
	}

	return ret, nil
}

// collectBlockTokenText collects all tokens from a block's body as text,
// for reference pattern scanning.
func collectBlockTokenText(block *hclwrite.Block) string {
	tokens := block.Body().BuildTokens(nil)
	var sb strings.Builder
	for _, t := range tokens {
		sb.Write(t.Bytes)
	}
	return sb.String()
}

// findResourceReferences scans text for resource reference patterns
// (type.name.attribute) and returns matching known resource keys.
func findResourceReferences(text string, known map[string]bool) []string {
	matches := resourceRefPattern.FindAllStringSubmatch(text, -1)

	seen := make(map[string]bool)
	var refs []string

	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		ref := m[1]
		if known[ref] && !seen[ref] {
			seen[ref] = true
			refs = append(refs, ref)
		}
	}

	return refs
}

// appendUnique appends val to slice only if it is not already present.
func appendUnique(slice []string, val string) []string {
	for _, s := range slice {
		if s == val {
			return slice
		}
	}
	return append(slice, val)
}
