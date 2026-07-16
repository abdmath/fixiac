// Package context provides Terraform codebase context analysis types and utilities.
package context

import (
	"github.com/hashicorp/hcl/v2"
)

// Variable represents a Terraform variable defined in the codebase and its resolved value.
type Variable struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Default     string `json:"default,omitempty"`
	Description string `json:"description,omitempty"`
	Value       string `json:"value,omitempty"` // actual value from .tfvars
	File        string `json:"file"`
	Sensitive   bool   `json:"sensitive,omitempty"`
}

// ModuleUsage represents a Terraform module reference found in the codebase.
type ModuleUsage struct {
	Name    string            `json:"name"`
	Source  string            `json:"source"`
	Version string            `json:"version,omitempty"`
	File    string            `json:"file"`
	Inputs  map[string]string `json:"inputs,omitempty"`
	IsLocal bool              `json:"is_local,omitempty"`
}

// NamingConventions describes the detected naming patterns in the codebase.
type NamingConventions struct {
	Pattern        string   `json:"pattern,omitempty"`    // detected pattern like "{env}-{project}-{type}"
	Separator      string   `json:"separator,omitempty"`  // "-" or "_"
	UsesVars       bool     `json:"uses_vars,omitempty"`  // references variables in names
	Confidence     float64  `json:"confidence"`           // 0-1
	Examples       []string `json:"examples,omitempty"`
	ResourcePrefix string   `json:"resource_prefix,omitempty"`
	ResourceSuffix string   `json:"resource_suffix,omitempty"`
	CaseStyle      string   `json:"case_style,omitempty"`
}

// ProviderConfig represents a Terraform provider block configuration.
type ProviderConfig struct {
	Name    string `json:"name"`
	Region  string `json:"region,omitempty"`
	Alias   string `json:"alias,omitempty"`
	Version string `json:"version,omitempty"`
	File    string `json:"file"`
}

// TerraformConfig represents the terraform {} block configuration.
type TerraformConfig struct {
	RequiredVersion   string            `json:"required_version,omitempty"`
	Backend           string            `json:"backend,omitempty"`
	RequiredProviders map[string]string `json:"required_providers,omitempty"`
}

// TagStandard describes the detected tagging standard across the codebase.
type TagStandard struct {
	CommonKeys   []string          `json:"common_keys,omitempty"`
	Template     map[string]string `json:"template,omitempty"` // key -> typical value pattern
	Coverage     float64           `json:"coverage"`           // fraction of resources with tags
	RequiredTags []string          `json:"required_tags,omitempty"`
	DefaultTags  map[string]string `json:"default_tags,omitempty"`
	TagPrefix    string            `json:"tag_prefix,omitempty"`
}

// ResourceNode represents a single Terraform resource in the dependency graph.
type ResourceNode struct {
	Type         string   `json:"type"`
	Name         string   `json:"name"`
	File         string   `json:"file"`
	DependsOn    []string `json:"depends_on,omitempty"`
	ReferencedBy []string `json:"referenced_by,omitempty"`
}

// DependencyEdge represents an edge in the Terraform resource dependency graph.
type DependencyEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Type string `json:"type"` // "explicit", "implicit"
}

// DependencyGraph holds all resource nodes and their dependency relationships.
type DependencyGraph struct {
	Nodes     map[string]*ResourceNode `json:"nodes,omitempty"` // key: "type.name"
	Edges     []DependencyEdge         `json:"edges,omitempty"`
	Resources []string                 `json:"resources,omitempty"`
	Adjacency map[string][]string      `json:"-"` // computed adjacency list
}

// Dependents returns the list of resources that directly depend on the given resource.
func (g *DependencyGraph) Dependents(resource string) []string {
	if g == nil || g.Adjacency == nil {
		return nil
	}
	return g.Adjacency[resource]
}

// AllDependents returns all resources transitively dependent on the given resource
// using breadth-first search.
func (g *DependencyGraph) AllDependents(resource string) []string {
	if g == nil || g.Adjacency == nil {
		return nil
	}
	visited := make(map[string]bool)
	queue := []string{resource}
	visited[resource] = true
	var result []string

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		for _, dep := range g.Adjacency[current] {
			if !visited[dep] {
				visited[dep] = true
				result = append(result, dep)
				queue = append(queue, dep)
			}
		}
	}
	return result
}

// CodebaseContext holds the complete analyzed context of a Terraform codebase.
type CodebaseContext struct {
	RootDir      string             `json:"root_dir"`
	Variables    []Variable         `json:"variables,omitempty"`
	Modules      []ModuleUsage      `json:"modules,omitempty"`
	Conventions  *NamingConventions `json:"conventions,omitempty"`
	Providers    []ProviderConfig   `json:"providers,omitempty"`
	Terraform    *TerraformConfig   `json:"terraform,omitempty"`
	TagStandard  *TagStandard       `json:"tag_standard,omitempty"`
	Dependencies *DependencyGraph   `json:"dependencies,omitempty"`
	FileContents map[string]string  `json:"file_contents,omitempty"`
}

// hclPos returns a default starting position for HCL parsing.
func hclPos() hcl.Pos {
	return hcl.Pos{Line: 1, Column: 1, Byte: 0}
}
