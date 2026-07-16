// Package context provides analysis of Terraform codebases, extracting
// variables, modules, conventions, providers, tags, and dependency graphs
// to build a comprehensive understanding of the infrastructure code.
package context

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Analyzer orchestrates the analysis of a Terraform codebase by running
// each sub-analyzer and assembling the results into a CodebaseContext.
type Analyzer struct{}

// NewAnalyzer creates a new Analyzer.
func NewAnalyzer() *Analyzer {
	return &Analyzer{}
}

// AnalyzeFile analyzes the parent directory of a specific file.
func (a *Analyzer) AnalyzeFile(ctx context.Context, path string) (*CodebaseContext, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolving absolute path: %w", err)
	}
	info, err := os.Stat(absPath)
	if err != nil {
		return nil, fmt.Errorf("stat file %s: %w", absPath, err)
	}
	dir := absPath
	if !info.IsDir() {
		dir = filepath.Dir(absPath)
	}
	return a.Analyze(ctx, dir)
}

// Analyze walks all .tf and .tfvars files in dir (recursively) and builds
// a comprehensive CodebaseContext by invoking each sub-analyzer.
func (a *Analyzer) Analyze(ctx context.Context, dir string) (*CodebaseContext, error) {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("resolving absolute path for %s: %w", dir, err)
	}

	info, err := os.Stat(absDir)
	if err != nil {
		return nil, fmt.Errorf("accessing directory %s: %w", absDir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", absDir)
	}

	result := &CodebaseContext{
		RootDir:      absDir,
		FileContents: make(map[string]string),
	}

	// Collect all .tf file contents.
	if err := collectFileContents(absDir, result.FileContents); err != nil {
		return nil, fmt.Errorf("collecting file contents: %w", err)
	}

	// Run sub-analyzers. Errors in individual analyzers are non-fatal;
	// we collect as much context as possible.
	var errs []string

	variables, err := ExtractVariables(absDir)
	if err != nil {
		errs = append(errs, fmt.Sprintf("variables: %v", err))
	}
	result.Variables = variables

	modules, err := ExtractModules(absDir)
	if err != nil {
		errs = append(errs, fmt.Sprintf("modules: %v", err))
	}
	result.Modules = modules

	conventions, err := DetectConventions(absDir)
	if err != nil {
		errs = append(errs, fmt.Sprintf("conventions: %v", err))
	}
	result.Conventions = conventions

	providers, tfConfig, err := ExtractProviders(absDir)
	if err != nil {
		errs = append(errs, fmt.Sprintf("providers: %v", err))
	}
	result.Providers = providers
	result.Terraform = tfConfig

	tagStandard, err := DetectTagStandard(absDir)
	if err != nil {
		errs = append(errs, fmt.Sprintf("tags: %v", err))
	}
	result.TagStandard = tagStandard

	depGraph, err := BuildDependencyGraph(absDir)
	if err != nil {
		errs = append(errs, fmt.Sprintf("dependencies: %v", err))
	}
	result.Dependencies = depGraph

	if len(errs) > 0 {
		// Return partial results with a combined error.
		return result, fmt.Errorf("partial analysis errors: %s", strings.Join(errs, "; "))
	}

	return result, nil
}

// collectFileContents walks dir recursively and reads all .tf files into the map.
func collectFileContents(dir string, contents map[string]string) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			// Skip hidden directories and .terraform.
			base := filepath.Base(path)
			if strings.HasPrefix(base, ".") && path != dir {
				return filepath.SkipDir
			}
			return nil
		}

		if !strings.HasSuffix(path, ".tf") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("reading %s: %w", path, err)
		}

		relPath, err := filepath.Rel(dir, path)
		if err != nil {
			relPath = path
		}
		contents[filepath.ToSlash(relPath)] = string(data)

		return nil
	})
}

// findTFFiles returns all .tf file paths under dir, recursively.
// It skips hidden directories and .terraform.
func findTFFiles(dir string) ([]string, error) {
	var files []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			base := filepath.Base(path)
			if strings.HasPrefix(base, ".") && path != dir {
				return filepath.SkipDir
			}
			if base == ".terraform" {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".tf") {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}

// findTFVarsFiles returns all .tfvars file paths under dir, recursively.
func findTFVarsFiles(dir string) ([]string, error) {
	var files []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			base := filepath.Base(path)
			if strings.HasPrefix(base, ".") && path != dir {
				return filepath.SkipDir
			}
			if base == ".terraform" {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".tfvars") {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}
