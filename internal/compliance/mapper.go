package compliance

import (
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"

	"github.com/abdma/fixiac/internal/scanner"
	"gopkg.in/yaml.v3"
)

//go:embed configs/frameworks/*.yaml configs/mappings/*.yaml
var embeddedConfigs embed.FS

// Mapper manages compliance frameworks and maps scanner findings to controls.
type Mapper struct {
	frameworks map[string]*Framework
	mappings   map[string]*RuleMapping // ruleID -> mapping
}

// NewMapper loads embedded compliance frameworks and rule mappings.
func NewMapper() *Mapper {
	m, _ := NewMapperWithError()
	return m
}

// NewMapperWithError loads embedded compliance frameworks and rule mappings and returns an error if any.
func NewMapperWithError() (*Mapper, error) {
	m := &Mapper{
		frameworks: make(map[string]*Framework),
		mappings:   make(map[string]*RuleMapping),
	}

	if err := m.loadEmbedded(); err != nil {
		return nil, fmt.Errorf("failed to load compliance configs: %w", err)
	}

	return m, nil
}

func (m *Mapper) loadEmbedded() error {
	// Load frameworks
	fwEntries, err := fs.ReadDir(embeddedConfigs, "configs/frameworks")
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	for _, entry := range fwEntries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".yaml" && filepath.Ext(entry.Name()) != ".yml" {
			continue
		}
		data, err := embeddedConfigs.ReadFile("configs/frameworks/" + entry.Name())
		if err != nil {
			return fmt.Errorf("reading framework %s: %w", entry.Name(), err)
		}
		var fw Framework
		if err := yaml.Unmarshal(data, &fw); err != nil {
			return fmt.Errorf("parsing framework %s: %w", entry.Name(), err)
		}
		if fw.ID != "" {
			m.frameworks[strings.ToLower(fw.ID)] = &fw
		}
	}

	// Load mappings
	mapEntries, err := fs.ReadDir(embeddedConfigs, "configs/mappings")
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	for _, entry := range mapEntries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".yaml" && filepath.Ext(entry.Name()) != ".yml" {
			continue
		}
		data, err := embeddedConfigs.ReadFile("configs/mappings/" + entry.Name())
		if err != nil {
			return fmt.Errorf("reading mapping %s: %w", entry.Name(), err)
		}

		// First try unmarshaling as a top-level slice
		var list []RuleMapping
		if err := yaml.Unmarshal(data, &list); err == nil && len(list) > 0 {
			for i := range list {
				rm := list[i]
				if rm.RuleID != "" {
					m.mappings[strings.ToUpper(rm.RuleID)] = &rm
				}
			}
			continue
		}

		// Next try unmarshaling as struct containing mappings field
		var wrapper struct {
			Mappings []RuleMapping `yaml:"mappings"`
		}
		if err := yaml.Unmarshal(data, &wrapper); err == nil && len(wrapper.Mappings) > 0 {
			for i := range wrapper.Mappings {
				rm := wrapper.Mappings[i]
				if rm.RuleID != "" {
					m.mappings[strings.ToUpper(rm.RuleID)] = &rm
				}
			}
		}
	}

	return nil
}

// MapFinding returns the compliance controls associated with a scanner rule ID.
func (m *Mapper) MapFinding(ruleID string) []scanner.FrameworkControl {
	ruleID = strings.ToUpper(strings.TrimSpace(ruleID))
	mapping, ok := m.mappings[ruleID]
	if !ok {
		return nil
	}

	var controls []scanner.FrameworkControl
	for _, ref := range mapping.Controls {
		fwID := strings.ToLower(ref.Framework)
		fc := scanner.FrameworkControl{
			Framework: ref.Framework,
			ControlID: ref.ControlID,
		}

		if fw, exists := m.frameworks[fwID]; exists {
			for _, ctrl := range fw.Controls {
				if strings.EqualFold(ctrl.ID, ref.ControlID) {
					fc.Description = ctrl.Description
					if fc.Framework == "" {
						fc.Framework = fw.Name
					}
					break
				}
			}
		}

		if fc.Description == "" {
			fc.Description = mapping.Description
		}

		controls = append(controls, fc)
	}

	return controls
}

// GetFramework returns a compliance framework by its ID (e.g. "cis_aws").
func (m *Mapper) GetFramework(id string) *Framework {
	return m.frameworks[strings.ToLower(strings.TrimSpace(id))]
}

// ListFrameworks returns all loaded framework IDs sorted alphabetically.
func (m *Mapper) ListFrameworks() []string {
	ids := make([]string, 0, len(m.frameworks))
	for id := range m.frameworks {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// FilterByFramework returns only findings that map to the specified framework.
func (m *Mapper) FilterByFramework(findings []scanner.Finding, framework string) []scanner.Finding {
	if framework == "" || strings.EqualFold(framework, "all") {
		return findings
	}

	targetFW := strings.ToLower(strings.TrimSpace(framework))
	var filtered []scanner.Finding
	for _, f := range findings {
		mapped := m.MapFinding(f.RuleID)
		if len(f.FrameworkControls) > 0 {
			mapped = append(mapped, f.FrameworkControls...)
		}
		for _, ctrl := range mapped {
			if strings.EqualFold(ctrl.Framework, targetFW) {
				fCopy := f
				fCopy.FrameworkControls = mapped
				filtered = append(filtered, fCopy)
				break
			}
		}
	}
	return filtered
}
