package suppress

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"gopkg.in/yaml.v3"
)

// suppressionFile is the filename used for the YAML-based suppression store.
const suppressionFile = ".fixiac-suppressions.yaml"

// Store is a file-backed store for finding suppressions. It persists
// suppressions as a YAML array in a well-known file inside the project
// directory.
type Store struct {
	path         string
	suppressions []Suppression
	mu           sync.Mutex
}

// NewStore creates a new Store that reads from and writes to
// <dir>/.fixiac-suppressions.yaml.
func NewStore(dir string) *Store {
	return &Store{
		path: filepath.Join(dir, suppressionFile),
	}
}

// Load reads the suppression file from disk. If the file does not exist it is
// created as an empty YAML file so subsequent operations succeed.
func (s *Store) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			s.suppressions = []Suppression{}
			return s.saveLocked()
		}
		return fmt.Errorf("reading suppression file %s: %w", s.path, err)
	}

	var sups []Suppression
	if err := yaml.Unmarshal(data, &sups); err != nil {
		return fmt.Errorf("parsing suppression file %s: %w", s.path, err)
	}
	if sups == nil {
		sups = []Suppression{}
	}
	s.suppressions = sups
	return nil
}

// Save writes the current in-memory suppressions to the YAML file on disk.
func (s *Store) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked()
}

// saveLocked is the internal save that assumes the mutex is already held.
func (s *Store) saveLocked() error {
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating suppression directory: %w", err)
	}

	data, err := yaml.Marshal(s.suppressions)
	if err != nil {
		return fmt.Errorf("marshalling suppressions: %w", err)
	}

	if err := os.WriteFile(s.path, data, 0o644); err != nil {
		return fmt.Errorf("writing suppression file %s: %w", s.path, err)
	}
	return nil
}

// Add appends a new suppression and persists the store to disk.
func (s *Store) Add(sup Suppression) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.suppressions = append(s.suppressions, sup)
	return s.saveLocked()
}

// Remove deletes the first suppression matching the given ruleID and resource,
// then persists the change. Returns an error if no matching suppression is found.
func (s *Store) Remove(ruleID, resource string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	idx := -1
	for i := range s.suppressions {
		if s.suppressions[i].Matches(ruleID, resource) {
			idx = i
			break
		}
	}
	if idx == -1 {
		return fmt.Errorf("no suppression found for rule %q resource %q", ruleID, resource)
	}

	s.suppressions = append(s.suppressions[:idx], s.suppressions[idx+1:]...)
	return s.saveLocked()
}

// IsSuppressed checks whether a finding identified by ruleID and resource is
// currently suppressed. It returns the suppression status and the reason.
// Expired suppressions are not considered active.
func (s *Store) IsSuppressed(ruleID, resource string) (bool, string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.suppressions {
		sup := &s.suppressions[i]
		if sup.Matches(ruleID, resource) && !sup.IsExpired() {
			return true, sup.Reason
		}
	}
	return false, ""
}

// List returns all non-expired suppressions.
func (s *Store) List() []Suppression {
	s.mu.Lock()
	defer s.mu.Unlock()

	var active []Suppression
	for i := range s.suppressions {
		if !s.suppressions[i].IsExpired() {
			active = append(active, s.suppressions[i])
		}
	}
	return active
}

// ListAll returns every suppression, including expired entries.
func (s *Store) ListAll() []Suppression {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]Suppression, len(s.suppressions))
	copy(out, s.suppressions)
	return out
}
