// Package curriculum supplies the discovery loop a stream of targets to attempt.
package curriculum

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type Source string

const (
	SourceBench     Source = "bench"
	SourceARVO      Source = "arvo"
	SourceSynthetic Source = "synthetic"
)

type Target struct {
	ID             string
	Objective      string
	ExpectClass    []string
	Source         Source
	DescriptorPath string // quarry.yaml path, for file-backed sources
	Ref            string // opaque ref for non-file sources
}

var ErrExhausted = errors.New("curriculum: source exhausted")

type TargetSource interface {
	Next(ctx context.Context) (*Target, error)
}

// subset of the bench/suite.yaml schema
type suiteFile struct {
	Name        string      `yaml:"name"`
	Description string      `yaml:"description"`
	Cases       []suiteCase `yaml:"cases"`
}

type suiteCase struct {
	ID          string   `yaml:"id"`
	Objective   string   `yaml:"objective"`
	ExpectClass []string `yaml:"expect_class"`
}

type BenchSource struct {
	name    string
	targets []Target
	i       int
}

// descriptors are expected at <suiteDir>/cases/<id>/quarry.yaml
func NewBenchSource(suitePath string) (*BenchSource, error) {
	data, err := os.ReadFile(suitePath)
	if err != nil {
		return nil, fmt.Errorf("curriculum: read suite %s: %w", suitePath, err)
	}
	var sf suiteFile
	if err := yaml.Unmarshal(data, &sf); err != nil {
		return nil, fmt.Errorf("curriculum: parse suite %s: %w", suitePath, err)
	}
	if len(sf.Cases) == 0 {
		return nil, fmt.Errorf("curriculum: suite %s has no cases", suitePath)
	}
	suiteDir := filepath.Dir(suitePath)
	bs := &BenchSource{name: sf.Name}
	for _, c := range sf.Cases {
		if c.ID == "" {
			return nil, fmt.Errorf("curriculum: suite %s: a case is missing an id", suitePath)
		}
		desc := filepath.Join(suiteDir, "cases", c.ID, "quarry.yaml")
		// a suite case with no descriptor on disk is an error, not a skip
		if _, err := os.Stat(desc); err != nil {
			return nil, fmt.Errorf("curriculum: case %q descriptor not found at %s: %w", c.ID, desc, err)
		}
		bs.targets = append(bs.targets, Target{
			ID:             c.ID,
			Objective:      c.Objective,
			ExpectClass:    c.ExpectClass,
			Source:         SourceBench,
			DescriptorPath: desc,
		})
	}
	return bs, nil
}

func (b *BenchSource) Next(_ context.Context) (*Target, error) {
	if b.i >= len(b.targets) {
		return nil, ErrExhausted
	}
	t := b.targets[b.i]
	b.i++
	return &t, nil
}

func (b *BenchSource) Len() int { return len(b.targets) }

func (b *BenchSource) Reset() { b.i = 0 }

type SliceSource struct {
	targets []Target
	i       int
}

func NewSliceSource(targets []Target) *SliceSource {
	return &SliceSource{targets: append([]Target(nil), targets...)}
}

func (s *SliceSource) Next(_ context.Context) (*Target, error) {
	if s.i >= len(s.targets) {
		return nil, ErrExhausted
	}
	t := s.targets[s.i]
	s.i++
	return &t, nil
}

var (
	_ TargetSource = (*BenchSource)(nil)
	_ TargetSource = (*SliceSource)(nil)
)
