// Package toolctl builds a pinned tool manifest into content-addressed blobs.
package toolctl

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	ArtifactFile  = "file"  // one file lifted out with docker cp
	ArtifactImage = "image" // the whole image tarball from docker save
)

type Manifest struct {
	Tools []ToolEntry `yaml:"tools"`
}

type ToolEntry struct {
	Name     string   `yaml:"name"`
	Source   Source   `yaml:"source"`
	Recipe   Recipe   `yaml:"recipe"`
	Artifact Artifact `yaml:"artifact"`
	// expected content hash; empty until the first populate records one
	Pin string `yaml:"pin,omitempty"`
}

type Source struct {
	Repo   string `yaml:"repo" json:"repo"`
	Commit string `yaml:"commit" json:"commit"`
	Ref    string `yaml:"ref,omitempty" json:"ref,omitempty"`
}

type Recipe struct {
	Dockerfile string            `yaml:"dockerfile" json:"dockerfile"`
	Context    string            `yaml:"context,omitempty" json:"context,omitempty"`
	BuildArgs  map[string]string `yaml:"build_args,omitempty" json:"build_args,omitempty"`
	ImageTag   string            `yaml:"image_tag" json:"image_tag"`
}

type Artifact struct {
	Mode   string `yaml:"mode,omitempty"` // ArtifactFile (default) | ArtifactImage
	Path   string `yaml:"path,omitempty"` // in-image path (ArtifactFile only)
	Target string `yaml:"target"`         // absolute in-container mount path
}

func (a Artifact) mode() string {
	if a.Mode == "" {
		return ArtifactFile
	}
	return a.Mode
}

// Load returns the manifest and its dir, the base for relative recipe paths.
func Load(path string) (Manifest, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, "", fmt.Errorf("toolctl: read manifest %s: %w", path, err)
	}
	var m Manifest
	if err := yaml.Unmarshal(data, &m); err != nil {
		return Manifest{}, "", fmt.Errorf("toolctl: parse manifest %s: %w", path, err)
	}
	if err := m.Validate(); err != nil {
		return Manifest{}, "", err
	}
	dir, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		return Manifest{}, "", err
	}
	return m, dir, nil
}

func (m Manifest) Validate() error {
	if len(m.Tools) == 0 {
		return fmt.Errorf("toolctl: manifest declares no tools")
	}
	seen := map[string]bool{}
	for i, t := range m.Tools {
		if t.Name == "" {
			return fmt.Errorf("toolctl: tool[%d] has no name", i)
		}
		if seen[t.Name] {
			return fmt.Errorf("toolctl: duplicate tool name %q", t.Name)
		}
		seen[t.Name] = true
		if t.Source.Repo == "" || t.Source.Commit == "" {
			return fmt.Errorf("toolctl: tool %q must pin a source repo + commit", t.Name)
		}
		if t.Recipe.Dockerfile == "" || t.Recipe.ImageTag == "" {
			return fmt.Errorf("toolctl: tool %q needs a recipe dockerfile + image_tag", t.Name)
		}
		if !filepath.IsAbs(t.Artifact.Target) {
			return fmt.Errorf("toolctl: tool %q artifact target %q must be an absolute in-container path", t.Name, t.Artifact.Target)
		}
		switch t.Artifact.mode() {
		case ArtifactFile:
			if t.Artifact.Path == "" {
				return fmt.Errorf("toolctl: tool %q file artifact needs an in-image path", t.Name)
			}
		case ArtifactImage:
		default:
			return fmt.Errorf("toolctl: tool %q unknown artifact mode %q (want %q|%q)", t.Name, t.Artifact.Mode, ArtifactFile, ArtifactImage)
		}
		if err := validatePin(t.Pin); err != nil {
			return fmt.Errorf("toolctl: tool %q %w", t.Name, err)
		}
	}
	return nil
}

func validatePin(pin string) error {
	if pin == "" {
		return nil
	}
	if !strings.HasPrefix(pin, "sha256:") || len(pin) != len("sha256:")+64 {
		return fmt.Errorf("pin %q must be a full \"sha256:<64 hex>\" content hash", pin)
	}
	return nil
}
