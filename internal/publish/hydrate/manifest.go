package hydrate

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"

	"github.com/0xjustus/quarry/internal/intake/target"
	"github.com/0xjustus/quarry/internal/verdict/oracle"

	"gopkg.in/yaml.v3"
)

type manifestFile struct {
	Entries []manifestEntry `yaml:"entries"`
}

type manifestEntry struct {
	ID           string           `yaml:"id"`
	Project      string           `yaml:"project"`
	Vuln         target.Ingest    `yaml:"vuln"`
	Fix          target.Ingest    `yaml:"fix"`
	Run          target.RunConfig `yaml:"run"`
	Oracle       oracle.Spec      `yaml:"oracle"`
	TestcaseFile string           `yaml:"testcase_file"`
	TestcaseB64  string           `yaml:"testcase_b64"`
}

// LoadManifest returns the entries plus the base dir for their relative paths.
func LoadManifest(path string) ([]Entry, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("hydrate: read manifest %s: %w", path, err)
	}
	var mf manifestFile
	if err := yaml.Unmarshal(data, &mf); err != nil {
		return nil, "", fmt.Errorf("hydrate: parse manifest: %w", err)
	}
	base := filepath.Dir(path)
	entries := make([]Entry, 0, len(mf.Entries))
	for i, me := range mf.Entries {
		if me.ID == "" {
			return nil, "", fmt.Errorf("hydrate: entry %d has no id", i)
		}
		tc, err := loadTestcase(me, base)
		if err != nil {
			return nil, "", fmt.Errorf("hydrate: entry %s: %w", me.ID, err)
		}
		entries = append(entries, Entry{
			ID:       me.ID,
			Project:  me.Project,
			Vuln:     me.Vuln,
			Fix:      me.Fix,
			Run:      me.Run,
			Oracle:   me.Oracle,
			Testcase: tc,
		})
	}
	return entries, base, nil
}

func loadTestcase(me manifestEntry, base string) ([]byte, error) {
	switch {
	case me.TestcaseB64 != "":
		return base64.StdEncoding.DecodeString(me.TestcaseB64)
	case me.TestcaseFile != "":
		p := me.TestcaseFile
		if !filepath.IsAbs(p) {
			p = filepath.Join(base, p)
		}
		return os.ReadFile(p)
	default:
		return nil, fmt.Errorf("no testcase (set testcase_file or testcase_b64)")
	}
}
