package toolctl

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

const provenanceFile = "provenance.json"

type Provenance struct {
	Name         string    `json:"name"`
	Source       Source    `json:"source"`
	Recipe       Recipe    `json:"recipe"`
	ArtifactMode string    `json:"artifact_mode"`
	ArtifactPath string    `json:"artifact_path,omitempty"`
	TargetPath   string    `json:"target_path"`
	Hash         string    `json:"hash"` // "sha256:…" content address of the pinned bytes
	Size         int       `json:"size"`
	BuiltAt      time.Time `json:"built_at"`
}

func ProvenancePath(storeRoot string) string { return filepath.Join(storeRoot, provenanceFile) }

func LoadProvenance(storeRoot string) ([]Provenance, error) {
	data, err := os.ReadFile(ProvenancePath(storeRoot))
	if os.IsNotExist(err) {
		return nil, nil // an absent file is a not-yet-populated library, not an error
	}
	if err != nil {
		return nil, fmt.Errorf("toolctl: read provenance: %w", err)
	}
	var recs []Provenance
	if err := json.Unmarshal(data, &recs); err != nil {
		return nil, fmt.Errorf("toolctl: parse provenance %s: %w", ProvenancePath(storeRoot), err)
	}
	sortProvenance(recs)
	return recs, nil
}

// SaveProvenance must stay temp+rename: a torn write truncates the evidence log.
func SaveProvenance(storeRoot string, recs []Provenance) error {
	if err := os.MkdirAll(storeRoot, 0o700); err != nil {
		return err
	}
	sortProvenance(recs)
	data, err := json.MarshalIndent(recs, "", "  ")
	if err != nil {
		return err
	}
	tmp := ProvenancePath(storeRoot) + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, ProvenancePath(storeRoot))
}

// mergeProvenance upserts by name: a re-populate replaces, never appends.
func mergeProvenance(existing, fresh []Provenance) []Provenance {
	byName := map[string]Provenance{}
	for _, r := range existing {
		byName[r.Name] = r
	}
	for _, r := range fresh {
		byName[r.Name] = r
	}
	out := make([]Provenance, 0, len(byName))
	for _, r := range byName {
		out = append(out, r)
	}
	sortProvenance(out)
	return out
}

// Allowlist is the trusted set: the store, not a target descriptor, decides what mounts.
func Allowlist(storeRoot string) ([]string, error) {
	recs, err := LoadProvenance(storeRoot)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(recs))
	for _, r := range recs {
		if r.Hash != "" {
			out = append(out, r.Hash)
		}
	}
	return out, nil
}

func sortProvenance(recs []Provenance) {
	sort.Slice(recs, func(i, j int) bool { return recs[i].Name < recs[j].Name })
}
