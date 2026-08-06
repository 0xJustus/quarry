package sarif

import (
	"encoding/json"
	"fmt"
	"sort"
)

// Candidate is a lead, never a verdict: the oracle remains the sole judge.
type Candidate struct {
	RuleID      string
	File        string
	Line        int
	Message     string
	Fingerprint string
}

// Parse is deliberately lenient: only a structurally invalid document errors.
func Parse(data []byte) ([]Candidate, error) {
	var rep Report
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, fmt.Errorf("sarif: parse: %w", err)
	}
	var out []Candidate
	for _, run := range rep.Runs {
		for _, res := range run.Results {
			c := Candidate{
				RuleID:      res.RuleID,
				Message:     res.Message.Text,
				Fingerprint: pickFingerprint(res),
			}
			c.File, c.Line = firstPhysical(res.Locations)
			if c.RuleID == "" && c.File == "" && c.Fingerprint == "" && c.Message == "" {
				continue
			}
			out = append(out, c)
		}
	}
	return out, nil
}

func firstPhysical(locs []Location) (string, int) {
	for _, loc := range locs {
		if loc.PhysicalLocation == nil {
			continue
		}
		uri := loc.PhysicalLocation.ArtifactLocation.URI
		if uri == "" {
			continue
		}
		line := 0
		if loc.PhysicalLocation.Region != nil {
			line = loc.PhysicalLocation.Region.StartLine
		}
		return uri, line
	}
	return "", 0
}

// prefer the behavioral key so a round-tripped quarry finding dedups exactly
func pickFingerprint(res Result) string {
	if v := res.PartialFingerprints[behavioralKeyFP]; v != "" {
		return v
	}
	if v := firstByKey(res.PartialFingerprints); v != "" {
		return v
	}
	return firstByKey(res.Fingerprints)
}

func firstByKey(m map[string]string) string {
	if len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return m[keys[0]]
}
