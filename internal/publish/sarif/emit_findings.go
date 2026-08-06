package sarif

import (
	"fmt"
	"sort"
	"strings"
)

type Finding struct {
	BehavioralKey string
	BugClass      string
	File          string
	Line          int
	Abstract      string
}

func EmitFindings(fs []Finding, opts Opts) Report {
	results := make([]Result, 0, len(fs))
	ruleSet := map[string]Rule{}
	for _, f := range fs {
		ruleID := f.BugClass
		if ruleID == "" {
			ruleID = "memory-safety-crash"
		}
		res := Result{
			RuleID:  ruleID,
			Level:   "error",
			Message: Message{Text: findingMessage(f)},
			GUID:    randomGUID(),
		}
		if f.BehavioralKey != "" {
			res.CorrelationGUID = stableGUID(f.BehavioralKey)
			res.PartialFingerprints = map[string]string{behavioralKeyFP: f.BehavioralKey}
		}
		if loc := findingLocation(f, opts.SrcRoot); loc != nil {
			res.Locations = []Location{*loc}
		}
		results = append(results, res)
		if _, ok := ruleSet[ruleID]; !ok {
			ruleSet[ruleID] = ruleFor(ruleID)
		}
	}

	ruleIDs := make([]string, 0, len(ruleSet))
	for id := range ruleSet {
		ruleIDs = append(ruleIDs, id)
	}
	sort.Strings(ruleIDs)
	rules := make([]Rule, 0, len(ruleIDs))
	for _, id := range ruleIDs {
		rules = append(rules, ruleSet[id])
	}
	return Report{Schema: schema, Version: version, Runs: []Run{newRun(rules, results, opts)}}
}

func findingMessage(f Finding) string {
	if a := strings.TrimSpace(f.Abstract); a != "" {
		return a
	}
	bc := f.BugClass
	if bc == "" {
		bc = "memory-safety crash"
	}
	if f.File != "" {
		return fmt.Sprintf("Oracle-confirmed %s at %s:%d (behavioral key %s).", bc, f.File, f.Line, f.BehavioralKey)
	}
	return fmt.Sprintf("Oracle-confirmed %s (behavioral key %s).", bc, f.BehavioralKey)
}

func findingLocation(f Finding, srcRoot string) *Location {
	if f.File == "" {
		return nil
	}
	// srcArtifact, never a bare SRCROOT stamp: an absolute uri must not be re-based
	phys := &Physical{ArtifactLocation: srcArtifact(f.File, srcRoot)}
	if f.Line > 0 {
		phys.Region = &Region{StartLine: f.Line}
	}
	return &Location{PhysicalLocation: phys}
}
