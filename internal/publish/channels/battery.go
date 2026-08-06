package channels

import (
	"context"
	"fmt"
	"strings"

	"github.com/0xjustus/quarry/internal/publish/artifact"
	"github.com/0xjustus/quarry/internal/publish/redact"
	"github.com/0xjustus/quarry/internal/verdict/oracle"
)

// Allow is the ONLY path by which a reproducer reaches a public tier.
type ProvenanceBattery struct {
	Allow    map[string]bool
	Fallback ReIDBattery
	userName string
}

func NewProvenanceBattery(allow ...string) ProvenanceBattery {
	m := make(map[string]bool, len(allow))
	for _, a := range allow {
		m[strings.ToLower(a)] = true
	}
	return ProvenanceBattery{Allow: m, Fallback: NewLeakScanBattery(), userName: currentUserName()}
}

// AcquiredBy is unauthenticated: it waives only the above-local rule, never the scan.
func (b ProvenanceBattery) Score(ctx context.Context, e *artifact.Envelope, minForTier float64) ReIDResult {
	if e == nil {
		return ReIDResult{Score: 0, Cleared: false, Notes: "nil envelope: nothing measured"}
	}
	fb := b.Fallback
	if fb == nil {
		fb = StubBattery{}
	}
	if minForTier <= 0 || !b.Allow[strings.ToLower(e.Provenance.AcquiredBy)] {
		return fb.Score(ctx, e, minForTier)
	}
	if leaks := scanReIDSignals(b.userName, leakSurfaces(e)); len(leaks) > 0 {
		return ReIDResult{Score: 0, Cleared: false, Notes: fmt.Sprintf(
			"known-public provenance (%s) does not waive the leak scan: re-id signals present: %s",
			e.Provenance.AcquiredBy, strings.Join(leaks, ", "))}
	}
	return ReIDResult{Score: 1, Cleared: true, Notes: "known-public provenance (" + e.Provenance.AcquiredBy + "): no re-id signals found"}
}

func scanReIDSignals(userName string, surfaces []string) []string {
	var leaks []string
	for _, s := range surfaces {
		// redact.HasPath, not the bare regex: the scan must match what the redactor rewrites
		if redact.HasPath(s) {
			leaks = append(leaks, "home/build path")
		}
		if redact.Email.MatchString(s) {
			leaks = append(leaks, "email")
		}
		if redact.IPv4.MatchString(s) || redact.IPv6.MatchString(s) {
			leaks = append(leaks, "ip")
		}
		if userName != "" && strings.Contains(s, userName) {
			leaks = append(leaks, "operator name")
		}
	}
	return dedupStrings(leaks)
}

// every surface riding to the sink verbatim, incl. untouchable reproducer fields
func leakSurfaces(e *artifact.Envelope) []string {
	crash := e.Artifact.Content.Crash
	s := append([]string{e.Abstract, crash.DedupToken, crash.PathSig}, crash.Frames...)
	s = append(s, crash.Sites...)
	p := e.Provenance
	s = append(s, p.Model, p.ExperimentID, p.RunID, p.AcquiredBy, p.Project)
	s = append(s, p.ToolHashes...)
	if sp := e.Artifact.Content.Specimen; sp != nil {
		s = append(s, sp.Media)
	}
	return append(s, reproducerSurfaces(e.Artifact.Reproducer)...)
}

// keep in step with oracle.Spec/Verdict: a missed field is unscanned on the wire
func reproducerSurfaces(r *artifact.Reproducer) []string {
	if r == nil {
		return nil
	}
	out := []string{r.Media}
	out = append(out, specSurfaces(r.Oracle)...)
	return append(out, verdictSurfaces(r.Verdict)...)
}

func specSurfaces(sp oracle.Spec) []string {
	out := conditionSurfaces(sp.Conditions)
	if sp.Differential != nil {
		out = append(out, sp.Differential.FixedImage)
	}
	for _, st := range sp.Sequence {
		out = append(out, st.Name)
		out = append(out, conditionSurfaces(st.Conditions)...)
	}
	return out
}

func conditionSurfaces(cs []oracle.Condition) []string {
	var out []string
	for _, c := range cs {
		out = append(out, c.Tool, c.CrashSite, c.Stream, c.Regex, c.Sink, c.Script, c.Relation)
		out = append(out, c.Signals...)
		out = append(out, c.BugClass...)
		if c.Baseline != nil {
			out = append(out, c.Baseline.Stream, c.Baseline.Matches)
			if c.Baseline.Equals != nil {
				out = append(out, *c.Baseline.Equals)
			}
		}
	}
	return out
}

func verdictSurfaces(v oracle.Verdict) []string {
	var out []string
	for _, cr := range v.Conditions {
		out = append(out, cr.Detail)
	}
	for _, st := range v.Stages {
		out = append(out, st.Name)
		for _, cr := range st.Conditions {
			out = append(out, cr.Detail)
		}
	}
	if v.Differential != nil {
		out = append(out, v.Differential.Detail)
	}
	return append(out, v.PartialCredit...)
}
