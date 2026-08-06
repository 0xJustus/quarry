package runner

import (
	"regexp"
	"strings"

	"github.com/0xjustus/quarry/internal/verdict/oracle"
)

const DefaultTaintMarker = "QUARRY_TAINT_SINK:"

// A LEAD that drives an oracle taint condition, never a verdict; the oracle disposes.
type TaintParser interface {
	Parse(stdout, stderr string) (reached bool, sink string)
}

// MarkerTaintParser reads the marker line an instrumented harness prints; no dynamic taint tracking of its own.
type MarkerTaintParser struct {
	Marker string // empty → DefaultTaintMarker
}

func (p MarkerTaintParser) marker() string {
	if p.Marker != "" {
		return p.Marker
	}
	return DefaultTaintMarker
}

// both streams, unlike a sanitizer report: a lead only costs recall, never soundness
func (p MarkerTaintParser) Parse(stdout, stderr string) (bool, string) {
	re := regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(p.marker()) + `\s*(.*?)\s*$`)
	for _, text := range []string{stderr, stdout} {
		if m := re.FindStringSubmatch(text); m != nil {
			return true, strings.TrimSpace(m[1])
		}
	}
	return false, ""
}

var _ TaintParser = MarkerTaintParser{}

// default-off: a nil parser leaves the fields zero
func applyTaint(rr *oracle.RunResult, spec RunSpec) {
	if spec.Taint == nil {
		return
	}
	if reached, sink := spec.Taint.Parse(rr.Stdout, rr.Stderr); reached {
		rr.TaintReached = true
		rr.TaintSink = sink
	}
}
