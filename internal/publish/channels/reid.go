package channels

import (
	"context"
	"fmt"
	"strings"

	"github.com/0xjustus/quarry/internal/publish/artifact"
)

type LeakScanBattery struct {
	userName string
}

func NewLeakScanBattery() LeakScanBattery {
	return LeakScanBattery{userName: currentUserName()}
}

func (b LeakScanBattery) Score(_ context.Context, e *artifact.Envelope, minForTier float64) ReIDResult {
	if minForTier <= 0 {
		return ReIDResult{Score: 1, Cleared: true, Notes: "local tier: no clearance required"}
	}
	// above local, a raw reproducer/specimen clears only via known-public provenance
	if e.Artifact.Content.Specimen != nil || e.Artifact.Reproducer != nil {
		return ReIDResult{Score: 0, Cleared: false, Notes: "reproducer/specimen-bearing artifact: not clearable above local without known-public provenance"}
	}

	leaks := scanReIDSignals(b.userName, leakSurfaces(e))

	// 0.34 per category: one leak must drop public below 0.9
	score := 1.0 - 0.34*float64(len(leaks))
	if score < 0 {
		score = 0
	}
	if score >= minForTier {
		return ReIDResult{Score: score, Cleared: true, Notes: "no re-identification signals found"}
	}
	return ReIDResult{Score: score, Cleared: false, Notes: fmt.Sprintf("re-id signals present: %s", strings.Join(leaks, ", "))}
}

func dedupStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
