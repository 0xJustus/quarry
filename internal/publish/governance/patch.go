package governance

import (
	"fmt"
	"time"

	"github.com/0xjustus/quarry/internal/publish/artifact"
)

type PatchState struct {
	// reuse artifact.ComputeBehavioralKey; never mint a parallel identity here
	BehavioralKey string
	Fixed         bool
	FixedAt       time.Time
	CVE           string
}

// Applier turns a patch-landed signal into a placement promotion; it never writes.
type Applier struct{}

var ErrNotFixed = fmt.Errorf("governance: patch state is not marked fixed")

func (Applier) Apply(from ExposureState, ps PatchState) (ExposureState, artifact.Placement, error) {
	if !ps.Fixed {
		return from, from.Placement(), ErrNotFixed
	}
	to, err := Transition(from, PatchLanded)
	if err != nil {
		return from, from.Placement(), err
	}
	return to, to.Placement(), nil
}

func (ps PatchState) MarkFixed(now time.Time) PatchState {
	if ps.Fixed { // first landing wins
		return ps
	}
	ps.Fixed = true
	ps.FixedAt = now
	return ps
}
