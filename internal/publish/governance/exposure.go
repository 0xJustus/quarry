// Package governance models an exposure lifecycle over the commons placement tiers (unwired).
package governance

import (
	"fmt"

	"github.com/0xjustus/quarry/internal/publish/artifact"
)

type ExposureState string

const (
	Embargoed ExposureState = "embargoed"
	TrustedX  ExposureState = "trusted"
	PublicX   ExposureState = "public"
)

func (s ExposureState) Valid() bool {
	switch s {
	case Embargoed, TrustedX, PublicX:
		return true
	}
	return false
}

func (s ExposureState) Placement() artifact.Placement {
	switch s {
	case PublicX:
		return artifact.Public
	case TrustedX:
		return artifact.Trusted
	default: // fail closed to the most restrictive tier
		return artifact.Private
	}
}

type Event string

const (
	PatchLanded           Event = "patch-landed"
	TrustGranted          Event = "trust-granted"
	DisclosureDeadlineHit Event = "disclosure-deadline-hit"
)

func (e Event) Valid() bool {
	switch e {
	case PatchLanded, TrustGranted, DisclosureDeadlineHit:
		return true
	}
	return false
}

// absent entry = illegal; PublicX has none: publication is irreversible
var transitions = map[ExposureState]map[Event]ExposureState{
	Embargoed: {
		PatchLanded:           PublicX,
		TrustGranted:          TrustedX,
		DisclosureDeadlineHit: PublicX,
	},
	TrustedX: {
		PatchLanded:           PublicX,
		DisclosureDeadlineHit: PublicX,
	},
}

func Transition(from ExposureState, event Event) (ExposureState, error) {
	if !from.Valid() {
		return from, fmt.Errorf("governance: unknown state %q", from)
	}
	if !event.Valid() {
		return from, fmt.Errorf("governance: unknown event %q", event)
	}
	byEvent, ok := transitions[from]
	if !ok {
		return from, fmt.Errorf("governance: %q is terminal; event %q rejected", from, event)
	}
	to, ok := byEvent[event]
	if !ok {
		return from, fmt.Errorf("governance: illegal transition %q --%s-->", from, event)
	}
	return to, nil
}

func CanTransition(from ExposureState, event Event) bool {
	_, err := Transition(from, event)
	return err == nil
}
