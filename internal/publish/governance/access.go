package governance

import "github.com/0xjustus/quarry/internal/publish/artifact"

// AccessPolicy is the read-side gate over a placement tier (write side: channels).
type AccessPolicy struct {
	Originator string
	Trusted    map[string]bool
}

func NewAccessPolicy(originator string, trusted ...string) AccessPolicy {
	m := make(map[string]bool, len(trusted))
	for _, p := range trusted {
		m[p] = true
	}
	return AccessPolicy{Originator: originator, Trusted: m}
}

func (p AccessPolicy) Allow(principal string, placement artifact.Placement) bool {
	switch placement {
	case artifact.Public:
		return true
	case artifact.Trusted:
		if principal != "" && principal == p.Originator {
			return true
		}
		return principal != "" && p.Trusted[principal]
	case artifact.Private:
		// an empty principal is never the originator
		return principal != "" && principal == p.Originator
	default:
		return false // fail closed: an unknown tier denies
	}
}
