package impact

import (
	"regexp"
	"strings"
)

// Reusable security-consumer probes; grading keys on the FLIP, so even a broad probe is sound.

var reAdminSignals = regexp.MustCompile(`(?i)"role"\s*:\s*"admin"|role=admin|"is_?admin"\s*:\s*true|"authenticated"\s*:\s*true|"authorized"\s*:\s*true|access\s*=\s*granted|ROLE_ADMIN|"admin"\s*:\s*true`)

// AuthProbe decides allow/deny by a privilege signal; a deny→allow flip is the auth-bypass rung (S3).
func AuthProbe() Probe {
	return Probe{Name: "authz", Boundary: S3SecurityDecisionFlip, Decide: func(o []byte) string {
		if reAdminSignals.Match(o) {
			return "allow"
		}
		return "deny"
	}}
}

// un-neutralized metacharacters an injection sink would act on
var dangerousTokens = []string{"<script", "</", "javascript:", "' or ", "';", "\" or ", "--", "$(", "`", "../", "..\\", "\x00"}

// InjectionProbe decides sink-reached/clean by a dangerous token; a clean→sink-reached flip is S2.
func InjectionProbe() Probe {
	return Probe{Name: "injection-sink", Boundary: S2InjectionEnabling, Decide: func(o []byte) string {
		s := strings.ToLower(string(o))
		for _, t := range dangerousTokens {
			if strings.Contains(s, t) {
				return "sink-reached"
			}
		}
		return "clean"
	}}
}

// FieldProbe reads a named field's value; a changed value is the data-corruption rung (S1).
func FieldProbe(field string) Probe {
	// field=value | "field": value | "field":"value"
	re := regexp.MustCompile(`(?i)(?:"` + regexp.QuoteMeta(field) + `"\s*:\s*"?|` + regexp.QuoteMeta(field) + `\s*=\s*)([^\s",}]+)`)
	return Probe{Name: "field:" + field, Boundary: S1DataCorruption, Decide: func(o []byte) string {
		if m := re.FindSubmatch(o); m != nil {
			return string(m[1])
		}
		return "<absent>"
	}}
}

// DefaultProbes is the general bundle: an auth consumer and an injection sink.
func DefaultProbes() []Probe { return []Probe{AuthProbe(), InjectionProbe()} }

func DivergenceFrom(kind string, reference, divergent []byte) Divergence {
	return Divergence{Kind: kind, Reference: reference, Divergent: divergent}
}
