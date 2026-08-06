// Package impact is the semantic-impact grader: it grades a confirmed output divergence by whether it flips a real security consumer's decision.
package impact

import "fmt"

// Rung is the semantic-impact ladder (non-crash analog of the crash-primitive ladder).
type Rung int

const (
	// outputs differ but NO consumer decision flips — the conservative default
	S0SpecDeviation Rung = iota
	// the divergence changes a DATA VALUE a consumer reads
	S1DataCorruption
	// the divergence carries an un-neutralized token into an injection sink
	S2InjectionEnabling
	// the divergence FLIPS a security decision (auth allow/deny) — the auth-bypass rung
	S3SecurityDecisionFlip
)

func (r Rung) String() string {
	switch r {
	case S0SpecDeviation:
		return "S0-spec-deviation"
	case S1DataCorruption:
		return "S1-data-corruption"
	case S2InjectionEnabling:
		return "S2-injection-enabling"
	case S3SecurityDecisionFlip:
		return "S3-security-decision-flip"
	default:
		return fmt.Sprintf("S?(%d)", int(r))
	}
}

// Divergence is a confirmed semantic divergence to grade: the reference (correct) and divergent observables.
type Divergence struct {
	Kind      string // "diverge_on_output" | "metamorphic" | "exception"
	Reference []byte
	Divergent []byte
}

// Probe is a security CONSUMER of the output; grading is sound only if Decide is a genuine consumer (it keys on the FLIP).
type Probe struct {
	Name     string
	Boundary Rung // the rung a decision-flip on this probe demonstrates
	Decide   func([]byte) string
}

type Assessment struct {
	Rung         Rung
	Demonstrated bool // true iff a probe decision flipped (false ⇒ defaulted down)
	ProbeName    string
	RefDecision  string
	DivDecision  string
	Rationale    string
}

// Grade returns the HIGHEST rung a probe demonstrably flips; default DOWN to S0, never elevated on assertion (vault: Corpus and Grading).
func Grade(d Divergence, probes []Probe) Assessment {
	best := Assessment{
		Rung:      S0SpecDeviation,
		Rationale: "outputs differ but no security-consumer decision flipped; defaulted down (spec-deviation)",
	}
	for _, p := range probes {
		if p.Decide == nil {
			continue
		}
		ref := p.Decide(d.Reference)
		div := p.Decide(d.Divergent)
		if ref == div {
			continue
		}
		if !best.Demonstrated || p.Boundary > best.Rung {
			best = Assessment{
				Rung:         p.Boundary,
				Demonstrated: true,
				ProbeName:    p.Name,
				RefDecision:  ref,
				DivDecision:  div,
				Rationale: fmt.Sprintf("probe %q (%s) flipped: reference=%q divergent=%q — the divergence changes a real security decision",
					p.Name, p.Boundary, ref, div),
			}
		}
	}
	return best
}
