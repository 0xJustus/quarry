package chain

import (
	"strings"

	"github.com/0xjustus/quarry/internal/publish/artifact"
)

const (
	CapInputReachable    = "input-reachable"
	CapControlledWrite   = "controlled-write"
	CapInfoDisclosure    = "info-disclosure"
	CapMemoryCorruption  = "memory-corruption"
	CapDenialOfService   = "denial-of-service"
	CapControlFlowHijack = "control-flow-hijack"
	CapCodeExecution     = "code-execution"
)

// keep in sync with artifact.IntegrityTier; "oracle" is reserved for quarry's own in-process Verifier
const (
	GroundingOracle          = "oracle"
	GroundingSelfReproducing = "self-reproducing"
	GroundingSigned          = "canonical-consistent"
	GroundingAsserted        = "provenance-asserted"
	GroundingUnverified      = "unverified"
)

// Cap returns the state-free capability for a class name.
func Cap(class string) Capability { return Capability{Class: class} }

// InputReachable is the entry capability every real bug shares.
func InputReachable() Capability { return Cap(CapInputReachable) }

// PrimitiveForBugClass maps an oracle bug-class token to the primitive it achieves.
func PrimitiveForBugClass(bugClass string) Capability {
	b := strings.ToLower(strings.TrimSpace(bugClass))
	switch {
	case b == "":
		return Cap(CapMemoryCorruption)

	// matched FIRST: these contain "overflow" and must not reach the write arm
	case strings.Contains(b, "stack-overflow"), strings.Contains(b, "stack-exhaustion"),
		strings.Contains(b, "timeout"), strings.Contains(b, "hang"),
		strings.Contains(b, "out-of-memory"), b == "oom", strings.Contains(b, "abort"):
		return Cap(CapDenialOfService)

	case strings.Contains(b, "integer-overflow"), strings.Contains(b, "float-cast-overflow"):
		return Cap(CapMemoryCorruption)

	case strings.Contains(b, "uninitialized"), strings.Contains(b, "info-leak"),
		strings.Contains(b, "memory-leak"), strings.Contains(b, "read"):
		return Cap(CapInfoDisclosure)
	case strings.Contains(b, "use-after"), strings.Contains(b, "double-free"),
		strings.Contains(b, "overflow"), strings.Contains(b, "out-of-bounds"),
		strings.Contains(b, "oob"), strings.Contains(b, "wild"),
		strings.Contains(b, "negative-size"), strings.Contains(b, "index-out"):
		return Cap(CapControlledWrite)
	default:
		return Cap(CapMemoryCorruption)
	}
}

// ArtifactFact is the minimal projection of a confirmed artifact the producer needs.
type ArtifactFact struct {
	BugClass      string
	BehavioralKey string
	Project       string
	ArtifactID    string
	Grounding     string
}

func FactFromEnvelope(e *artifact.Envelope) ArtifactFact {
	return ArtifactFact{
		BugClass:      e.Artifact.Content.Crash.BugClass,
		BehavioralKey: e.Artifact.BehavioralKey(),
		Project:       e.Provenance.Project,
		ArtifactID:    e.Artifact.ID,
		Grounding:     GroundingForEnvelope(e),
	}
}

// GroundingForEnvelope derives grounding from STRUCTURE (id, signature, tier), not a writer's label.
func GroundingForEnvelope(e *artifact.Envelope) string {
	if e == nil {
		return GroundingUnverified
	}
	if err := e.Verify(); err != nil {
		return GroundingUnverified
	}
	switch e.IntegrityTier() {
	case artifact.SelfReproducing:
		// the reproducer sits outside the id preimage and the signature: writer-controlled
		r := e.Artifact.Reproducer
		if r != nil && r.BlobHash != "" && r.Verdict.Pass {
			return GroundingSelfReproducing
		}
		return GroundingUnverified
	case artifact.CanonicalConsistent:
		return GroundingSigned
	default:
		return GroundingAsserted
	}
}

// Transition builds the reachability edge for one artifact.
func (f ArtifactFact) Transition() Transition {
	proj := f.Project
	if proj == "" {
		proj = "unknown"
	}
	grounding := f.Grounding
	if grounding == "" {
		// fail closed: an unlabelled fact may not print as oracle-grounded
		grounding = GroundingAsserted
	}
	return Transition{
		Pre: InputReachable(),
		Technique: Technique{
			Name:       "vuln:" + proj + ":" + strings.ToLower(strings.TrimSpace(f.BugClass)),
			ArtifactID: f.ArtifactID,
			Note:       "bk=" + f.BehavioralKey,
		},
		Post:     PrimitiveForBugClass(f.BugClass),
		Verified: grounding,
	}
}

// modeled, unverified edges: only controlled-write escalates, the rest are terminal
func escalationTransitions() []Transition {
	edge := func(pre, post, name string) Transition {
		return Transition{Pre: Cap(pre), Post: Cap(post), Technique: Technique{Name: name, Note: "modeled escalation"}}
	}
	return []Transition{
		edge(CapControlledWrite, CapControlFlowHijack, "overwrite-code-pointer"),
		edge(CapControlFlowHijack, CapCodeExecution, "hijack-to-rop-or-shellcode"),
	}
}

func BuildGraph(facts []ArtifactFact) *Graph {
	g := NewGraph()
	for _, f := range facts {
		g.AddTransition(f.Transition())
	}
	for _, t := range escalationTransitions() {
		g.AddTransition(t)
	}
	return g
}

func BuildGraphFromEnvelopes(envs []*artifact.Envelope) *Graph {
	facts := make([]ArtifactFact, 0, len(envs))
	for _, e := range envs {
		facts = append(facts, FactFromEnvelope(e))
	}
	return BuildGraph(facts)
}
