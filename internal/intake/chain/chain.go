// Package chain models exploitation as content-addressed capability transitions.
package chain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
)

// Capability is a point in capability-state space, content-addressed by (Class, State).
type Capability struct {
	Class string            `json:"class"`
	State map[string]string `json:"state,omitempty"`
}

func (c Capability) ID() string { return "cap:" + digest(c.preimage()) }

// canonical: state keys sorted — ids must match across machines
func (c Capability) preimage() []byte {
	keys := make([]string, 0, len(c.State))
	for k := range c.State {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString("class=")
	b.WriteString(c.Class)
	for _, k := range keys {
		b.WriteString("|")
		b.WriteString(k)
		b.WriteString("=")
		b.WriteString(c.State[k])
	}
	return []byte(b.String())
}

// Technique is the artifact that realizes a transition, plus a human label.
type Technique struct {
	Name       string `json:"name"`
	ArtifactID string `json:"artifact_id,omitempty"`
	Note       string `json:"note,omitempty"`
}

// Transition is the atom: pre -> technique -> post, content-addressed over its full content.
type Transition struct {
	Pre       Capability `json:"pre"`
	Technique Technique  `json:"technique"`
	Post      Capability `json:"post"`
	Verified  string     `json:"verified,omitempty"` // grounding metadata: NOT part of the id
}

func (t Transition) ID() string {
	body, _ := json.Marshal(struct {
		Pre  string    `json:"pre"`
		Tech Technique `json:"tech"`
		Post string    `json:"post"`
	}{t.Pre.ID(), t.Technique, t.Post.ID()})
	return "tx:" + digest(body)
}

// Chain is an ordered path of transitions where each post equals the next pre.
type Chain struct {
	Transitions []Transition `json:"transitions"`
}

// Valid reports whether the chain is a contiguous, non-empty path.
func (c Chain) Valid() bool {
	for i := 1; i < len(c.Transitions); i++ {
		if c.Transitions[i-1].Post.ID() != c.Transitions[i].Pre.ID() {
			return false
		}
	}
	return len(c.Transitions) > 0
}

func (c Chain) ID() string { return "chain:" + digest([]byte(c.joinTo(len(c.Transitions)))) }

// PrefixIDs returns the cumulative prefix hashes p_k, k=1..n.
func (c Chain) PrefixIDs() []string {
	out := make([]string, 0, len(c.Transitions))
	for k := 1; k <= len(c.Transitions); k++ {
		out = append(out, "chain:"+digest([]byte(c.joinTo(k))))
	}
	return out
}

// federated chain-hash wire format: transition ids in order, ‖-joined
func (c Chain) joinTo(k int) string {
	ids := make([]string, 0, k)
	for i := 0; i < k && i < len(c.Transitions); i++ {
		ids = append(ids, c.Transitions[i].ID())
	}
	return strings.Join(ids, "‖")
}

// Start and End panic on an empty chain: guard with Valid.
func (c Chain) Start() Capability { return c.Transitions[0].Pre }
func (c Chain) End() Capability   { return c.Transitions[len(c.Transitions)-1].Post }

func (c Chain) TransitionIDs() []string {
	out := make([]string, len(c.Transitions))
	for i, t := range c.Transitions {
		out[i] = t.ID()
	}
	return out
}

// truncated to 32 hex: changing the length changes every id in the commons
func digest(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])[:32]
}
