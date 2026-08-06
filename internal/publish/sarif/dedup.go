package sarif

import "strconv"

type Verdict string

const (
	Novel       Verdict = "novel"
	Rediscovery Verdict = "rediscovery"
	// RediscoveryClaimed: matched on an asserted key, so still pursuable
	RediscoveryClaimed Verdict = "rediscovery-claimed"
	DuplicateInBatch   Verdict = "duplicate-in-batch"
)

// FingerprintSource declares WHO computed the fingerprints; Dedup must never guess.
type FingerprintSource int

const (
	// FingerprintsAsserted: writer-controlled, so the zero value fails closed
	FingerprintsAsserted FingerprintSource = iota
	// FingerprintsMeasured: quarry derived every fingerprint from an observed run
	FingerprintsMeasured
)

type Decision struct {
	Candidate  Candidate
	Verdict    Verdict
	MatchedKey string
}

// Dedup: only a MEASURED fingerprint proves rediscovery; asserted is a claim.
func Dedup(cands []Candidate, knownKeys []string, src FingerprintSource) []Decision {
	known := make(map[string]bool, len(knownKeys))
	for _, k := range knownKeys {
		if k != "" {
			known[k] = true
		}
	}
	seen := map[string]bool{}
	out := make([]Decision, 0, len(cands))
	for _, c := range cands {
		d := Decision{Candidate: c, Verdict: Novel}
		switch {
		case c.Fingerprint == "":
			// no dedup identity — leave Novel
		case known[c.Fingerprint]:
			d.MatchedKey = c.Fingerprint
			if src == FingerprintsMeasured {
				d.Verdict = Rediscovery
			} else {
				d.Verdict = RediscoveryClaimed
			}
		case seen[batchIdentity(c, src)]:
			d.Verdict = DuplicateInBatch
		}
		if c.Fingerprint != "" {
			seen[batchIdentity(c, src)] = true
		}
		out = append(out, d)
	}
	return out
}

// an in-batch collapse DROPS a lead, so an asserted key also needs the evidence to agree
func batchIdentity(c Candidate, src FingerprintSource) string {
	if src == FingerprintsMeasured {
		return c.Fingerprint
	}
	return c.Fingerprint + "\x00" + c.RuleID + "\x00" + c.File + "\x00" + strconv.Itoa(c.Line)
}

// Novels returns the pursuable leads: an unproven "already found" must not retire one.
func Novels(ds []Decision) []Candidate {
	var out []Candidate
	for _, d := range ds {
		if d.Verdict == Novel || d.Verdict == RediscoveryClaimed {
			out = append(out, d.Candidate)
		}
	}
	return out
}
