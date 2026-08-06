package anonymize

import (
	"bytes"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type Normalizer interface {
	// MUST be idempotent: it doubles as the re-verify oracle when Verifier is nil
	Normalize(specimen []byte) ([]byte, error)
}

type Verifier interface {
	Verify(specimen []byte) error
}

type VerifierFunc func(specimen []byte) error

func (f VerifierFunc) Verify(specimen []byte) error { return f(specimen) }

type NormalizeResult struct {
	Normalized []byte // the canonical bytes when Verified, else the original bytes
	Changed    bool
	Verified   bool
}

// an unverified normalization is never usable: original back, Verified=false
func NormalizeAndVerify(n Normalizer, v Verifier, specimen []byte) (NormalizeResult, error) {
	norm, err := n.Normalize(specimen)
	if err != nil {
		return NormalizeResult{Normalized: specimen}, err
	}
	changed := !bytes.Equal(norm, specimen)

	verified := false
	if v != nil {
		verified = v.Verify(norm) == nil
	} else {
		again, err := n.Normalize(norm)
		if err != nil {
			return NormalizeResult{Normalized: specimen}, err
		}
		verified = bytes.Equal(again, norm)
	}

	if !verified {
		return NormalizeResult{Normalized: append([]byte(nil), specimen...), Changed: false, Verified: false}, nil
	}
	return NormalizeResult{Normalized: norm, Changed: changed, Verified: true}, nil
}

var (
	reWS    = regexp.MustCompile(`[ \t]+`)
	reIdent = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*`)
)

type StructuralNormalizer struct {
	CollapseWhitespace bool
	// off by default: sound only when line order carries no behavior
	SortLines bool
	// off by default: sound only when identifier spelling is inert to the repro
	RenameIdents bool
	// tokens exempt from renaming, so a load-bearing name is never rewritten
	Keywords map[string]struct{}
}

func (s *StructuralNormalizer) Normalize(specimen []byte) ([]byte, error) {
	out := string(specimen)
	// line endings first: every later pass splits on "\n"
	out = strings.ReplaceAll(out, "\r\n", "\n")
	out = strings.ReplaceAll(out, "\r", "\n")

	if s.RenameIdents {
		out = s.renameIdents(out)
	}
	if s.CollapseWhitespace {
		out = collapseWhitespace(out)
	}
	if s.SortLines {
		out = sortLines(out)
	}
	return []byte(out), nil
}

func collapseWhitespace(in string) string {
	lines := strings.Split(in, "\n")
	kept := lines[:0]
	for _, ln := range lines {
		ln = strings.TrimSpace(reWS.ReplaceAllString(ln, " "))
		if ln != "" {
			kept = append(kept, ln)
		}
	}
	return strings.Join(kept, "\n")
}

func sortLines(in string) string {
	lines := strings.Split(in, "\n")
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

// first-appearance numbering is what makes a second pass a fixpoint
func (s *StructuralNormalizer) renameIdents(in string) string {
	mapping := make(map[string]string)
	next := 0
	return reIdent.ReplaceAllStringFunc(in, func(tok string) string {
		if s.Keywords != nil {
			if _, ok := s.Keywords[tok]; ok {
				return tok
			}
		}
		if r, ok := mapping[tok]; ok {
			return r
		}
		r := "id" + strconv.Itoa(next)
		next++
		mapping[tok] = r
		return r
	})
}
