package anonymize

import (
	"regexp"
	"strings"

	"github.com/0xjustus/quarry/internal/publish/redact"
)

// vulnerable-path strings; membership is by overlap, not equality (see loadBearing)
type KeepSet map[string]struct{}

func NewKeepSet(keep ...string) KeepSet {
	k := make(KeepSet, len(keep))
	for _, s := range keep {
		if s = strings.TrimSpace(s); s != "" {
			k[s] = struct{}{}
		}
	}
	return k
}

// an identifier kept verbatim because redacting it would break the repro
type LoadBearingLeak struct {
	Value string
	Kind  string // email | ip | path | user | secret
}

type TaintRedactor struct {
	UserName string // scrubbed only at >=3 chars: shorter is unsafe to substitute
	Secrets  []string
}

func (r *TaintRedactor) Redact(s string, keep KeepSet) (string, []LoadBearingLeak) {
	if s == "" {
		return s, nil
	}
	var leaks []LoadBearingLeak

	// redact.Paths (not the bare regex): network URLs survive intact as upstream citations.
	s = redact.Paths(s, func(p string) string {
		if loadBearing(p, keep) {
			leaks = append(leaks, LoadBearingLeak{Value: p, Kind: "path"})
			return p
		}
		return redact.KeepBasename(p)
	})

	s = r.replaceGated(s, redact.Email, "<redacted-email>", "email", keep, &leaks)
	s = r.replaceGated(s, redact.IPv4, "<redacted-ip>", "ip", keep, &leaks)
	s = r.replaceGated(s, redact.IPv6, "<redacted-ip>", "ip", keep, &leaks)

	if name := strings.TrimSpace(r.UserName); len(name) >= 3 {
		s = replaceLiteralGated(s, name, "<user>", "user", keep, &leaks)
	}
	for _, sec := range r.Secrets {
		if sec = strings.TrimSpace(sec); sec != "" {
			s = replaceLiteralGated(s, sec, "<redacted-secret>", "secret", keep, &leaks)
		}
	}
	return s, leaks
}

func (r *TaintRedactor) replaceGated(s string, re *regexp.Regexp, repl, kind string, keep KeepSet, leaks *[]LoadBearingLeak) string {
	return re.ReplaceAllStringFunc(s, func(m string) string {
		if loadBearing(m, keep) {
			*leaks = append(*leaks, LoadBearingLeak{Value: m, Kind: kind})
			return m
		}
		return repl
	})
}

func replaceLiteralGated(s, lit, repl, kind string, keep KeepSet, leaks *[]LoadBearingLeak) string {
	if !strings.Contains(s, lit) {
		return s
	}
	if loadBearing(lit, keep) {
		*leaks = append(*leaks, LoadBearingLeak{Value: lit, Kind: kind})
		return s
	}
	return strings.ReplaceAll(s, lit, repl)
}

// below 4 bytes an overlap is coincidence, not signal; equality still wins
const minOverlap = 4

func loadBearing(match string, keep KeepSet) bool {
	if len(keep) == 0 {
		return false
	}
	if _, ok := keep[match]; ok {
		return true
	}
	if len(match) < minOverlap {
		return false
	}
	for k := range keep {
		if len(k) < minOverlap {
			continue
		}
		if strings.Contains(match, k) || strings.Contains(k, match) {
			return true
		}
	}
	return false
}
