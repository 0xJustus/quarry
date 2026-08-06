package semantic

import (
	"regexp"
	"strings"

	"github.com/0xjustus/quarry/internal/publish/artifact"
)

// Root-cause oriented: the faulting frame is one element among many.
func CrashFeatures(c artifact.Crash) Features {
	var f Features
	if bc := norm(c.BugClass); bc != "" {
		f = append(f, "class:"+bc)
	}
	if san := norm(c.Sanitizer); san != "" {
		f = append(f, "san:"+san)
	}
	frames := c.Frames
	if len(frames) == 0 {
		frames = c.Sites
	}
	for _, fr := range frames {
		toks := frameTokens(fr)
		if len(toks) == 0 {
			continue
		}
		f = append(f, "frame:"+strings.Join(toks, "."))
		for _, t := range toks {
			f = append(f, "tok:"+t)
		}
	}
	return f
}

var reIdent = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*`)

// keep in sync with artifact.normalizeFrame
var reFrameLocation = regexp.MustCompile(`\s+\S*:\d+(?::\d+)?$`)

var sourceExt = map[string]struct{}{
	"c": {}, "cc": {}, "cpp": {}, "cxx": {}, "c++": {}, "h": {}, "hh": {}, "hpp": {}, "hxx": {},
	"inc": {}, "s": {}, "asm": {}, "go": {}, "rs": {}, "m": {}, "mm": {},
}

// load-bearing: reIdent would tokenize path segments as identifiers
func stripFrameLocation(frame string) string {
	if m := reFrameLocation.FindStringIndex(frame); m != nil {
		frame = frame[:m[0]]
	}
	fields := strings.Fields(frame)
	kept := fields[:0]
	for _, f := range fields {
		if isPathField(f) {
			continue
		}
		kept = append(kept, f)
	}
	return strings.Join(kept, " ")
}

// errs toward dropping: a kept path corrupts the ranking, a lost token costs recall
func isPathField(f string) bool {
	if strings.ContainsAny(f, `/\`) {
		return true
	}
	lf := strings.ToLower(f)
	if i := strings.LastIndex(lf, "."); i > 0 {
		if _, ok := sourceExt[lf[i+1:]]; ok {
			return true
		}
	}
	return false
}

// type/qualifier tokens that vary across build variants
var typeNoise = map[string]struct{}{
	"const": {}, "unsigned": {}, "signed": {}, "int": {}, "uint": {}, "char": {},
	"void": {}, "long": {}, "short": {}, "double": {}, "float": {}, "bool": {},
	"std": {}, "size_t": {}, "uint8_t": {}, "uint16_t": {}, "uint32_t": {}, "uint64_t": {},
}

func frameTokens(frame string) []string {
	raw := reIdent.FindAllString(stripFrameLocation(frame), -1)
	out := make([]string, 0, len(raw))
	for _, t := range raw {
		lt := strings.ToLower(t)
		if _, noise := typeNoise[lt]; noise {
			continue
		}
		out = append(out, lt)
	}
	return out
}

func norm(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
