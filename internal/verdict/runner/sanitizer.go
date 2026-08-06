package runner

import (
	"regexp"
	"strings"

	"github.com/0xjustus/quarry/internal/verdict/oracle"
)

var (
	reSanError   = regexp.MustCompile(`(?m)^\s*==\d+==\s*ERROR:\s*(AddressSanitizer|UndefinedBehaviorSanitizer|MemorySanitizer|ThreadSanitizer|LeakSanitizer):\s*([a-zA-Z0-9\-_]+)`)
	reSanSummary = regexp.MustCompile(`(?m)^\s*SUMMARY:\s*(AddressSanitizer|UndefinedBehaviorSanitizer|MemorySanitizer|ThreadSanitizer|LeakSanitizer):\s*(\S+)\s+(?:\S+\s+)?in\s+(.+)$`)
	reFrameN     = regexp.MustCompile(`(?m)^\s*#(\d+)\s+0x[0-9a-f]+\s+in\s+(.+)$`)
	// UBSan sometimes prints only this, without the ==pid==ERROR line
	reUBSan = regexp.MustCompile(`(?m)runtime error:\s*(.+)$`)
)

const maxFrames = 10

func toolSlug(name string) string {
	switch name {
	case "AddressSanitizer":
		return "asan"
	case "UndefinedBehaviorSanitizer":
		return "ubsan"
	case "MemorySanitizer":
		return "msan"
	case "ThreadSanitizer":
		return "tsan"
	case "LeakSanitizer":
		return "lsan"
	}
	return strings.ToLower(name)
}

// ParseSanitizer parses a sanitizer report from stderr only (stdout is agent-forgeable); trusted only after corroborateSanitizer.
func ParseSanitizer(_, stderr string) oracle.SanitizerReport {
	text := stderr
	r := oracle.SanitizerReport{}

	if m := reSanError.FindStringSubmatch(text); m != nil {
		r.Fired = true
		r.Tool = toolSlug(m[1])
		r.BugClass = m[2]
	}
	if m := reSanSummary.FindStringSubmatch(text); m != nil {
		r.Fired = true
		if r.Tool == "" {
			r.Tool = toolSlug(m[1])
		}
		if r.BugClass == "" {
			r.BugClass = m[2]
		}
		r.CrashSite = cleanSymbol(m[3])
	}
	if r.Fired {
		// anchor at the report line: a #0 injected into earlier stderr must not own frames[0]
		anchor := 0
		if loc := reSanError.FindStringIndex(text); loc != nil {
			anchor = loc[0]
		} else if loc := reSanSummary.FindStringIndex(text); loc != nil {
			anchor = loc[0]
		}
		r.Frames = extractFrames(text[anchor:])
		if r.CrashSite == "" && len(r.Frames) > 0 {
			r.CrashSite = r.Frames[0]
		}
	}
	if !r.Fired {
		if m := reUBSan.FindStringSubmatch(text); m != nil {
			r.Fired = true
			r.Tool = "ubsan"
			r.BugClass = "undefined-behavior"
			r.CrashSite = strings.TrimSpace(m[1])
		}
	}

	if r.Fired {
		r.DedupToken = dedupToken(r)
	}
	return r
}

// the non-gameability boundary: only a memory-safety fault signal corroborates a report
func corroborateSanitizer(rr oracle.RunResult) oracle.SanitizerReport {
	if !rr.Sanitizer.Fired {
		return rr.Sanitizer
	}
	if oracle.IsCrashSignal(rr.TermSignal) {
		return rr.Sanitizer
	}
	return oracle.SanitizerReport{}
}

func extractFrames(text string) []string {
	ms := reFrameN.FindAllStringSubmatch(text, -1)
	if len(ms) == 0 {
		return nil
	}
	var frames []string
	started := false
	for _, m := range ms {
		if m[1] == "0" {
			if started {
				break
			}
			started = true
		}
		if !started {
			continue
		}
		frames = append(frames, cleanSymbol(m[2]))
	}
	for len(frames) > 1 && isNoiseFrame(frames[0]) {
		frames = frames[1:]
	}
	if len(frames) > maxFrames {
		frames = frames[:maxFrames]
	}
	return frames
}

func isNoiseFrame(sym string) bool {
	s := strings.ToLower(sym)
	if strings.HasPrefix(s, "asan_") {
		return true
	}
	for _, n := range []string{
		"__interceptor_", "__asan_", "__sanitizer", "operator new", "operator delete",
		"malloc", "calloc", "realloc", "free", "memcpy", "memmove", "memset", "strcpy", "strcat",
	} {
		if strings.HasPrefix(s, n) {
			return true
		}
	}
	return false
}

// strips a trailing source location the greedy frame capture appended
var reLocSuffix = regexp.MustCompile(`\s+\S*:\d+(?::\d+)?$`)

func cleanSymbol(s string) string {
	s = strings.TrimSpace(s)
	if m := reLocSuffix.FindStringIndex(s); m != nil {
		s = s[:m[0]]
	}
	if i := strings.Index(s, " /"); i > 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

func dedupToken(r oracle.SanitizerReport) string {
	return strings.ToLower(r.Tool + ":" + r.BugClass + ":" + r.CrashSite)
}
