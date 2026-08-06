// Package corpus mines silent security-fix commits into -vuln/-fix differential pairs.
package corpus

import (
	"regexp"
	"strings"
)

type Commit struct {
	SHA     string
	Subject string
	Body    string
	Files   []string
	Added   int
	Deleted int
	Diff    string // may be truncated by the miner
}

type Signal struct {
	Name   string
	Weight int
}

type Classification struct {
	Label    string // "security-fix" | "refactor" | "uncertain"
	Score    int
	Signals  []Signal
	Category string // "memory-safety" | "output-divergence" | ""
}

func (c Classification) IsSecurityFix() bool { return c.Label == "security-fix" }

func (c Classification) IsOutputDivergence() bool { return c.Category == "output-divergence" }

var (
	reCVE        = regexp.MustCompile(`(?i)\bCVE-\d{4}-\d{3,}\b`)
	reStrongVuln = regexp.MustCompile(`(?i)\b(buffer overflow|heap overflow|stack overflow|out[- ]of[- ]bounds|out of bound|use[- ]after[- ]free|double[- ]free|integer overflow|integer underflow|oob (read|write)|oob\b|null (pointer )?deref|uninitialized (read|memory)|type confusion|off[- ]by[- ]one|format string|command injection|sql injection|path traversal|ssrf|xxe|memory corruption|heap corruption|invalid free|wild pointer|dangling pointer)\b`)
	reSanitizer  = regexp.MustCompile(`(?i)\b(asan|ubsan|msan|tsan|addresssanitizer|oss-?fuzz|clusterfuzz|fuzzer found|found by fuzz)\b`)
	reMediumSec  = regexp.MustCompile(`(?i)\b(security|vulnerab|exploit|attacker|malicious|untrusted input|sanitize|overread|over-read|underflow|bounds check|missing check|missing validation|validate (the )?(length|size|input|bounds))\b`)
	reFixVerb    = regexp.MustCompile(`(?i)\b(fix(e[sd])?|correct(ed|s)?|prevent|guard against|reject|handle)\b`)
	// keep a bare "dos" OUT: it matches DOS/MS-DOS file-format commits, not crashes (vault: Corpus and Grading)
	reCrashy      = regexp.MustCompile(`(?i)\b(crash|segfault|sigsegv|sigabrt|abort|hang|infinite loop|denial of service|ddos|dos (attack|vector|condition|vulnerabilit\w*)|panic|assertion fail)\b`)
	reNegative    = regexp.MustCompile(`(?i)\b(refactor|rename|typo|whitespace|reformat|style|lint|cleanup|clean up|comment|docs?|documentation|readme|changelog|bump version|release|merge branch|revert|gofmt|clang-format)\b`)
	reTestOnly    = regexp.MustCompile(`(?i)\b(add (a )?test|unit test|test case|regression test|ci|workflow)\b`)
	reAddedBounds = regexp.MustCompile(`(?m)^\+.*\b(if|while)\b.*(<=?|>=?|==|!=)`)
	reAddedReturn = regexp.MustCompile(`(?m)^\+.*\b(return|goto|break|continue|abort|exit)\b`)
	reOutputTerms = regexp.MustCompile(`(?i)\b(parse|parser|serializ|deserializ|encod|decod|canonical|normaliz|round[- ]?trip|idempoten|unescape|escaping|escape|marshal|unmarshal|tokeniz|utf-?8|percent[- ]?encod|url[- ]?(en|de)cod|base64|checksum mismatch)\b`)
	reWrongOutput = regexp.MustCompile(`(?i)\b(incorrect(ly)?|wrong (output|result|value|answer|byte|character)|returns? the wrong|should (return|output|be)|mismatch|off[- ]by[- ]one|rounding (error|bug)|sign(ed|edness)? (error|bug|mismatch)|inconsistent (result|output|behavior))\b`)
	reCmpChange   = regexp.MustCompile(`(?m)^[-+].*(<=?|>=?|==|!=).*`)
	// the bound must be a LENGTH-ish identifier, not just len-prefixed (next/nodes must not false-match) (vault: Corpus and Grading)
	reAddedLenCk = regexp.MustCompile(`(?m)^\+.*\b(n|(\w+_)?(len|length|size|count|remaining|avail)(_\w+)?)\s*(<=?|>=?)`)
)

func Classify(c Commit) Classification {
	msg := c.Subject + "\n" + c.Body
	var sig []Signal
	add := func(name string, w int) { sig = append(sig, Signal{name, w}) }

	if reCVE.MatchString(msg) {
		add("cve-backlink", 6)
	}
	if reStrongVuln.MatchString(msg) {
		add("strong-vuln-term", 5)
	}
	if reSanitizer.MatchString(msg) {
		add("sanitizer/fuzzer-origin", 4)
	}
	if reMediumSec.MatchString(msg) {
		add("security-term", 2)
	}
	fixVerb := reFixVerb.MatchString(msg)
	crashy := reCrashy.MatchString(msg)
	if fixVerb && crashy {
		add("fix+crash", 3)
	} else if crashy {
		add("crash-term", 2)
	} else if fixVerb {
		add("fix-verb", 1)
	}

	if c.Diff != "" {
		if reAddedLenCk.MatchString(c.Diff) {
			add("added-length-check", 3)
		} else if reAddedBounds.MatchString(c.Diff) {
			add("added-guard", 2)
		}
		if reAddedReturn.MatchString(c.Diff) {
			add("added-early-out", 1)
		}
		if total := c.Added + c.Deleted; total > 0 && total <= 30 {
			add("surgical-diff", 1)
		} else if total > 400 {
			add("sprawling-diff", -2)
		}
	}

	outputTerm := reOutputTerms.MatchString(msg)
	wrongOutput := reWrongOutput.MatchString(msg)
	if outputTerm {
		add("output-logic-term", 4)
	}
	if wrongOutput {
		add("wrong-output-term", 3)
	}
	if c.Diff != "" && reCmpChange.MatchString(c.Diff) && !reAddedLenCk.MatchString(c.Diff) {
		add("changed-comparison", 1)
	}

	if reNegative.MatchString(msg) {
		add("refactor/doc/style-marker", -4)
	}
	if reTestOnly.MatchString(msg) && !reStrongVuln.MatchString(msg) && !reCVE.MatchString(msg) {
		add("test/ci-marker", -2)
	}
	if onlyNonCode(c.Files) {
		add("no-code-files", -5)
	}

	score := 0
	for _, s := range sig {
		score += s.Weight
	}
	// FAIL CLOSED: a security-fix label needs a corroborating asserted-defect signal, or an over-threshold perf/feature commit becomes a false-CONFIRM reference (vault: Corpus and Grading)
	corroborated := reCVE.MatchString(msg) || reStrongVuln.MatchString(msg) || reSanitizer.MatchString(msg) ||
		reMediumSec.MatchString(msg) || crashy || wrongOutput
	label := "uncertain"
	switch {
	case score >= 6 && corroborated:
		label = "security-fix"
	case score <= 1:
		label = "refactor"
	}
	if score >= 6 && !corroborated {
		add("uncorroborated-vocabulary-only", 0)
	}
	memSafety := reStrongVuln.MatchString(msg) || reSanitizer.MatchString(msg) || crashy
	category := ""
	switch {
	case (outputTerm || wrongOutput) && !memSafety:
		category = "output-divergence"
	case memSafety:
		category = "memory-safety"
	}
	return Classification{Label: label, Score: score, Signals: sig, Category: category}
}

func onlyNonCode(files []string) bool {
	if len(files) == 0 {
		return false
	}
	for _, f := range files {
		if isCodeFile(f) {
			return false
		}
	}
	return true
}

func isCodeFile(path string) bool {
	l := strings.ToLower(path)
	if strings.HasSuffix(l, ".md") || strings.HasSuffix(l, ".txt") || strings.HasSuffix(l, ".rst") {
		return false
	}
	// exclude tests per path SEGMENT + ext-stripped name; over-matching is safe (only subtracts) (vault: Corpus and Grading)
	segs := strings.Split(l, "/")
	for i, s := range segs {
		if i == len(segs)-1 {
			if dot := strings.LastIndex(s, "."); dot > 0 {
				s = s[:dot]
			}
		}
		if isTestName(s) {
			return false
		}
	}
	switch {
	case strings.HasSuffix(l, ".c"), strings.HasSuffix(l, ".h"), strings.HasSuffix(l, ".cc"),
		strings.HasSuffix(l, ".cpp"), strings.HasSuffix(l, ".cxx"), strings.HasSuffix(l, ".hpp"),
		strings.HasSuffix(l, ".cerr"):
		return true
	}
	return false
}

// test/tests as prefix or suffix; the plural spelling is the common one
func isTestName(s string) bool {
	return strings.HasPrefix(s, "test") || strings.HasSuffix(s, "test") || strings.HasSuffix(s, "tests")
}
