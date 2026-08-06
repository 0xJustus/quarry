package loop

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"

	"github.com/0xjustus/quarry/internal/verdict/oracle"
	"github.com/0xjustus/quarry/internal/verdict/verify"
)

// priorAttemptBudget bounds the rendered failed-attempt context so a child prompt stays compact.
const priorAttemptBudget = 700

// renderFailedAttempt distills a failed PoV attempt into a bounded note the next line refines from (ADR-0005); "" if nothing to learn.
func renderFailedAttempt(pov []byte, res *verify.Result, rationale string) string {
	if res == nil || len(pov) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("PREVIOUS ATTEMPT ON THIS LEAD (failed — diagnose and CHANGE it; do not resubmit it verbatim):\n")
	fmt.Fprintf(&b, "- input tried (%d bytes): %s\n", len(pov), inputPreview(pov, 120))
	if d := failureDetail(res.Verdict.Conditions); d != "" {
		fmt.Fprintf(&b, "- why the oracle did not fire: %s\n", d)
	}
	if pc := res.Verdict.PartialCredit; len(pc) > 0 {
		fmt.Fprintf(&b, "- interesting signals seen (near-miss): %s\n", strings.Join(pc, ", "))
	}
	if r := strings.TrimSpace(rationale); r != "" {
		fmt.Fprintf(&b, "- the prior line's own conclusion: %s\n", clip(r, 260))
	}
	return clip(b.String(), priorAttemptBudget)
}

// failureDetail lists the oracle conditions that did NOT match, so the next line knows what to steer toward.
func failureDetail(conds []oracle.ConditionResult) string {
	var unmet []string
	for _, c := range conds {
		if !c.Matched {
			unmet = append(unmet, string(c.Type)+": "+c.Detail)
		}
	}
	if len(unmet) == 0 {
		return ""
	}
	if len(unmet) > 3 {
		unmet = append(unmet[:3], "(+"+strconv.Itoa(len(unmet)-3)+" more)")
	}
	return strings.Join(unmet, "; ")
}

// inputPreview renders leading PoV bytes as printable text, falling back to hex for binary input.
func inputPreview(b []byte, max int) string {
	if len(b) > max {
		b = b[:max]
	}
	printable := 0
	for _, r := range b {
		if r == '\n' || r == '\t' || (r >= 0x20 && r < 0x7f) {
			printable++
		}
	}
	if len(b) > 0 && printable*100/len(b) >= 80 {
		s := strings.Map(func(r rune) rune {
			if r == '\n' || r == '\t' {
				return ' '
			}
			if unicode.IsPrint(r) {
				return r
			}
			return '.'
		}, string(b))
		return strconv.Quote(s)
	}
	return "hex:" + hexPrefix(b, 48)
}

func hexPrefix(b []byte, n int) string {
	if len(b) > n {
		b = b[:n]
	}
	const hexdigits = "0123456789abcdef"
	var sb strings.Builder
	for _, c := range b {
		sb.WriteByte(hexdigits[c>>4])
		sb.WriteByte(hexdigits[c&0x0f])
	}
	return sb.String()
}

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return strings.TrimSpace(s[:n]) + "…"
	}
	return s
}
