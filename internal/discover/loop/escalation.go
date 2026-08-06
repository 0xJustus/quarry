package loop

import "strings"

// escalationWarm reports whether a depth-0 directed lead is "warm" enough for ONE strong-tier retry (vault: Loop Core).
func escalationWarm(res scientistResult, depth int, statement string) bool {
	if depth != 0 || res.finding != nil {
		return false
	}
	if strings.HasPrefix(statement, "UNDIRECTED EXPLORATION") {
		return false
	}
	// cleanly ruled out or errored: a strong retry of the same lead won't help.
	if res.stopReason == "model-concluded" || strings.HasPrefix(res.stopReason, "error") {
		return false
	}
	// warm: near-miss candidate PoVs, or budget-truncated (still hunting when it stopped).
	return res.povSubmissions > 0 ||
		res.stopReason == "max-iters" || res.stopReason == "stall" || res.stopReason == "token-budget"
}

// mergeEscalation folds a strong-tier retry into the base result: the escalated finding wins; costs accumulate.
func mergeEscalation(base, esc scientistResult) scientistResult {
	base.iterations += esc.iterations
	addUsage(&base.usage, esc.usage)
	base.povSubmissions += esc.povSubmissions
	if esc.finding != nil {
		base.finding = esc.finding
		base.stopReason = esc.stopReason
		base.finalMessage = esc.finalMessage
		base.spawned = esc.spawned
		return base
	}
	base.stopReason = "escalated→" + esc.stopReason
	if esc.finalMessage != "" {
		base.finalMessage = esc.finalMessage
	}
	if len(esc.spawned) > 0 {
		base.spawned = esc.spawned
	}
	return base
}
