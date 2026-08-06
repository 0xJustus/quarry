package loop

import (
	"context"
	"fmt"
	"strings"

	"github.com/0xjustus/quarry/internal/discover/agent"
	"github.com/0xjustus/quarry/internal/discover/cpg"
	"github.com/0xjustus/quarry/internal/publish/channels"
)

// cpgQuerier adapts a *cpg.Client (Joern CPG, ADR-0007) to agent.CPGQuerier; only SinkSites is rendered to strings.
type cpgQuerier struct{ *cpg.Client }

func (q cpgQuerier) SinkSites(ctx context.Context) ([]string, error) {
	sites, err := q.Client.Sinks(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(sites))
	for _, s := range sites {
		out = append(out, fmt.Sprintf("%s in %s:%d", s.Callee, s.Func, s.Line))
	}
	return out, nil
}

// MissingAuthz adapts cpg.Client's AuthzResult to the agent.CPGQuerier signature (Next Builds #6a).
func (q cpgQuerier) MissingAuthz(ctx context.Context, entry, sink, authGate string) (reachesSink, unauthedPath, authPresent bool, err error) {
	r, e := q.Client.MissingAuthz(ctx, entry, sink, authGate)
	return r.ReachesSink, r.UnauthedPath, r.AuthPresent, e
}

// openCPG attaches a warm Joern session for req.CPGPath; returns (nil, no-op) when unconfigured or on failure (recall, not soundness).
func (l *Loop) openCPG(ctx context.Context, req Request) (agent.CPGQuerier, func()) {
	if req.CPGPath == "" {
		return nil, func() {}
	}
	cc := cpg.New(req.CPGPath)
	if err := cc.Open(ctx); err != nil {
		l.log("cpg: could not open %s: %v (continuing without CPG tools)", req.CPGPath, err)
		return nil, func() {}
	}
	l.log("cpg: warm Joern session attached (%s) — cpg_reaches/taint/bounds/sinks/callers/callees available (ADR-0007)", req.CPGPath)
	l.annotateCPGFromCommons(ctx, req, cc)
	return cpgQuerier{cc}, func() { _ = cc.Close() }
}

// annotateCPGFromCommons is the ADR-0007 catalyst: keys commons prior art onto CPG nodes by crash-stack symbols. Best-effort.
func (l *Loop) annotateCPGFromCommons(ctx context.Context, req Request, cc *cpg.Client) {
	if l.Primer == nil {
		return
	}
	pa, err := l.Primer.Prime(ctx, PrimeQuery{Objective: req.Objective, TargetDesc: req.TargetDesc, K: primeK})
	if err != nil || len(pa) == 0 {
		return
	}
	if ann := buildNodeAnnotations(pa); len(ann) > 0 {
		cc.NodeAnnotations = ann
		l.log("cpg: catalyst — annotated %d function symbol(s) with commons prior art (ADR-0007)", len(ann))
	}
}

// buildNodeAnnotations keys prior-art tags by each artifact's simplified crash-stack symbols.
func buildNodeAnnotations(pa []channels.PriorArt) map[string][]cpg.PriorArtTag {
	ann := map[string][]cpg.PriorArtTag{}
	for _, a := range pa {
		tag := cpg.PriorArtTag{BugClass: a.BugClass, Abstract: a.Abstract}
		for _, raw := range a.Sites {
			if sym := simplifySymbol(raw); sym != "" {
				ann[sym] = append(ann[sym], tag)
			}
		}
	}
	return ann
}

// simplifySymbol reduces a crash-stack frame to a bare function name so it matches CPG node names.
func simplifySymbol(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '('); i >= 0 { // drop "(args...)"
		s = s[:i]
	}
	if i := strings.LastIndexByte(s, ' '); i >= 0 { // drop "returnType " prefix
		s = s[i+1:]
	}
	if i := strings.LastIndex(s, "::"); i >= 0 { // keep the last namespace/class segment
		s = s[i+2:]
	}
	if i := strings.IndexByte(s, '<'); i >= 0 { // drop a trailing "<template...>" on the segment
		s = s[:i]
	}
	return strings.TrimSpace(s)
}
