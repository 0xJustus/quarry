package loop

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/0xjustus/quarry/internal/discover/agent"
	"github.com/0xjustus/quarry/internal/platform/model"
	"github.com/0xjustus/quarry/internal/platform/router"
	"github.com/0xjustus/quarry/internal/verdict/oracle"
	"github.com/0xjustus/quarry/internal/verdict/verify"
)

const authorReferenceSchema = `{"type":"object","properties":{"reference_source":{"type":"string","description":"C/C++ source of a CORRECT reference: read argv[1] (the input file), print the correct output to stdout, exit 0. Same I/O as the target."},"language":{"type":"string","enum":["c","cpp"]}},"required":["reference_source"]}`

// fail open on missing infra, fail closed on a run vote (vault: Loop Directors)
func (l *Loop) corroborateDivergence(ctx context.Context, sess *agent.Session, req Request, res *verify.Result) (bool, string) {
	if res == nil || res.Verdict.Differential == nil || res.Verdict.Differential.Rule != oracle.DivergeOnOutput {
		return true, ""
	}
	if res.Fixed == nil || sess == nil || l.Model == nil || l.Runner == nil {
		return true, "corroboration unavailable (missing reference run / model / runner) — accepted un-corroborated"
	}
	// empty ReferenceSource ⇒ operator-declared: a model must never veto ground truth
	if strings.TrimSpace(sess.ReferenceSource) == "" {
		return true, "reference is operator-declared (descriptor ground truth, not model-authored) — no vote needed"
	}
	seed := readSeedSource(req.SeedFiles)
	if strings.TrimSpace(seed) == "" {
		return true, "no seed source to author an independent reference from — accepted un-corroborated"
	}
	src, lang, ok := l.authorStrongReference(ctx, seed)
	if !ok {
		return true, "strong-tier reference authoring unavailable — accepted un-corroborated"
	}
	img, compileErr, err := agent.BuildReferenceImage(ctx, l.DockerBin, src, lang)
	if err != nil || compileErr != "" {
		return true, "strong-tier reference did not build — accepted un-corroborated"
	}
	// must go through ReferenceRunSpec: sess.Base's argv[0] is the target's, absent here
	spec := agent.ReferenceRunSpec(sess.Base, img)
	spec.PoV = sess.ConfirmedPoV
	strongRun, rerr := l.Runner.Run(ctx, spec)
	if rerr != nil {
		return true, "strong-tier reference run failed — accepted un-corroborated"
	}

	// fail closed: did-not-run is its own state, never equal to a clean run
	if why := referenceUnfit("the executor's reference", *res.Fixed); why != "" {
		return false, "divergence INCONCLUSIVE: " + why + " — a reference that did not run cannot corroborate anything"
	}
	if why := referenceUnfit("the strong-tier reference", strongRun); why != "" {
		return false, "divergence INCONCLUSIVE: " + why + " — a reference that did not run cannot corroborate anything"
	}

	// hang divergence: completion is the signal, the returned values are irrelevant
	if res.Primary.TimedOut || res.Primary.OOMKilled {
		return true, "corroborated: target hangs where both independent references return (DoS divergence)"
	}

	return corroborationVote(oracle.Observe(res.Primary), oracle.Observe(*res.Fixed), oracle.Observe(strongRun))
}

// "" only when the run honored the contract: read input, print output, exit 0
func referenceUnfit(who string, r oracle.RunResult) string {
	switch {
	case r.TimedOut:
		return who + " did not complete (timed out)"
	case r.OOMKilled:
		return who + " did not complete (OOM-killed)"
	case r.TermSignal != 0:
		return fmt.Sprintf("%s was killed by signal %d", who, r.TermSignal)
	case r.Sanitizer.Fired:
		return fmt.Sprintf("%s tripped %s (%s)", who, r.Sanitizer.Tool, r.Sanitizer.BugClass)
	case r.ExitCode != 0:
		return fmt.Sprintf("%s exited %d (its contract is: print the correct output, exit 0)", who, r.ExitCode)
	}
	return ""
}

// oracle.Observation is the one definition of the observable set a divergence is decided on
func corroborationVote(target, execRef, strongRef oracle.Observation) (bool, string) {
	switch {
	case strongRef == execRef && target != execRef:
		return true, fmt.Sprintf("corroborated: two independent references agree (%s); target dissents (%s)", execRef, target)
	case strongRef == target:
		return false, fmt.Sprintf("the strong-tier reference AGREES with the target (%s); the executor's reference (%s) was wrong — spurious divergence", target, execRef)
	default:
		return false, fmt.Sprintf("references disagree (executor=%s strong=%s target=%s) — divergence not corroborated", execRef, strongRef, target)
	}
}

// answer must be parsed from CONTENT: the strong tier's proxy ignores request tools
func (l *Loop) authorStrongReference(ctx context.Context, seed string) (string, string, bool) {
	m := ""
	if l.Router != nil {
		m = l.Router.Pick(router.RoleAnalyst, router.OpenReasoning, router.Budget{}).Model
	}
	sys := "You are verifying a candidate finding. Below is a target program under audit. INDEPENDENTLY author a CORRECT reference implementation of what the program is SPECIFIED to do (read its contract in the comments), with the SAME input/output contract: read the input file at argv[1], print the correct output to stdout, exit 0. Implement the SPEC, not the program's current (possibly buggy) behavior — and RESPECT documented idioms (intentional wraparound, saturation, biased/encoded fields, guarded operations) as part of the spec, not as bugs. Respond with ONLY the reference source in a single fenced code block: ```c … ``` (or ```cpp … ``` for C++). No prose before or after."
	resp, err := l.Model.Chat(ctx, model.ChatRequest{
		Model: m,
		Messages: []model.Message{
			{Role: "system", Content: sys},
			{Role: "user", Content: "Target program:\n\n" + seed},
		},
		Tools: []model.ToolDef{{Name: "author_reference", Description: "Return the reference implementation source.", Parameters: json.RawMessage(authorReferenceSchema)}},
	})
	if err != nil {
		return "", "", false
	}
	for _, tc := range resp.Message.ToolCalls {
		if tc.Name != "author_reference" {
			continue
		}
		var a struct {
			ReferenceSource string `json:"reference_source"`
			Language        string `json:"language"`
		}
		if json.Unmarshal([]byte(tc.Arguments), &a) == nil && strings.TrimSpace(a.ReferenceSource) != "" {
			return a.ReferenceSource, a.Language, true
		}
	}
	return extractReferenceSource(resp.Message.Content)
}

func extractReferenceSource(content string) (string, string, bool) {
	looksLikeSource := func(s string) bool {
		return strings.Contains(s, "#include") && strings.Contains(s, "main")
	}
	langOf := func(info, body string) string {
		info = strings.ToLower(strings.TrimSpace(info))
		if strings.Contains(info, "cpp") || strings.Contains(info, "c++") || strings.Contains(info, "cxx") {
			return "cpp"
		}
		if info == "c" {
			return "c"
		}
		if strings.Contains(body, "std::") || strings.Contains(body, "iostream") || strings.Contains(body, "<string>") {
			return "cpp"
		}
		return "c"
	}
	if i := strings.Index(content, "```"); i >= 0 {
		rest := content[i+3:]
		nl := strings.IndexByte(rest, '\n')
		if nl >= 0 {
			info := rest[:nl]
			body := rest[nl+1:]
			if end := strings.Index(body, "```"); end >= 0 {
				body = body[:end]
			}
			if src := strings.TrimSpace(body); looksLikeSource(src) {
				return src, langOf(info, src), true
			}
		}
	}
	if src := strings.TrimSpace(content); looksLikeSource(src) {
		return src, langOf("", src), true
	}
	return "", "", false
}

func readSeedSource(paths []string) string {
	const cap = 20000
	var b strings.Builder
	// dedup by resolved path: a doubled harness breaks the differential-fuzz combine
	seen := map[string]bool{}
	add := func(p string) {
		if b.Len() >= cap {
			return
		}
		abs, err := filepath.Abs(p)
		if err != nil {
			abs = p
		}
		if seen[abs] {
			return
		}
		seen[abs] = true
		data, err := os.ReadFile(p)
		if err != nil {
			return
		}
		if b.Len()+len(data) > cap {
			data = data[:cap-b.Len()]
		}
		b.WriteString("// " + filepath.Base(p) + "\n")
		b.Write(data)
		b.WriteString("\n")
	}
	isSrc := func(name string) bool {
		switch filepath.Ext(name) {
		case ".c", ".cc", ".cpp", ".cxx", ".h", ".hpp":
			return true
		}
		return false
	}
	for _, p := range paths {
		fi, err := os.Stat(p)
		if err != nil {
			continue
		}
		if fi.IsDir() {
			entries, _ := os.ReadDir(p)
			for _, e := range entries {
				if !e.IsDir() && isSrc(e.Name()) {
					add(filepath.Join(p, e.Name()))
				}
			}
		} else {
			add(p)
		}
	}
	return b.String()
}
