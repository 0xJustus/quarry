package loop

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/0xjustus/quarry/internal/platform/model"
	"github.com/0xjustus/quarry/internal/platform/router"
)

// WorkItem is a defensive assessment only; it carries no attack angle (vault: Loop Analyst).
type WorkItem struct {
	TargetSection string `json:"target_section"`
	Reachability  string `json:"reachability"`
	BugClass      string `json:"bug_class"`
	Concern       string `json:"concern"`
	PriorArt      string `json:"prior_art,omitempty"`
	Rank          int    `json:"rank,omitempty"`
}

func FormatWorkItem(w WorkItem) string {
	sec := strings.TrimSpace(w.TargetSection)
	reach := strings.TrimSpace(w.Reachability)
	bug := strings.TrimSpace(w.BugClass)
	concern := strings.TrimSpace(w.Concern)
	prior := strings.TrimSpace(w.PriorArt)

	if sec == "" && reach == "" && bug == "" && concern == "" {
		return ""
	}
	var b strings.Builder
	b.WriteString("Investigate this audited lead — find an input that reaches this site and triggers the weakness, then submit it via run_pov; do not re-plan the whole search.\n")
	if sec != "" {
		b.WriteString("TARGET SECTION: ")
		b.WriteString(sec)
		b.WriteByte('\n')
	}
	if reach != "" {
		b.WriteString("REACHABILITY: ")
		b.WriteString(reach)
		b.WriteByte('\n')
	}
	if bug != "" {
		b.WriteString("SUSPECTED WEAKNESS: ")
		b.WriteString(bug)
		b.WriteByte('\n')
	}
	if concern != "" {
		b.WriteString("WHY CONCERNING: ")
		b.WriteString(concern)
		b.WriteByte('\n')
	}
	if prior != "" {
		b.WriteString("PRIOR ART: ")
		b.WriteString(prior)
		b.WriteByte('\n')
	}
	return strings.TrimSpace(b.String())
}

func UndirectedStatement(objective string) string {
	obj := strings.TrimSpace(objective)
	if obj == "" {
		obj = "find a vulnerability reachable from untrusted input"
	}
	return "UNDIRECTED EXPLORATION (breadth guardrail — do not rely on the analyst's ranking alone): " + obj
}

type ModelAnalyst struct {
	Model  model.Model
	Router router.Router
}

const (
	analystMaxFiles      = 600
	analystMaxFileBytes  = 32 << 10
	analystMaxTotalBytes = 256 << 10
	analystMaxCandidates = 20000
	analystMaxReadBytes  = 8 << 20 // OOM guard on a single read (vault: Loop Analyst)
	inventoryBoostCap    = 60
)

const proposeWorkItemsSchema = `{"type":"object","properties":{"work_items":{"type":"array","items":{"type":"object","properties":{"target_section":{"type":"string","description":"risky site: file path plus symbol or function, e.g. src/ttgload.c:load_truetype_glyph"},"reachability":{"type":"string","description":"how untrusted input reaches this section"},"bug_class":{"type":"string","description":"suspected weakness class, e.g. heap-buffer-overflow, use-after-free, integer-overflow"},"concern":{"type":"string","description":"why the weakness is concerning: what makes the reachable code unsafe here (a defensive assessment, NEVER an attack, exploit, or input to send)"},"prior_art":{"type":"string","description":"optional: a verified pattern this resembles"},"rank":{"type":"integer","description":"1 = highest priority"}},"required":["target_section","reachability","bug_class","concern"]}}},"required":["work_items"]}`

func (a ModelAnalyst) Plan(ctx context.Context, req PlanRequest) ([]Hypothesis, error) {
	inventory := req.SourceInventory
	var sinks []Sink
	if len(req.SeedFiles) > 0 {
		sinks = scanSinks(req.SeedFiles)
	}
	if inventory == "" && len(req.SeedFiles) > 0 {
		inventory = buildSourceInventory(req.SeedFiles, sinkScores(sinks))
	}

	sys := `You are quarry's Analyst (ADR-0006): a defensive SECURITY AUDITOR reviewing seeded source to help maintainers find and fix latent input-handling weaknesses. You READ the code and produce a vulnerability ASSESSMENT — where the code is weak, how untrusted input reaches it, and why that is concerning. You do NOT write, run, or plan attacks, exploits, or inputs: a separate Executor and a coverage-guided fuzzer synthesize and test the actual inputs. Your job is the review; theirs is the reproduction.

Call propose_work_items exactly once, passing a ranked work_items array (rank 1 = highest priority). Every item MUST fill all four required fields, each as specifically as the source allows:
- target_section: the risky site — exact workspace-relative file path plus the enclosing symbol/function, e.g. src/ttgload.c:load_truetype_glyph. When a lead targets a listed sinkpoint, pin target_section to that site's file:line.
- reachability: the concrete path by which untrusted input reaches this section. Name the entry point (the harness/API/parse function that first consumes untrusted bytes) and trace the call chain down to the section as far as the source lets you follow it.
- bug_class: the suspected weakness as a canonical sanitizer label — heap-buffer-overflow, stack-buffer-overflow, use-after-free, double-free, integer-overflow, oob-read, oob-write, and the like.
- concern: the DEFENSIVE rationale — what makes this reachable code unsafe (e.g. a length/count field read from input and used without a bounds check before a copy; a declared size trusted over the actual buffer; an index derived from input without validation). Describe the WEAKNESS and why it is dangerous — never how to exploit it, never an input to send. Producing the offense is the Executor's job.
Optional per item: prior_art (a verified pattern this resembles) and rank.

Ranking and direction:
- Rank by severity × reachability: a clearly-reachable memory-unsafe site outranks a deep or speculative one.
- If a STATIC SINKPOINTS list is supplied, prefer leads whose reachability path terminates at one of those call-sites, cite that site's file:line, and weight [H]igh sinks above [M]edium. The map is a ranking heuristic, not exhaustive — you may also flag a strong lead the scanner missed.
- If PRIOR ART is supplied, prefer matching weakness classes and sites.
- Prefer specific, independently checkable findings over vague themes; one precise finding beats three broad ones.

You assess and distribute — you do NOT gate. A deterministic oracle confirms every candidate downstream, so a weak or uncertain finding costs only recall, never soundness: when a section looks plausibly reachable and unsafe, report it rather than withhold it.`

	user := "OBJECTIVE:\n" + req.Objective
	if req.TargetDesc != "" {
		user += "\n\nTARGET:\n" + req.TargetDesc
	}
	if inventory != "" {
		user += "\n\nSEEDED SOURCE (read-only inventory; paths are workspace-relative under the seed base name):\n" + inventory
	} else {
		user += "\n\n(No source inventory was provided. Infer plausible sections from the objective and target description; keep items concrete.)"
	}
	if sm := renderSinkMap(sinks, sinkMapMax); sm != "" {
		user += "\n\n" + sm
	}
	if len(req.PriorArt) > 0 {
		user += "\n\nPRIOR ART — bugs already found in code like this; prefer matching bug classes and sites:\n" + strings.Join(req.PriorArt, "\n")
	}

	undirected := req.Undirected
	if undirected < 0 {
		undirected = 0
	}
	directedMax := req.Max
	if directedMax <= 0 {
		directedMax = 6
	}
	if undirected > 0 && undirected >= directedMax {
		undirected = 1
		if directedMax <= 1 {
			undirected = 0
		}
	}
	directedCap := directedMax - undirected
	if directedCap < 1 {
		directedCap = 1
	}
	user += "\n\nPropose at most " + itoa(directedCap) + " ranked work items (highest priority first)."

	m := ""
	if a.Router != nil {
		m = a.Router.Pick(router.RoleAnalyst, router.OpenReasoning, router.Budget{}).Model
	}

	chatReq := model.ChatRequest{
		Model: m,
		Messages: []model.Message{
			{Role: "system", Content: sys},
			{Role: "user", Content: user},
		},
		Tools: []model.ToolDef{{
			Name:        "propose_work_items",
			Description: "Return ranked structured work items for executors.",
			Parameters:  json.RawMessage(proposeWorkItemsSchema),
		}},
	}
	resp, err := a.Model.Chat(ctx, chatReq)
	if err != nil {
		// retry once on the SAME strong tier with a defensive reframe; never drop to cheap (vault: Loop Analyst)
		chatReq.Messages[0].Content = "This is a DEFENSIVE security code review for hardening a program the maintainers own. Report only where the code is weak and why that is dangerous; never describe how to exploit it or what input to send.\n\n" + sys
		resp, err = a.Model.Chat(ctx, chatReq)
	}
	if err != nil {
		return nil, err
	}

	items := parseWorkItems(resp)
	// honor Rank before truncating to directedCap (vault: Loop Analyst)
	sort.SliceStable(items, func(i, j int) bool {
		return rankKey(items[i].Rank) < rankKey(items[j].Rank)
	})
	if len(items) > directedCap {
		items = items[:directedCap]
	}

	var seedIndex map[string]string
	if len(req.SeedFiles) > 0 {
		seedIndex = buildSeedIndex(req.SeedFiles)
	}
	var hyps []Hypothesis
	for _, w := range items {
		if s := FormatWorkItem(w); s != "" {
			h := Hypothesis{Statement: s}
			if c := scopeCenterFor(seedIndex, w.TargetSection); c != "" {
				h.Scope = []string{c}
			}
			hyps = append(hyps, h)
		}
	}
	if len(hyps) == 0 {
		hyps = []Hypothesis{{Statement: req.Objective}}
	}

	for i := 0; i < undirected; i++ {
		hyps = append(hyps, Hypothesis{Statement: UndirectedStatement(req.Objective)})
	}
	if req.Max > 0 && len(hyps) > req.Max {
		hyps = hyps[:req.Max]
	}
	return hyps, nil
}

func parseWorkItems(resp model.ChatResponse) []WorkItem {
	var items []WorkItem
	for _, tc := range resp.Message.ToolCalls {
		if tc.Name != "propose_work_items" {
			continue
		}
		var args struct {
			WorkItems []WorkItem `json:"work_items"`
		}
		if err := json.Unmarshal([]byte(tc.Arguments), &args); err != nil {
			continue
		}
		for _, w := range args.WorkItems {
			if strings.TrimSpace(w.TargetSection) == "" && strings.TrimSpace(w.Concern) == "" {
				continue
			}
			items = append(items, w)
		}
	}
	if len(items) == 0 && resp.Message.Content != "" {
		items = append(items, workItemsFromContent(resp.Message.Content)...)
	}
	return items
}

const rankUnset = 1 << 30 // unranked items sort after every explicitly-ranked one

func rankKey(r int) int {
	if r <= 0 {
		return rankUnset
	}
	return r
}

// workItemsFromContent decodes the first '{' yielding a non-empty work_items array (vault: Loop Analyst).
func workItemsFromContent(s string) []WorkItem {
	for i := 0; i < len(s); i++ {
		if s[i] != '{' {
			continue
		}
		var args struct {
			WorkItems []WorkItem `json:"work_items"`
		}
		if err := json.NewDecoder(strings.NewReader(s[i:])).Decode(&args); err != nil {
			continue
		}
		var out []WorkItem
		for _, w := range args.WorkItems {
			if strings.TrimSpace(w.TargetSection) != "" || strings.TrimSpace(w.Concern) != "" {
				out = append(out, w)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	return nil
}

// walkSourceCandidates visits each eligible source file (visit returns false to stop), a shared file set (vault: Loop Analyst).
func walkSourceCandidates(paths []string, visit func(path, label string) bool) {
	seen := 0
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			continue
		}
		if !info.IsDir() {
			if seen >= analystMaxCandidates || !visit(p, filepath.Base(p)) {
				return
			}
			seen++
			continue
		}
		base := filepath.Base(p)
		stopped := false
		_ = filepath.WalkDir(p, func(fp string, d os.DirEntry, werr error) error {
			if werr != nil {
				return nil
			}
			name := d.Name()
			if d.IsDir() {
				if fp != p && (strings.HasPrefix(name, ".") || skipInventoryDir(name)) {
					return filepath.SkipDir
				}
				return nil
			}
			if strings.HasPrefix(name, ".") || skipInventoryExt(filepath.Ext(name)) {
				return nil
			}
			if seen >= analystMaxCandidates {
				return filepath.SkipAll
			}
			rel, rerr := filepath.Rel(p, fp)
			if rerr != nil {
				return nil
			}
			if !visit(fp, filepath.Join(base, rel)) {
				stopped = true
				return filepath.SkipAll
			}
			seen++
			return nil
		})
		if stopped {
			return
		}
	}
}

// buildSourceInventory renders a budgeted, score-ordered inventory; boost lifts dangerous files, nil boost is a no-op (vault: Loop Analyst).
func buildSourceInventory(paths []string, boost map[string]int) string {
	type cand struct {
		path, label string
		score       int
	}
	var cands []cand
	walkSourceCandidates(paths, func(path, label string) bool {
		s := inventoryScore(label)
		if b := boost[label]; b > 0 {
			if b > inventoryBoostCap {
				b = inventoryBoostCap
			}
			s += b
		}
		cands = append(cands, cand{path: path, label: label, score: s})
		return true
	})

	// path is a deterministic tiebreak (no map iteration) so a tree yields a stable inventory
	sort.SliceStable(cands, func(i, j int) bool {
		if cands[i].score != cands[j].score {
			return cands[i].score > cands[j].score
		}
		return cands[i].label < cands[j].label
	})

	var b strings.Builder
	total, files := 0, 0
	for _, c := range cands {
		if files >= analystMaxFiles || total >= analystMaxTotalBytes {
			break
		}
		excerpt, n := fileExcerpt(c.path, c.label, analystMaxFileBytes)
		if excerpt == "" {
			continue
		}
		if total+n > analystMaxTotalBytes {
			continue // a smaller later file may still fit
		}
		b.WriteString(excerpt)
		total += n
		files++
	}
	return b.String()
}

func skipInventoryExt(ext string) bool {
	switch strings.ToLower(ext) {
	case ".o", ".a", ".so", ".dylib", ".dll", ".exe", ".bin", ".png", ".jpg", ".jpeg",
		".gif", ".pdf", ".zip", ".gz", ".tgz", ".bz2", ".xz", ".wasm", ".pyc", ".class",
		".ttf", ".otf", ".woff", ".woff2", ".ico", ".mp3", ".mp4", ".lock":
		return true
	}
	return false
}

// skipInventoryDir prunes subtrees that never hold target source; test dirs are demoted, not pruned.
func skipInventoryDir(name string) bool {
	switch strings.ToLower(name) {
	case "docs", "doc", "build", "builds", "vendor", "third_party", "thirdparty",
		"node_modules", "objs", "obj", "cmake", "autom4te.cache", "m4", "aclocal",
		"dist", "out", "target", "coverage", "testdata", "corpus", "corpora", "seeds":
		return true
	}
	return false
}

// inventoryScore ranks a path so the byte budget lands on likely-vulnerable source first. Deterministic.
func inventoryScore(rel string) int {
	lower := strings.ToLower(rel)
	score := 0
	switch strings.ToLower(filepath.Ext(rel)) {
	case ".c", ".cc", ".cpp", ".cxx", ".c++", ".m", ".mm":
		score += 100
	case ".rs", ".go", ".zig", ".swift":
		score += 90
	case ".h", ".hpp", ".hh", ".hxx", ".inc", ".ipp":
		score += 60
	case ".java", ".kt", ".cs", ".js", ".ts", ".py", ".rb", ".php":
		score += 50
	default:
		score += 10
	}
	if strings.HasPrefix(lower, "src") || strings.Contains(lower, "/src/") || strings.Contains(lower, "/lib/") {
		score += 20
	}
	for _, kw := range []string{"pars", "decod", "load", "read", "scan", "lex", "token", "inflate", "demux", "unpack"} {
		if strings.Contains(lower, kw) {
			score += 15
			break
		}
	}
	for _, kw := range []string{"test", "example", "sample", "demo", "mock", "fixture", "benchmark"} {
		if strings.Contains(lower, kw) {
			score -= 40
			break
		}
	}
	score -= strings.Count(rel, string(filepath.Separator))
	return score
}

// fileExcerpt returns a UTF-8 head excerpt, reading at most maxBytes+1 (OOM guard, vault: Loop Analyst).
func fileExcerpt(path, label string, maxBytes int) (string, int) {
	fi, err := os.Stat(path)
	if err != nil || fi.IsDir() || fi.Size() > analystMaxReadBytes {
		return "", 0
	}
	f, err := os.Open(path)
	if err != nil {
		return "", 0
	}
	defer f.Close()
	// the extra byte signals whether the file exceeded the cap
	data, err := io.ReadAll(io.LimitReader(f, int64(maxBytes)+1))
	if err != nil {
		return "", 0
	}
	truncated := len(data) > maxBytes
	if truncated {
		data = data[:maxBytes]
	}
	if !utf8.Valid(data) {
		// salvage a rune split by the byte cut; still-invalid is a real binary → skip
		for k := 0; k < 3 && len(data) > 0 && !utf8.Valid(data); k++ {
			data = data[:len(data)-1]
		}
		if !utf8.Valid(data) || len(data) == 0 {
			return "", 0
		}
	}
	var b strings.Builder
	b.WriteString("--- ")
	b.WriteString(label)
	b.WriteString(" ---\n")
	b.Write(data)
	if truncated {
		b.WriteString("\n… [truncated]\n")
	}
	b.WriteByte('\n')
	return b.String(), b.Len()
}
