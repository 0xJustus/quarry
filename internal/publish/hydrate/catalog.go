package hydrate

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/0xjustus/quarry/internal/publish/artifact"
)

// ClusterFuzz signature: "Key: value" lines plus an indented frame block after "Crash State:".
var (
	reCrashType  = regexp.MustCompile(`(?m)^\s*Crash Type:\s*(.+?)\s*$`)
	reCrashState = regexp.MustCompile(`(?m)^\s*Crash State:\s*$`)
	reCFField    = regexp.MustCompile(`^\s*[A-Z][A-Za-z ]+:\s`) // a new field ends the frame block
)

type clusterFuzzCrash struct {
	CrashType string
	State     []string // call-ordered
}

// an ARVO-Meta report blob is a string OR {comments:[{content}]}
func reportText(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	if raw[0] == '"' {
		var s string
		if err := json.Unmarshal(raw, &s); err == nil {
			raw = json.RawMessage(s)
		}
	}
	var doc struct {
		Comments []struct {
			Content string `json:"content"`
		} `json:"comments"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return string(raw)
	}
	var b strings.Builder
	for _, c := range doc.Comments {
		b.WriteString(c.Content)
		b.WriteByte('\n')
	}
	return b.String()
}

func parseClusterFuzzCrash(report string) (clusterFuzzCrash, bool) {
	var cc clusterFuzzCrash
	if m := reCrashType.FindStringSubmatch(report); m != nil {
		cc.CrashType = strings.TrimSpace(m[1])
	}
	if loc := reCrashState.FindStringIndex(report); loc != nil {
		rest := report[loc[1]:]
		for _, line := range strings.Split(rest, "\n") {
			t := strings.TrimSpace(line)
			if t == "" {
				if len(cc.State) > 0 {
					break
				}
				continue
			}
			if reCFField.MatchString(line) {
				break
			}
			cc.State = append(cc.State, t)
			if len(cc.State) >= 12 {
				break
			}
		}
	}
	return cc, cc.CrashType != "" || len(cc.State) > 0
}

func catalogBugClass(crashType string) string {
	t := strings.TrimSpace(crashType)
	if t == "" {
		return "differential-crash"
	}
	if i := strings.IndexByte(t, ' '); i >= 0 {
		return strings.ToLower(t[:i])
	}
	return strings.ToLower(t)
}

// map onto the token the sanitizer's OWN report prints — the two vocabularies must be ONE (vault: Artifact Identity)
func sanitizerBugClass(crashType, san string) string {
	bc := catalogBugClass(crashType)
	if san == "ubsan" {
		// the UBSan runtime prints one token for every check it traps
		return "undefined-behavior"
	}
	if bc == "unknown" && san == "asan" {
		// only asan: inventing another tool's token would be a false claim
		return "unknown-crash"
	}
	return bc
}

// no frames ⇒ ok=false (skip, never false-merge); frame 0 may be a DESCRIPTION line with the symbol glued on (vault: Artifact Identity)
func crashFrames(cc clusterFuzzCrash) ([]string, bool) {
	frames := cc.State
	if len(frames) == 0 {
		return nil, false
	}
	if head, ok := descriptionLine(cc.CrashType, frames[0]); ok {
		frames = frames[1:]
		if head != "" {
			frames = append([]string{head}, frames...)
		}
	}
	if len(frames) == 0 {
		return nil, false
	}
	return frames, true
}

// returns the frame symbol glued onto a description line ("" ⇒ description only)
func descriptionLine(crashType, line string) (string, bool) {
	t := strings.TrimSpace(crashType)
	if i := strings.IndexByte(t, ' '); i >= 0 {
		t = t[:i]
	}
	if t == "" || !strings.HasPrefix(strings.ToLower(line), strings.ToLower(t)+" ") {
		return "", false
	}
	// '>' or ')' followed by an identifier char is the glue point; a real frame has none
	glue := -1
	for i := 0; i < len(line)-1; i++ {
		if c := line[i]; c == '>' || c == ')' {
			if n := line[i+1]; n == '_' || (n >= 'a' && n <= 'z') || (n >= 'A' && n <= 'Z') {
				glue = i + 1
			}
		}
	}
	if glue < 0 {
		return "", true
	}
	return strings.TrimSpace(line[glue:]), true
}

// CatalogArtifact builds a public abstract from ClusterFuzz metadata alone; must key identically to a real sanitizer run.
func CatalogArtifact(m ARVOMeta, createdAt string) (*artifact.Envelope, bool, error) {
	cc, ok := parseClusterFuzzCrash(reportText(m.Report))
	if !ok || len(cc.State) == 0 {
		return nil, false, nil
	}
	frames, ok := crashFrames(cc)
	if !ok {
		return nil, false, nil
	}
	san := mapSanitizer(m.Sanitizer)
	bc := sanitizerBugClass(cc.CrashType, san)
	crash := artifact.Crash{
		BugClass:   bc,
		Sites:      []string{frames[0]}, // schema-required: tracks frame 0
		Frames:     frames,
		Sanitizer:  san,
		DedupToken: strings.ToLower(san + ":" + bc + ":" + normalizeSiteForToken(frames[0])),
		// no run happened; frames are non-empty above, so PathSig never keys here
		PathSig: "testcase",
	}
	env := &artifact.Envelope{
		Artifact: artifact.Artifact{
			V:       artifact.SchemaVersion,
			Content: artifact.Content{Crash: crash},
		},
		Placement: artifact.Public, // patched public OSS bug
		Abstract:  catalogSummary(m, crash, cc.CrashType),
		Provenance: artifact.Provenance{
			ExperimentID: fmt.Sprintf("arvo-%d", m.LocalID), // machine ref for on-demand repro
			Model:        "arvo-catalog",                    // provenance only
			AcquiredBy:   "arvo",
			Project:      m.Project,
		},
		CreatedAt: createdAt,
	}
	if err := env.Artifact.ComputeID(); err != nil {
		return nil, false, err
	}
	return env, true, nil
}

func normalizeSiteForToken(frame string) string {
	s := frame
	if i := strings.IndexByte(s, '('); i >= 0 {
		s = s[:i]
	}
	return strings.ToLower(strings.TrimSpace(s))
}

// fix_commit is a string OR an array of shas
func fixRef(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var arr []string
	if json.Unmarshal(raw, &arr) == nil && len(arr) > 0 {
		return arr[0]
	}
	return ""
}

func catalogSummary(m ARVOMeta, c artifact.Crash, crashType string) string {
	loc := "the target"
	if len(c.Sites) > 0 && c.Sites[0] != "" {
		loc = c.Sites[0]
	}
	fix := m.Fix
	if fix == "" {
		fix = fixRef(m.FixCommit)
	}
	patched := "patched upstream"
	if fix != "" {
		patched = "patched upstream (" + fix + ")"
	}
	class := c.BugClass
	if ct := strings.TrimSpace(crashType); ct != "" && !strings.EqualFold(ct, c.BugClass) {
		class += " (ClusterFuzz: " + ct + ")"
	}
	return fmt.Sprintf("%s in %s (%s), %s — catalogued from ARVO entry arvo-%d (reproduce on demand: n132/arvo:%d-vul)",
		class, loc, m.Project, patched, m.LocalID, m.LocalID)
}

func (s ARVOSource) ListIDs(ctx context.Context) ([]int, error) {
	root, err := s.githubTree(ctx, "main")
	if err != nil {
		return nil, err
	}
	ad := treeSHA(root, "archive_data")
	if ad == "" {
		return nil, fmt.Errorf("arvo: archive_data not found in repo root")
	}
	adTree, err := s.githubTree(ctx, ad)
	if err != nil {
		return nil, err
	}
	meta := treeSHA(adTree, "meta")
	if meta == "" {
		return nil, fmt.Errorf("arvo: archive_data/meta not found")
	}
	metaTree, err := s.githubTree(ctx, meta)
	if err != nil {
		return nil, err
	}
	if metaTree.Truncated {
		return nil, fmt.Errorf("arvo: meta tree truncated (%d entries) — need pagination", len(metaTree.Tree))
	}
	var ids []int
	for _, e := range metaTree.Tree {
		if strings.HasSuffix(e.Path, ".json") {
			var id int
			if _, err := fmt.Sscanf(strings.TrimSuffix(e.Path, ".json"), "%d", &id); err == nil {
				ids = append(ids, id)
			}
		}
	}
	sort.Ints(ids)
	return ids, nil
}

type githubTreeResp struct {
	Tree []struct {
		Path string `json:"path"`
		SHA  string `json:"sha"`
	} `json:"tree"`
	Truncated bool `json:"truncated"`
}

func treeSHA(t githubTreeResp, path string) string {
	for _, e := range t.Tree {
		if e.Path == path {
			return e.SHA
		}
	}
	return ""
}

func (s ARVOSource) githubTree(ctx context.Context, sha string) (githubTreeResp, error) {
	repo := s.MetaRepo
	if repo == "" {
		repo = "n132/ARVO-Meta"
	}
	url := fmt.Sprintf("https://api.github.com/repos/%s/git/trees/%s", repo, sha)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return githubTreeResp{}, err
	}
	req.Header.Set("accept", "application/vnd.github+json")
	resp, err := s.httpClient().Do(req)
	if err != nil {
		return githubTreeResp{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return githubTreeResp{}, fmt.Errorf("arvo: github tree %s: HTTP %d", sha, resp.StatusCode)
	}
	var out githubTreeResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return githubTreeResp{}, err
	}
	return out, nil
}

// asanOnly: ASan aborts cleanly on the vuln build, UBSan/MSan are recoverable and reproduce flakily
func (s ARVOSource) SelectReproducible(ctx context.Context, limit int, asanOnly bool) ([]int, error) {
	all, err := s.ListIDs(ctx)
	if err != nil {
		return nil, err
	}
	var out []int
	for _, id := range all {
		if limit > 0 && len(out) >= limit {
			break
		}
		if !asanOnly {
			out = append(out, id)
			continue
		}
		m, err := s.FetchMeta(ctx, id)
		if err != nil {
			continue
		}
		if mapSanitizer(m.Sanitizer) == "asan" {
			out = append(out, id)
		}
	}
	return out, nil
}

type CatalogResult struct {
	ID       int
	Envelope *artifact.Envelope
	Skipped  bool // no parseable crash state
	Err      string
}

// BuildCatalog fetches + normalizes ids concurrently (index-aligned); a cancelled ctx returns partial results AND an error (vault: Artifact Identity).
func (s ARVOSource) BuildCatalog(ctx context.Context, ids []int, concurrency int, now func() time.Time, progress func(done, total int)) ([]CatalogResult, error) {
	if concurrency <= 0 {
		concurrency = 12
	}
	if s.HTTP == nil {
		s.HTTP = &http.Client{
			Timeout: 45 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        concurrency * 2,
				MaxIdleConnsPerHost: concurrency * 2,
				IdleConnTimeout:     60 * time.Second,
			},
		}
	}
	results := make([]CatalogResult, len(ids))
	sem := make(chan struct{}, concurrency)
	done := make(chan int, len(ids))
	launched := 0
	for i, id := range ids {
		if ctx.Err() != nil {
			break // cancelled: stop launching, then drain what is in flight
		}
		sem <- struct{}{}
		launched++
		go func(i, id int) {
			defer func() { <-sem; done <- 1 }()
			// the GET is pure, so retrying a throttled CDN fetch is safe
			var m ARVOMeta
			var err error
			for attempt := 0; attempt < 3; attempt++ {
				if m, err = s.FetchMeta(ctx, id); err == nil {
					break
				}
				if ctx.Err() != nil {
					break
				}
			}
			if err != nil {
				results[i] = CatalogResult{ID: id, Err: err.Error()}
				return
			}
			// a zero clock omits created_at, keeping catalog refreshes byte-stable
			createdAt := ""
			if t := now(); !t.IsZero() {
				createdAt = t.UTC().Format(time.RFC3339)
			}
			env, ok, err := CatalogArtifact(m, createdAt)
			switch {
			case err != nil:
				results[i] = CatalogResult{ID: id, Err: err.Error()}
			case !ok:
				results[i] = CatalogResult{ID: id, Skipped: true}
			default:
				results[i] = CatalogResult{ID: id, Envelope: env}
			}
		}(i, id)
	}
	completed := 0
	for i := 0; i < launched; i++ {
		<-done
		completed++
		if progress != nil && completed%200 == 0 {
			progress(completed, len(ids))
		}
	}
	// decide on ctx, not on the launched count: cancel can land mid-flight
	if err := ctx.Err(); err != nil {
		return results, fmt.Errorf("arvo: catalog aborted after %d of %d ids: %w", launched, len(ids), err)
	}
	return results, nil
}
