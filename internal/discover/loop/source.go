package loop

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/0xjustus/quarry/internal/publish/channels"
	"github.com/0xjustus/quarry/internal/publish/gitcommons"
)

type candidateIndex interface {
	Candidates(ctx context.Context, keys []string) ([]string, error)
}

type LocalSource struct {
	Store candidateIndex
}

func (s LocalSource) Lookup(ctx context.Context, keys []string) ([]channels.PriorArt, error) {
	if s.Store == nil {
		return nil, nil
	}
	ids, err := s.Store.Candidates(ctx, keys)
	if err != nil {
		return nil, err
	}
	out := make([]channels.PriorArt, 0, len(ids))
	for _, id := range ids {
		out = append(out, channels.PriorArt{ArtifactID: id, Source: "local"})
	}
	return out, nil
}

// a zero-hit union an incomplete source touched must NOT read as novel
type Federated []channels.PatternSource

func (f Federated) Lookup(ctx context.Context, keys []string) ([]channels.PriorArt, error) {
	seen := map[string]bool{}
	var out []channels.PriorArt
	incomplete := false
	for _, s := range f {
		if s == nil {
			continue
		}
		hits, err := safeLookup(ctx, s, keys)
		if err != nil {
			if errors.Is(err, gitcommons.ErrIncomplete) {
				incomplete = true
			}
			continue
		}
		for _, h := range hits {
			if h.ArtifactID == "" || seen[h.ArtifactID] {
				continue
			}
			seen[h.ArtifactID] = true
			out = append(out, h)
		}
	}
	if len(out) == 0 && incomplete {
		return nil, fmt.Errorf("federated prior-art lookup undecided: %w", gitcommons.ErrIncomplete)
	}
	return out, nil
}

// prior art by bug class BEFORE a crash exists; distinct from the crash-key Lookup
type PrimeQuery struct {
	Objective  string
	TargetDesc string
	K          int
}

// optional: a source that only answers crash-key Lookups need not implement it
type Primer interface {
	Prime(ctx context.Context, q PrimeQuery) ([]channels.PriorArt, error)
}

// read-only and best-effort: a missing tree yields no hints, never an error
type CommonsPrimer struct {
	Dir string
	// self-exclusion: priming a target with its own commons entry is teaching to the test
	Exclude []string
}

var _ Primer = CommonsPrimer{}

// gitcommons.ArtifactPath is the writer's sharding rule: derive, never re-implement.
func commonsArtifactPath(dir, id string) string {
	return filepath.Join(dir, gitcommons.ArtifactPath(id))
}

// fails open: an unreadable artifact costs recall, never soundness
func (c CommonsPrimer) excluded(id string) bool {
	if len(c.Exclude) == 0 {
		return false
	}
	b, err := os.ReadFile(commonsArtifactPath(c.Dir, id))
	if err != nil {
		return false
	}
	s := string(b)
	for _, tok := range c.Exclude {
		if tok != "" && strings.Contains(s, tok) {
			return true
		}
	}
	return false
}

func (c CommonsPrimer) Prime(_ context.Context, q PrimeQuery) ([]channels.PriorArt, error) {
	k := q.K
	if k <= 0 {
		k = 5
	}
	files, err := filepath.Glob(filepath.Join(c.Dir, "views", "by-class", "*.jsonl"))
	if err != nil || len(files) == 0 {
		return nil, err
	}
	sort.Strings(files)
	text := strings.ToLower(q.Objective + " " + q.TargetDesc)

	// score-rank first: an alphabetically-earlier weak match must not exhaust K
	type view struct {
		file  string
		score int
	}
	views := make([]view, 0, len(files))
	for _, f := range files {
		views = append(views, view{f, classScore(filepath.Base(f), text)})
	}
	sort.SliceStable(views, func(i, j int) bool { return views[i].score > views[j].score })

	var matched, rest [][]string
	for _, v := range views {
		ids := gitcommons.ReadViewIDs(v.file)
		if v.score > 0 {
			matched = append(matched, ids)
		} else {
			rest = append(rest, ids)
		}
	}

	seen := map[string]bool{}
	var out []channels.PriorArt
	for _, id := range append(interleave(matched), slices.Concat(rest...)...) {
		if len(out) >= k {
			break
		}
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		if c.excluded(id) {
			continue
		}
		bc, ab, sites := readCommonsAbstract(c.Dir, id)
		out = append(out, channels.PriorArt{ArtifactID: id, Source: "git-commons", BugClass: bc, Abstract: ab, Sites: sites})
	}
	return out, nil
}

func classScore(base, text string) int {
	n := 0
	for _, tok := range strings.Split(strings.TrimSuffix(base, ".jsonl"), "-") {
		if len(tok) >= 4 && strings.Contains(text, tok) {
			n++
		}
	}
	return n
}

// round-robin: the strongest match leads K but must not monopolize it
func interleave(lists [][]string) []string {
	var out []string
	for col := 0; ; col++ {
		any := false
		for _, l := range lists {
			if col < len(l) {
				out = append(out, l[col])
				any = true
			}
		}
		if !any {
			return out
		}
	}
}

func readCommonsAbstract(dir, id string) (bugClass, abstract string, sites []string) {
	b, err := os.ReadFile(commonsArtifactPath(dir, id))
	if err != nil {
		return "", "", nil
	}
	var e struct {
		Artifact struct {
			Content struct {
				Crash struct {
					BugClass string   `json:"bug_class"`
					Sites    []string `json:"sites"`
					Frames   []string `json:"frames"`
				} `json:"crash"`
			} `json:"content"`
		} `json:"artifact"`
		Abstract string `json:"abstract"`
	}
	_ = json.Unmarshal(b, &e)
	syms := e.Artifact.Content.Crash.Frames
	if len(syms) == 0 {
		syms = e.Artifact.Content.Crash.Sites
	}
	return e.Artifact.Content.Crash.BugClass, e.Abstract, syms
}

// converts a source panic into an error: one bad source must not abort the harvest
func safeLookup(ctx context.Context, s channels.PatternSource, keys []string) (hits []channels.PriorArt, err error) {
	defer func() {
		if r := recover(); r != nil {
			hits, err = nil, fmt.Errorf("source panicked: %v", r)
		}
	}()
	return s.Lookup(ctx, keys)
}
