package gitcommons

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/0xjustus/quarry/internal/publish/channels"
)

// undecidable, never a miss: a miss reads as novel for a bug the commons already holds
var ErrIncomplete = errors.New("gitcommons: incomplete checkout")

type Source struct {
	dir    string
	prefix int
	bloom  *Bloom
	mu     sync.Mutex
	shards map[string]map[string][]string // shard path → key → artifact ids
}

func Open(dir string) (*Source, error) {
	mf, err := os.ReadFile(filepath.Join(dir, "commons.json"))
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(mf, &m); err != nil {
		return nil, err
	}
	db, err := os.ReadFile(filepath.Join(dir, "digest", "keys.bloom"))
	if err != nil {
		return nil, err
	}
	bloom, err := UnmarshalBloom(db)
	if err != nil {
		return nil, err
	}
	return &Source{dir: dir, prefix: m.Prefix, bloom: bloom, shards: map[string]map[string][]string{}}, nil
}

// every hit is grounded in a readable abstract; the rest is ErrIncomplete, not a miss
func (s *Source) Lookup(_ context.Context, keys []string) ([]channels.PriorArt, error) {
	ids := map[string]struct{}{}
	var undecided []string
	for _, k := range keys {
		if !s.bloom.Test(k) {
			continue // definitive miss, no shard fetch
		}
		got, err := s.resolve(k)
		if err != nil {
			undecided = append(undecided, err.Error())
			continue
		}
		for _, id := range got {
			ids[id] = struct{}{}
		}
	}
	sorted := make([]string, 0, len(ids))
	for id := range ids {
		sorted = append(sorted, id)
	}
	sort.Strings(sorted) // stable representative first (callers log priorArt[0])
	out := make([]channels.PriorArt, 0, len(sorted))
	for _, id := range sorted {
		bc, ab, err := s.readAbstract(id)
		if err != nil {
			// an empty-fielded hit would turn a novel finding into a rediscovery of 1
			undecided = append(undecided, err.Error())
			continue
		}
		out = append(out, channels.PriorArt{ArtifactID: id, Source: "git-commons", BugClass: bc, Abstract: ab})
	}
	if len(undecided) > 0 {
		return out, fmt.Errorf("%w: %d unresolved (%s)", ErrIncomplete, len(undecided), strings.Join(undecided, "; "))
	}
	return out, nil
}

// never cache an unreadable shard as empty: unfetched is undecidable, not a miss
func (s *Source) resolve(key string) ([]string, error) {
	sp := shardPath(key, s.prefix)
	s.mu.Lock()
	defer s.mu.Unlock()
	if idx, ok := s.shards[sp]; ok {
		return idx[key], nil
	}
	f, err := os.Open(filepath.Join(s.dir, sp))
	if err != nil {
		return nil, fmt.Errorf("shard %s: %v", sp, err)
	}
	defer f.Close()
	idx := map[string][]string{}
	sc := jsonlScanner(f)
	for sc.Scan() {
		var e keyEntry
		if json.Unmarshal(sc.Bytes(), &e) == nil {
			idx[e.Key] = append(idx[e.Key], e.ArtifactID)
		}
	}
	if err := sc.Err(); err != nil {
		// a truncated read indexes only a prefix: refuse to cache or answer from it
		return nil, fmt.Errorf("shard %s: scan: %v", sp, err)
	}
	for k := range idx {
		sort.Strings(idx[k])
	}
	s.shards[sp] = idx
	return idx[key], nil
}

// a missing or garbled abstract is an error, not empty strings
func (s *Source) readAbstract(id string) (bugClass, abstract string, err error) {
	b, rErr := os.ReadFile(filepath.Join(s.dir, ArtifactPath(id)))
	if rErr != nil {
		return "", "", fmt.Errorf("artifact %s: %v", id, rErr)
	}
	var e struct {
		Artifact struct {
			Content struct {
				Crash struct {
					BugClass string `json:"bug_class"`
				} `json:"crash"`
			} `json:"content"`
		} `json:"artifact"`
		Abstract string `json:"abstract"`
	}
	if uErr := json.Unmarshal(b, &e); uErr != nil {
		return "", "", fmt.Errorf("artifact %s: unmarshal: %v", id, uErr)
	}
	return e.Artifact.Content.Crash.BugClass, e.Abstract, nil
}

var _ channels.PatternSource = (*Source)(nil)
