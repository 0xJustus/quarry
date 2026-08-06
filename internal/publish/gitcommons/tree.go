package gitcommons

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/0xjustus/quarry/internal/publish/artifact"
	"github.com/0xjustus/quarry/internal/publish/channels"
)

const bloomFPRate = 0.01

type Stats struct {
	Artifacts   int
	Keys        int
	Entries     int
	Shards      int
	Prefix      int
	Views       int
	DigestBytes int
	TreeBytes   int
	Removed     int
}

type keyEntry struct {
	Key        string `json:"key"`
	ArtifactID string `json:"artifact_id"`
}

// Manifest is the tree's commons.json.
type Manifest struct {
	Schema    string  `json:"schema"`
	Prefix    int     `json:"prefix"`
	Keys      int     `json:"keys"`
	Artifacts int     `json:"artifacts"`
	BloomFP   float64 `json:"bloom_fp"`
	DigestB   int     `json:"digest_bytes"`
}

const manifestSchema = "quarry-commons/v1"

// canonical: Verify pins manifest.Prefix here, so new thresholds break every tree
func shardPrefix(nKeys int) int {
	switch {
	case nKeys <= 10_000:
		return 0
	case nKeys <= 2_560_000:
		return 1
	default:
		return 2
	}
}

func shardPath(key string, prefix int) string {
	h := strings.TrimPrefix(key, "bk:")
	switch {
	case prefix <= 0 || len(h) < prefix*2:
		return filepath.Join("keys", "all.jsonl")
	case prefix == 1:
		return filepath.Join("keys", h[:2]+".jsonl")
	default:
		parts := []string{"keys"}
		for i := 0; i < prefix-1; i++ {
			parts = append(parts, h[i*2:i*2+2])
		}
		parts = append(parts, h[(prefix-1)*2:prefix*2]+".jsonl")
		return filepath.Join(parts...)
	}
}

// ArtifactPath is the writer's sharding rule for an abstract's tree-relative path; readers derive through here, never re-implement.
func ArtifactPath(id string) string {
	h := strings.TrimPrefix(id, "sha256:")
	if len(h) < 2 {
		return filepath.Join("artifacts", h+".json")
	}
	return filepath.Join("artifacts", h[:2], h+".json")
}

// Generate materializes the tree; a subtractive re-run is refused (see Regenerate).
func Generate(dir string, envs []*artifact.Envelope) (Stats, error) {
	return Regenerate(dir, envs, false)
}

// allowRemovals is explicit intent to de-publish: a shrunken tree still verifies clean
func Regenerate(dir string, envs []*artifact.Envelope, allowRemovals bool) (Stats, error) {
	var st Stats

	// fail closed: validate the whole batch before touching the tree
	if err := checkPublicTier(dir, envs); err != nil {
		return st, err
	}
	dropped, err := droppedArtifacts(dir, envs)
	if err != nil {
		return st, err
	}
	if len(dropped) > 0 && !allowRemovals {
		return st, fmt.Errorf("gitcommons: refusing a subtractive regenerate of %q: %d published artifact(s) are absent from this batch (e.g. %s); a shrunken tree still verifies clean, so de-publishing must be explicit (Regenerate with allowRemovals=true)",
			dir, len(dropped), strings.Join(dropped[:min(len(dropped), 3)], ", "))
	}
	st.Removed = len(dropped)

	// clear regenerated subtrees first so a re-run leaves no orphaned files
	for _, sub := range []string{"keys", "artifacts", "digest", "views"} {
		if err := os.RemoveAll(filepath.Join(dir, sub)); err != nil {
			return st, err
		}
	}
	writeFile := treeWriter(dir, &st)

	keySet := map[string]struct{}{}
	type pair struct{ key, id string }
	var pairs []pair
	seenPair := map[string]struct{}{}
	seenArt := map[string]struct{}{}
	// written = the deduped on-disk set (first wins); views must derive from this
	var written []*artifact.Envelope
	for _, e := range envs {
		if e == nil || e.Artifact.ID == "" {
			continue
		}
		id := e.Artifact.ID
		for _, k := range artifact.CrashKeys(e.Artifact.Content.Crash) {
			keySet[k] = struct{}{}
			pk := pairID(k, id)
			if _, dup := seenPair[pk]; dup {
				continue
			}
			seenPair[pk] = struct{}{}
			pairs = append(pairs, pair{k, id})
		}
		if _, dup := seenArt[id]; !dup {
			seenArt[id] = struct{}{}
			written = append(written, e)
			b, err := json.Marshal(e)
			if err != nil {
				return st, err
			}
			if err := writeFile(ArtifactPath(id), b); err != nil {
				return st, err
			}
			st.Artifacts++
		}
	}
	st.Keys = len(keySet)

	prefix := shardPrefix(len(keySet))
	st.Prefix = prefix

	shardRows := map[string][]keyEntry{}
	for _, p := range pairs {
		sp := shardPath(p.key, prefix)
		shardRows[sp] = append(shardRows[sp], keyEntry{Key: p.key, ArtifactID: p.id})
		st.Entries++
	}
	for sp, rows := range shardRows {
		if err := writeFile(sp, marshalRows(rows)); err != nil {
			return st, err
		}
	}
	st.Shards = len(shardRows)

	views := viewRows(written)
	for _, rel := range slices.Sorted(maps.Keys(views)) {
		if err := writeFile(rel, marshalIDList(views[rel])); err != nil {
			return st, err
		}
	}
	st.Views = len(views)

	digest := canonicalDigest(keySet)
	if err := writeFile(filepath.Join("digest", "keys.bloom"), digest); err != nil {
		return st, err
	}
	st.DigestBytes = len(digest)

	if err := writeMeta(writeFile, st.Artifacts, st.Keys, prefix, st.DigestBytes); err != nil {
		return st, err
	}
	return st, nil
}

// Add is additive only; crossing a shardPrefix boundary falls back to Generate.
func Add(dir string, envs []*artifact.Envelope) (Stats, error) {
	var st Stats
	if err := checkPublicTier(dir, envs); err != nil {
		return st, err
	}
	mb, err := os.ReadFile(filepath.Join(dir, "commons.json"))
	if err != nil {
		return Generate(dir, envs)
	}
	var m Manifest
	if err := json.Unmarshal(mb, &m); err != nil {
		return Generate(dir, envs)
	}
	prefix := m.Prefix
	writeFile := treeWriter(dir, &st)

	newRowsByShard := map[string][]keyEntry{}
	newIDsByView := map[string][]string{}
	newArtifacts := 0
	for _, e := range envs {
		if e == nil || e.Artifact.ID == "" {
			continue
		}
		id := e.Artifact.ID
		ap := ArtifactPath(id)
		if _, statErr := os.Stat(filepath.Join(dir, ap)); statErr != nil {
			b, mErr := json.Marshal(e)
			if mErr != nil {
				return st, mErr
			}
			if wErr := writeFile(ap, b); wErr != nil {
				return st, wErr
			}
			newArtifacts++
			// only a newly-written id contributes to views (Add must equal Generate)
			for _, rel := range viewPaths(e) {
				newIDsByView[rel] = append(newIDsByView[rel], id)
			}
		}
		for _, k := range artifact.CrashKeys(e.Artifact.Content.Crash) {
			sp := shardPath(k, prefix)
			newRowsByShard[sp] = append(newRowsByShard[sp], keyEntry{Key: k, ArtifactID: id})
		}
	}

	merged := map[string][]keyEntry{}
	keySet := map[string]struct{}{}
	keysRoot := filepath.Join(dir, "keys")
	if err := filepath.WalkDir(keysRoot, func(path string, d os.DirEntry, werr error) error {
		if werr != nil || d.IsDir() || !strings.HasSuffix(path, ".jsonl") {
			return nil
		}
		rel, _ := filepath.Rel(dir, path)
		rows := readShardRows(path)
		merged[rel] = rows
		for _, r := range rows {
			keySet[r.Key] = struct{}{}
		}
		return nil
	}); err != nil && !os.IsNotExist(err) {
		return st, err
	}
	for rel, add := range newRowsByShard {
		merged[rel] = append(merged[rel], add...)
		for _, r := range add {
			keySet[r.Key] = struct{}{}
		}
	}

	if shardPrefix(len(keySet)) != prefix {
		all, lErr := LoadEnvelopes(dir)
		if lErr != nil {
			return st, lErr
		}
		return Generate(dir, all)
	}

	// byte-identical to Generate for the same rows
	for rel := range newRowsByShard {
		if err := writeFile(rel, marshalRows(merged[rel])); err != nil {
			return st, err
		}
	}
	st.Shards = len(merged)
	st.Keys = len(keySet)

	for rel, add := range newIDsByView {
		combined := append(ReadViewIDs(filepath.Join(dir, rel)), add...)
		if err := writeFile(rel, marshalIDList(combined)); err != nil {
			return st, err
		}
	}

	digest := canonicalDigest(keySet)
	if err := writeFile(filepath.Join("digest", "keys.bloom"), digest); err != nil {
		return st, err
	}
	st.DigestBytes = len(digest)
	st.Prefix = prefix
	st.Artifacts = m.Artifacts + newArtifacts

	if err := writeMeta(writeFile, st.Artifacts, st.Keys, prefix, st.DigestBytes); err != nil {
		return st, err
	}
	return st, nil
}

func treeWriter(dir string, st *Stats) func(string, []byte) error {
	return func(rel string, data []byte) error {
		full := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(full, data, 0o644); err != nil {
			return err
		}
		st.TreeBytes += len(data)
		return nil
	}
}

// the one canonical digest: Verify byte-compares against it
func canonicalDigest(keySet map[string]struct{}) []byte {
	bloom := NewBloom(len(keySet), bloomFPRate)
	for k := range keySet {
		bloom.Add(k)
	}
	return bloom.Marshal()
}

// 1.0 = no residual re-id signal at all (channels' public minimum is 0.9)
const publicMinReID = 1.0

// mirrors the emit gate; federation.Admit fixes AcquiredBy so this cannot be claimed
var knownPublicSources = []string{"arvo", "oss-fuzz", "silent-fix"}

func publicReIDBattery() channels.ReIDBattery {
	return channels.NewProvenanceBattery(knownPublicSources...)
}

// "" means clear
func checkPublicLeaks(b channels.ReIDBattery, e *artifact.Envelope) string {
	res := b.Score(context.Background(), e, publicMinReID)
	if res.Cleared {
		return ""
	}
	return res.Notes
}

// fail-closed write gate: abstracts-only, Public, integrity-valid, re-id clean, attested
func checkPublicTier(dir string, envs []*artifact.Envelope) error {
	// a declared-but-unreadable trust root must stop the write, not read as "unpinned"
	accepted, err := loadSigners(dir)
	if err != nil {
		return fmt.Errorf("gitcommons: %s: %w", signersFile, err)
	}
	battery := publicReIDBattery()
	var bad []string
	for _, e := range envs {
		if e == nil || e.Artifact.ID == "" {
			continue
		}
		id := e.Artifact.ID
		if e.Placement != artifact.Public {
			bad = append(bad, id+": non-Public placement "+string(e.Placement))
		}
		if e.Artifact.Content.Specimen != nil {
			bad = append(bad, id+": public tier must not carry a specimen")
		}
		if e.Artifact.Reproducer != nil {
			bad = append(bad, id+": public tier must not carry a reproducer")
		}
		if err := e.Verify(); err != nil {
			bad = append(bad, id+": integrity: "+err.Error())
		}
		// the federated and lang paths bypass channels.Gate, so the scan must live here too
		if why := checkPublicLeaks(battery, e); why != "" {
			bad = append(bad, id+": re-id leak scan: "+why+" (anonymize through channels.Gate before publishing)")
		}
		if why := checkSigner(accepted, e); why != "" {
			bad = append(bad, id+": "+why)
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("gitcommons: refusing to write %d envelope(s) that fail the public-tier gate: %s", len(bad), strings.Join(bad, "; "))
	}
	return nil
}

// an artifacts/ subtree we cannot enumerate is an error: non-subtraction is unprovable
func droppedArtifacts(dir string, envs []*artifact.Envelope) ([]string, error) {
	keep := make(map[string]bool, len(envs))
	for _, e := range envs {
		if e != nil && e.Artifact.ID != "" {
			keep[e.Artifact.ID] = true
		}
	}
	var dropped []string
	err := filepath.WalkDir(filepath.Join(dir, "artifacts"), func(p string, d os.DirEntry, werr error) error {
		if werr != nil {
			if os.IsNotExist(werr) {
				return nil
			}
			return werr
		}
		if d.IsDir() || !strings.HasSuffix(p, ".json") {
			return nil
		}
		if id := "sha256:" + strings.TrimSuffix(filepath.Base(p), ".json"); !keep[id] {
			dropped = append(dropped, id)
		}
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	sort.Strings(dropped)
	return dropped, nil
}

func viewPaths(e *artifact.Envelope) []string {
	return []string{
		filepath.Join("views", "by-class", slug(e.Artifact.Content.Crash.BugClass)+".jsonl"),
		filepath.Join("views", "by-project", slug(e.Provenance.Project)+".jsonl"),
	}
}

func viewRows(envs []*artifact.Envelope) map[string][]string {
	sets := map[string]map[string]struct{}{}
	for _, e := range envs {
		if e == nil || e.Artifact.ID == "" {
			continue
		}
		for _, rel := range viewPaths(e) {
			if sets[rel] == nil {
				sets[rel] = map[string]struct{}{}
			}
			sets[rel][e.Artifact.ID] = struct{}{}
		}
	}
	out := map[string][]string{}
	for rel, ids := range sets {
		out[rel] = slices.Collect(maps.Keys(ids)) // marshalIDList sorts + dedups
	}
	return out
}

func slug(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "unknown"
	}
	return out
}

// canonical shard encoding: sorted + deduped JSONL (Verify byte-compares)
func marshalRows(rows []keyEntry) []byte {
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Key != rows[j].Key {
			return rows[i].Key < rows[j].Key
		}
		return rows[i].ArtifactID < rows[j].ArtifactID
	})
	var b strings.Builder
	var last keyEntry
	for i, r := range rows {
		if i > 0 && r == last {
			continue
		}
		line, _ := json.Marshal(r)
		b.Write(line)
		b.WriteByte('\n')
		last = r
	}
	return []byte(b.String())
}

// canonical view encoding: sorted + deduped JSONL (Verify byte-compares)
func marshalIDList(ids []string) []byte {
	sort.Strings(ids)
	var b strings.Builder
	last := ""
	for i, id := range ids {
		if id == "" || (i > 0 && id == last) {
			continue
		}
		line, _ := json.Marshal(struct {
			ID string `json:"id"`
		}{id})
		b.Write(line)
		b.WriteByte('\n')
		last = id
	}
	return []byte(b.String())
}

// 4 MiB max token: a JSONL row can be far longer than bufio's default
func jsonlScanner(r io.Reader) *bufio.Scanner {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 4<<20)
	return sc
}

// a missing or garbled shard yields nil
func readShardRows(path string) []keyEntry {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	sc := jsonlScanner(f)
	var rows []keyEntry
	for sc.Scan() {
		var e keyEntry
		if json.Unmarshal(sc.Bytes(), &e) == nil {
			rows = append(rows, e)
		}
	}
	return rows
}

// ReadViewIDs reads a view's {"id":…} rows; a missing or garbled view yields nil.
func ReadViewIDs(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	sc := jsonlScanner(f)
	var out []string
	for sc.Scan() {
		var row struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(sc.Bytes(), &row) == nil && row.ID != "" {
			out = append(out, row.ID)
		}
	}
	return out
}

// LoadEnvelopes reads every artifact abstract under dir/artifacts.
func LoadEnvelopes(dir string) ([]*artifact.Envelope, error) {
	var out []*artifact.Envelope
	root := filepath.Join(dir, "artifacts")
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, werr error) error {
		if werr != nil || d.IsDir() || !strings.HasSuffix(p, ".json") {
			return werr
		}
		b, rErr := os.ReadFile(p)
		if rErr != nil {
			return rErr
		}
		e, uErr := artifact.Unmarshal(b)
		if uErr != nil {
			return fmt.Errorf("%s: %w", p, uErr)
		}
		out = append(out, e)
		return nil
	})
	if os.IsNotExist(err) {
		return out, nil
	}
	return out, err
}

func writeMeta(writeFile func(string, []byte) error, artifacts, keys, prefix, digestBytes int) error {
	mf, _ := json.MarshalIndent(Manifest{
		Schema: manifestSchema, Prefix: prefix, Keys: keys,
		Artifacts: artifacts, BloomFP: bloomFPRate, DigestB: digestBytes,
	}, "", "  ")
	return writeFile("commons.json", mf)
}
