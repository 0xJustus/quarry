package core

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/0xjustus/quarry/internal/discover/corpus"
	"github.com/0xjustus/quarry/internal/platform/audit"
	"github.com/0xjustus/quarry/internal/platform/store"
	"github.com/0xjustus/quarry/internal/publish/artifact"
	"github.com/0xjustus/quarry/internal/publish/channels"
	"github.com/0xjustus/quarry/internal/publish/gitcommons"
	"github.com/0xjustus/quarry/internal/publish/hydrate"
)

type QueryRequest struct {
	Caller Caller   `json:"caller,omitempty"`
	Tree   string   `json:"tree"`
	Keys   []string `json:"keys"`
}

type QueryCandidate struct {
	ArtifactID string   `json:"artifact_id"`
	Source     string   `json:"source,omitempty"`
	BugClass   string   `json:"bug_class,omitempty"`
	Abstract   string   `json:"abstract,omitempty"`
	Sites      []string `json:"sites,omitempty"`
}

type QueryResult struct {
	Tree       string           `json:"tree"`
	Candidates []QueryCandidate `json:"candidates"`
}

func (e *Engine) Query(ctx context.Context, req QueryRequest) (QueryResult, error) {
	log := e.logFor(req.Caller.Principal, req.Caller.Session)
	sp := log.Start("core.Query", audit.KindAccess, fmt.Sprintf("tree:%s keys:%d", req.Tree, len(req.Keys)))
	res, err := e.query(ctx, req)
	sp.End(fmt.Sprintf("candidates:%d", len(res.Candidates)), err)
	return res, err
}

func (e *Engine) query(ctx context.Context, req QueryRequest) (QueryResult, error) {
	if req.Tree == "" {
		return QueryResult{}, fmt.Errorf("query: tree is required (a pulled quarry-commons tree)")
	}
	if len(req.Keys) == 0 {
		return QueryResult{}, fmt.Errorf("query: at least one behavioral key is required")
	}
	src, err := gitcommons.Open(req.Tree)
	if err != nil {
		return QueryResult{}, fmt.Errorf("query: open commons tree %s: %w", req.Tree, err)
	}
	hits, err := src.Lookup(ctx, req.Keys)
	if err != nil {

		return QueryResult{}, fmt.Errorf("query: lookup: %w", err)
	}
	out := QueryResult{Tree: req.Tree}
	for _, h := range hits {
		out.Candidates = append(out.Candidates, QueryCandidate{
			ArtifactID: h.ArtifactID, Source: h.Source, BugClass: h.BugClass,
			Abstract: h.Abstract, Sites: h.Sites,
		})
	}
	return out, nil
}

type CorpusMineRequest struct {
	Caller   Caller `json:"caller,omitempty"`
	Repo     string `json:"repo"`
	Rev      string `json:"rev,omitempty"`
	Max      int    `json:"max,omitempty"`
	PathSpec string `json:"pathspec,omitempty"`

	Class string `json:"class,omitempty"`
}

type CorpusSignal struct {
	Name   string `json:"name"`
	Weight int    `json:"weight"`
}

type CorpusCandidate struct {
	SHA      string         `json:"sha"`
	Parent   string         `json:"parent"`
	Subject  string         `json:"subject"`
	Files    []string       `json:"files,omitempty"`
	Score    int            `json:"score"`
	Label    string         `json:"label"`
	Category string         `json:"category,omitempty"`
	Signals  []CorpusSignal `json:"signals,omitempty"`
}

type CorpusMineResult struct {
	Candidates []CorpusCandidate `json:"candidates"`
}

func (e *Engine) CorpusMine(ctx context.Context, req CorpusMineRequest) (CorpusMineResult, error) {
	log := e.logFor(req.Caller.Principal, req.Caller.Session)
	sp := log.Start("core.CorpusMine", audit.KindAccess, fmt.Sprintf("repo:%s rev:%s max:%d", req.Repo, req.Rev, req.Max))
	res, err := e.corpusMine(ctx, req)
	sp.End(fmt.Sprintf("candidates:%d", len(res.Candidates)), err)
	return res, err
}

func (e *Engine) corpusMine(ctx context.Context, req CorpusMineRequest) (CorpusMineResult, error) {
	if req.Repo == "" {
		return CorpusMineResult{}, fmt.Errorf("corpus mine: repo is required")
	}
	cands, err := corpus.Mine(ctx, corpus.MineOptions{
		Repo: req.Repo, Rev: req.Rev, Max: req.Max, PathSpec: req.PathSpec,
	})
	if err != nil {
		return CorpusMineResult{}, err
	}
	var out CorpusMineResult
	for _, c := range cands {
		if req.Class != "" && c.Class.Category != req.Class {
			continue
		}
		cc := CorpusCandidate{
			SHA: c.Commit.SHA, Parent: c.Parent, Subject: c.Commit.Subject,
			Files: c.Commit.Files, Score: c.Class.Score, Label: c.Class.Label,
			Category: c.Class.Category,
		}
		for _, s := range c.Class.Signals {
			cc.Signals = append(cc.Signals, CorpusSignal{Name: s.Name, Weight: s.Weight})
		}
		out.Candidates = append(out.Candidates, cc)
	}
	return out, nil
}

type CorpusBuildRequest struct {
	Caller      Caller   `json:"caller,omitempty"`
	Repo        string   `json:"repo"`
	VulnSHA     string   `json:"vuln_sha"`
	FixSHA      string   `json:"fix_sha"`
	BuildCmd    string   `json:"build_cmd"`
	RunArgv     []string `json:"run_argv,omitempty"`
	Base        string   `json:"base,omitempty"`
	Name        string   `json:"name,omitempty"`
	OutDir      string   `json:"out_dir,omitempty"`
	Harness     []byte   `json:"harness,omitempty"`
	HarnessDest string   `json:"harness_dest,omitempty"`
	TimeoutS    int      `json:"timeout_s,omitempty"`
}

type CorpusBuildResult struct {
	VulnImage string `json:"vuln_image"`
	FixImage  string `json:"fix_image"`
	YAMLPath  string `json:"yaml_path"`
}

func (e *Engine) CorpusBuild(ctx context.Context, req CorpusBuildRequest) (CorpusBuildResult, error) {
	log := e.logFor(req.Caller.Principal, req.Caller.Session)
	sp := log.Start("core.CorpusBuild", audit.KindCall, fmt.Sprintf("repo:%s vuln:%s fix:%s", req.Repo, req.VulnSHA, req.FixSHA))
	res, err := e.corpusBuild(ctx, req)
	sp.End(res.YAMLPath, err)
	return res, err
}

func (e *Engine) corpusBuild(ctx context.Context, req CorpusBuildRequest) (CorpusBuildResult, error) {
	if req.Repo == "" || req.VulnSHA == "" || req.FixSHA == "" || req.BuildCmd == "" {
		return CorpusBuildResult{}, fmt.Errorf("corpus build: repo, vuln_sha, fix_sha, build_cmd are required")
	}
	opts := corpus.BuildPairOptions{
		Repo: req.Repo, VulnSHA: req.VulnSHA, FixSHA: req.FixSHA, BuildCmd: req.BuildCmd,
		RunArgv: req.RunArgv, Base: req.Base, DockerBin: e.cfg.DockerBin, Name: req.Name,
		OutDir: req.OutDir, HarnessDest: req.HarnessDest, TimeoutS: req.TimeoutS,
	}

	if len(req.Harness) > 0 {
		f, err := os.CreateTemp("", "quarry-harness-*")
		if err != nil {
			return CorpusBuildResult{}, fmt.Errorf("corpus build: stage harness: %w", err)
		}
		defer os.Remove(f.Name())
		if _, err := f.Write(req.Harness); err != nil {
			f.Close()
			return CorpusBuildResult{}, fmt.Errorf("corpus build: stage harness: %w", err)
		}
		f.Close()
		opts.HarnessFile = f.Name()
	}
	res, err := corpus.BuildPair(ctx, opts)
	if err != nil {
		return CorpusBuildResult{}, err
	}
	return CorpusBuildResult{VulnImage: res.VulnImage, FixImage: res.FixImage, YAMLPath: res.YAMLPath}, nil
}

type HydrateRequest struct {
	Caller    Caller `json:"caller,omitempty"`
	Manifest  string `json:"manifest,omitempty"`
	ArvoIDs   []int  `json:"arvo_ids,omitempty"`
	ArvoAll   bool   `json:"arvo_all,omitempty"`
	AsanOnly  *bool  `json:"asan_only,omitempty"`
	Limit     int    `json:"limit,omitempty"`
	DataDir   string `json:"data_dir,omitempty"`
	DockerBin string `json:"docker_bin,omitempty"`
	NoSign    bool   `json:"no_sign,omitempty"`
}

type HydrateEntryResult struct {
	EntryID       string `json:"entry_id"`
	Confirmed     bool   `json:"confirmed"`
	ArtifactID    string `json:"artifact_id,omitempty"`
	BehavioralKey string `json:"behavioral_key,omitempty"`
	Deduped       bool   `json:"deduped,omitempty"`
	DurationMS    int64  `json:"duration_ms"`
	Err           string `json:"err,omitempty"`
}

type HydrateResult struct {
	Results         []HydrateEntryResult `json:"results"`
	Hydrated        int                  `json:"hydrated"`
	Deduped         int                  `json:"deduped"`
	Failed          int                  `json:"failed"`
	AgentCalls      int                  `json:"agent_calls"`
	TotalDurationMS int64                `json:"total_duration_ms"`
	Interrupted     bool                 `json:"interrupted,omitempty"`
}

func (e *Engine) Hydrate(ctx context.Context, req HydrateRequest) (HydrateResult, error) {
	log := e.logFor(req.Caller.Principal, req.Caller.Session)
	sp := log.Start("core.Hydrate", audit.KindCall, fmt.Sprintf("manifest:%s arvo:%d all:%v", req.Manifest, len(req.ArvoIDs), req.ArvoAll))
	res, err := e.hydrate(ctx, req)
	sp.End(fmt.Sprintf("hydrated:%d deduped:%d failed:%d", res.Hydrated, res.Deduped, res.Failed), err)
	return res, err
}

func (e *Engine) hydrate(ctx context.Context, req HydrateRequest) (HydrateResult, error) {
	if req.Manifest == "" && len(req.ArvoIDs) == 0 && !req.ArvoAll {
		return HydrateResult{}, fmt.Errorf("hydrate: provide manifest, arvo_ids, or arvo_all")
	}
	cfg := e.cfg
	if req.DataDir != "" {
		cfg.DataDir = req.DataDir
	}
	dockerBin := cfg.DockerBin
	if req.DockerBin != "" {
		dockerBin = req.DockerBin
	}

	var entries []hydrate.Entry
	var err error
	baseDir := "."
	switch {
	case req.ArvoAll:
		asanOnly := true
		if req.AsanOnly != nil {
			asanOnly = *req.AsanOnly
		}
		ids, serr := hydrate.ARVOSource{}.SelectReproducible(ctx, req.Limit, asanOnly)
		if serr != nil {
			return HydrateResult{}, serr
		}
		if entries, err = (hydrate.ARVOSource{}).Entries(ctx, ids); err != nil {
			return HydrateResult{}, err
		}
	case len(req.ArvoIDs) > 0:
		if entries, err = (hydrate.ARVOSource{}).Entries(ctx, req.ArvoIDs); err != nil {
			return HydrateResult{}, err
		}
	default:
		if entries, baseDir, err = hydrate.LoadManifest(req.Manifest); err != nil {
			return HydrateResult{}, err
		}
	}

	if err := cfg.EnsureDataDir(); err != nil {
		return HydrateResult{}, err
	}
	st, err := store.Open(cfg.StoreDir())
	if err != nil {
		return HydrateResult{}, err
	}
	defer st.Close()

	h := &hydrate.Hydrator{
		Store:     st,
		Gate:      channels.NewGate(nil, channels.NewProvenanceBattery("arvo", "oss-fuzz", "silent-fix")),
		Sink:      channels.LocalOutboxSink{Out: st},
		DockerBin: dockerBin,
	}
	if !req.NoSign {
		key, err := cfg.LoadOrCreateSigningKey()
		if err != nil {
			return HydrateResult{}, err
		}
		h.Signer = key
	}

	rep, herr := h.Hydrate(ctx, entries, baseDir)
	out := HydrateResult{
		Hydrated: rep.Hydrated, Deduped: rep.Deduped, Failed: rep.Failed,
		AgentCalls: rep.AgentCalls, TotalDurationMS: rep.TotalDuration.Milliseconds(),
		Interrupted: herr != nil,
	}
	for _, r := range rep.Results {
		out.Results = append(out.Results, HydrateEntryResult{
			EntryID: r.EntryID, Confirmed: r.Confirmed, ArtifactID: r.ArtifactID,
			BehavioralKey: r.BehavioralKey, Deduped: r.Deduped,
			DurationMS: r.Duration.Milliseconds(), Err: r.Err,
		})
	}

	return out, herr
}

type CatalogRequest struct {
	Caller      Caller `json:"caller,omitempty"`
	ArvoIDs     []int  `json:"arvo_ids,omitempty"`
	All         bool   `json:"all,omitempty"`
	Limit       int    `json:"limit,omitempty"`
	Concurrency int    `json:"concurrency,omitempty"`
	DryRun      bool   `json:"dry_run,omitempty"`
	Tree        string `json:"tree,omitempty"`
	DataDir     string `json:"data_dir,omitempty"`
	NoSign      bool   `json:"no_sign,omitempty"`
	// explicit de-publish: allow a subtractive regenerate (a shrunken tree still verifies clean)
	AllowRemovals bool `json:"allow_removals,omitempty"`
}

type CatalogTreeStats struct {
	Artifacts   int `json:"artifacts"`
	Keys        int `json:"keys"`
	Prefix      int `json:"prefix"`
	Shards      int `json:"shards"`
	DigestBytes int `json:"digest_bytes"`
	TreeBytes   int `json:"tree_bytes"`
}

type CatalogResult struct {
	Selected   int               `json:"selected"`
	Built      int               `json:"built"`
	Skipped    int               `json:"skipped"`
	Failed     int               `json:"failed"`
	BugClasses map[string]int    `json:"bug_classes,omitempty"`
	Wrote      bool              `json:"wrote"`
	Tree       string            `json:"tree,omitempty"`
	Stats      *CatalogTreeStats `json:"stats,omitempty"`
}

func (e *Engine) Catalog(ctx context.Context, req CatalogRequest) (CatalogResult, error) {
	log := e.logFor(req.Caller.Principal, req.Caller.Session)
	sp := log.Start("core.Catalog", audit.KindCall, fmt.Sprintf("arvo:%d all:%v tree:%s", len(req.ArvoIDs), req.All, req.Tree))
	res, err := e.catalog(ctx, req)
	sp.End(fmt.Sprintf("built:%d skipped:%d failed:%d wrote:%v", res.Built, res.Skipped, res.Failed, res.Wrote), err)
	return res, err
}

func (e *Engine) catalog(ctx context.Context, req CatalogRequest) (CatalogResult, error) {
	src := hydrate.ARVOSource{}

	var ids []int
	var err error
	switch {
	case len(req.ArvoIDs) > 0:
		ids = req.ArvoIDs
	case req.All:
		if ids, err = src.ListIDs(ctx); err != nil {
			return CatalogResult{}, err
		}
	default:
		return CatalogResult{}, fmt.Errorf("catalog: provide arvo_ids or all")
	}
	if req.Limit > 0 && req.Limit < len(ids) {
		ids = ids[:req.Limit]
	}

	// deterministic catalog: a zero clock omits created_at so the git-native tree is byte-stable
	results, err := src.BuildCatalog(ctx, ids, req.Concurrency, func() time.Time { return time.Time{} }, nil)
	if err != nil {

		return CatalogResult{}, fmt.Errorf("catalog: %w — nothing written", err)
	}

	gate := channels.NewGate(nil, channels.NewProvenanceBattery("arvo", "oss-fuzz", "silent-fix"))
	if !req.NoSign {
		cfg := e.cfg
		if req.DataDir != "" {
			cfg.DataDir = req.DataDir
		}
		key, kerr := cfg.LoadOrCreateSigningKey()
		if kerr != nil {
			return CatalogResult{}, kerr
		}
		gate.Signer = key
	}
	sink := &channels.MemorySink{Cap: artifact.Public}

	out := CatalogResult{Selected: len(ids), BugClasses: map[string]int{}, Tree: req.Tree}
	var envs []*artifact.Envelope
	for _, r := range results {
		switch {
		case r.Err != "":
			out.Failed++
			continue
		case r.Skipped:
			out.Skipped++
			continue
		}
		emitted, eerr := gate.Emit(ctx, sink, r.Envelope)
		if eerr != nil {
			out.Failed++
			continue
		}
		envs = append(envs, emitted)
		out.Built++
		out.BugClasses[emitted.Artifact.Content.Crash.BugClass]++
	}

	if req.DryRun {
		return out, nil
	}
	if req.Tree == "" {
		return out, fmt.Errorf("catalog: tree is required to write the git-native commons (or set dry_run)")
	}
	st, err := gitcommons.Regenerate(req.Tree, envs, req.AllowRemovals)
	if err != nil {
		return out, fmt.Errorf("catalog: write git-native tree: %w", err)
	}
	out.Wrote = true
	out.Stats = &CatalogTreeStats{
		Artifacts: st.Artifacts, Keys: st.Keys, Prefix: st.Prefix,
		Shards: st.Shards, DigestBytes: st.DigestBytes, TreeBytes: st.TreeBytes,
	}
	return out, nil
}
