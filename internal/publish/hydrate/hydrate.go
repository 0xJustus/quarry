// Package hydrate seeds the commons from ARVO/OSS-Fuzz entries via the differential oracle; no model is called.
package hydrate

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/0xjustus/quarry/internal/intake/target"
	"github.com/0xjustus/quarry/internal/platform/store"
	"github.com/0xjustus/quarry/internal/publish/artifact"
	"github.com/0xjustus/quarry/internal/publish/channels"
	"github.com/0xjustus/quarry/internal/verdict/oracle"
	"github.com/0xjustus/quarry/internal/verdict/verify"
)

type Entry struct {
	ID       string
	Project  string
	Vuln     target.Ingest
	Fix      target.Ingest
	Run      target.RunConfig
	Oracle   oracle.Spec
	Testcase []byte // PoV bytes; for image reproducers, a small ref manifest
	// BugClassHint is a fallback used only when the sanitizer report yields none.
	BugClassHint string
}

func (e Entry) descriptor() *target.Descriptor {
	spec := e.Oracle
	if spec.Differential == nil {
		spec.Differential = &oracle.Differential{FixedImage: e.ID + "-fix", Rule: oracle.PassOnVulnFailOnFixed}
	}
	fix := e.Fix
	return &target.Descriptor{
		Name:   e.ID,
		Ingest: e.Vuln,
		Fixed:  &fix,
		Run:    e.Run,
		Oracle: spec,
	}
}

type Result struct {
	EntryID       string
	Confirmed     bool
	ArtifactID    string
	BehavioralKey string
	Deduped       bool
	Duration      time.Duration
	Err           string
}

type Report struct {
	Results       []Result
	Hydrated      int
	Deduped       int
	Failed        int
	AgentCalls    int // ALWAYS 0: the agent-independence thesis, measured
	TotalDuration time.Duration
}

type Hydrator struct {
	Store     *store.Store
	Gate      *channels.Gate
	Sink      channels.ArtifactSink
	Signer    ed25519.PrivateKey
	DockerBin string
	Now       func() time.Time
	Log       func(string)
}

func (h *Hydrator) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

func (h *Hydrator) log(format string, a ...any) {
	if h.Log != nil {
		h.Log(fmt.Sprintf(format, a...))
	}
}

// Hydrate replays each entry; baseDir resolves relative paths.
func (h *Hydrator) Hydrate(ctx context.Context, entries []Entry, baseDir string) (Report, error) {
	if h.Signer != nil && h.Gate != nil {
		h.Gate.Signer = h.Signer
	}
	start := h.now()
	rep := Report{}
	for _, e := range entries {
		// aborted ≠ failed: an un-attempted entry is not a differential failure
		if err := ctx.Err(); err != nil {
			rep.TotalDuration = h.now().Sub(start)
			return rep, fmt.Errorf("hydrate: aborted after %d of %d entries: %w", len(rep.Results), len(entries), err)
		}
		res := h.one(ctx, e, baseDir)
		rep.Results = append(rep.Results, res)
		switch {
		case res.Err != "":
			rep.Failed++
		case !res.Confirmed:
			rep.Failed++
		case res.Deduped:
			rep.Deduped++
		default:
			rep.Hydrated++
		}
	}
	rep.TotalDuration = h.now().Sub(start)
	return rep, nil
}

func (h *Hydrator) one(ctx context.Context, e Entry, baseDir string) Result {
	t0 := h.now()
	res := Result{EntryID: e.ID}
	fail := func(err error) Result {
		res.Err = err.Error()
		res.Duration = h.now().Sub(t0)
		return res
	}

	prepared, err := target.Prepare(ctx, e.descriptor(), baseDir, h.DockerBin)
	if err != nil {
		return fail(fmt.Errorf("prepare: %w", err))
	}

	run, err := h.Store.CreateRun(ctx, "ARVO hydrate "+e.ID, prepared.Ref, "hydrate")
	if err != nil {
		return fail(err)
	}
	hyp, _ := h.Store.AddHypothesis(ctx, run.ID, "", "ARVO "+e.ID+": differential-verified crash", 1)

	v := &verify.Verifier{Runner: prepared.Runner, Store: h.Store}
	vres, err := v.Verify(ctx, verify.Request{
		RunID:        run.ID,
		HypothesisID: hyp.ID,
		Model:        "arvo-hydrate", // provenance only
		Spec:         prepared.Oracle,
		Base:         prepared.Base,
		Fixed:        prepared.Fixed,
		PoV:          e.Testcase,
	})
	if err != nil {
		_ = h.Store.SetHypothesisState(ctx, hyp.ID, store.HypExhausted, err.Error())
		_ = h.Store.FinishRun(ctx, run.ID, "aborted", map[string]any{"error": err.Error()})
		return fail(fmt.Errorf("differential verify: %w", err))
	}
	res.Confirmed = vres.Verdict.Pass
	if !vres.Verdict.Pass {
		_ = h.Store.SetHypothesisState(ctx, hyp.ID, store.HypRefuted, "differential not satisfied (universal crash or fix did not clean)")
		_ = h.Store.FinishRun(ctx, run.ID, "done", map[string]any{"confirmed": false})
		res.Duration = h.now().Sub(t0)
		return res
	}
	_ = h.Store.SetHypothesisState(ctx, hyp.ID, store.HypConfirmed, "")

	env, deduped, err := h.harvest(ctx, run.ID, e, prepared, &vres)
	if err != nil {
		_ = h.Store.FinishRun(ctx, run.ID, "done", map[string]any{"confirmed": true, "emit_error": err.Error()})
		return fail(fmt.Errorf("harvest: %w", err))
	}
	res.ArtifactID = env.Artifact.ID
	res.BehavioralKey = env.Artifact.BehavioralKey()
	res.Deduped = deduped
	res.Duration = h.now().Sub(t0)
	_ = h.Store.FinishRun(ctx, run.ID, "done", map[string]any{"confirmed": true, "artifact": env.Artifact.ID})
	h.log("hydrated %s → %s (%s)%s", e.ID, env.Artifact.Content.Crash.BugClass, env.Artifact.ID, dedupSuffix(deduped))
	return res
}

func (h *Hydrator) harvest(ctx context.Context, runID string, e Entry, prepared *target.Prepared, vres *verify.Result) (*artifact.Envelope, bool, error) {
	createdAt := h.now().UTC().Format(time.RFC3339)
	reproBlob, err := h.Store.PutBlob(ctx, e.Testcase, "application/x-quarry-reproducer")
	if err != nil {
		return nil, false, err
	}
	// artifact.PathSigFor, never a hydrate-only token, else ARVO + a live rediscovery split into two commons entries
	crash := crashFrom(vres, e.BugClassHint, artifact.PathSigFor(prepared.Base.StdinPoV), e.Testcase)
	bk := artifact.ComputeBehavioralKey(crash)
	// frame-less: never dedup, prefer a false split
	seen := false
	if artifact.FramesResolved(crash) {
		_, seen, _ = h.Store.Dedup(ctx, bk)
	}

	// specimen = the runnable target, distinct from the reproducer testcase
	specimen := &artifact.SpecimenRef{BlobHash: reproBlob, Media: "application/x-quarry-specimen", Bytes: int64(len(e.Testcase))}
	if e.Vuln.Kind == target.KindImage && e.Vuln.Image != "" {
		desc := []byte(e.Vuln.Image)
		sb, err := h.Store.PutBlob(ctx, desc, "application/x-quarry-image-target")
		if err != nil {
			return nil, false, err
		}
		specimen = &artifact.SpecimenRef{BlobHash: sb, Media: "application/x-quarry-image-target", Bytes: int64(len(desc))}
	}

	env := &artifact.Envelope{
		Artifact: artifact.Artifact{
			Content: artifact.Content{
				Specimen: specimen,
				Crash:    crash,
			},
			Reproducer: &artifact.Reproducer{BlobHash: reproBlob, Media: "application/x-quarry-reproducer", Bytes: int64(len(e.Testcase)), Oracle: prepared.Oracle, Verdict: vres.Verdict},
		},
		Placement:  artifact.Public, // patched public OSS bug
		Abstract:   summarize(e, crash),
		Provenance: artifact.Provenance{RunID: runID, ExperimentID: vres.ExperimentID, Model: "arvo-hydrate", AcquiredBy: "arvo"},
		CreatedAt:  createdAt,
	}
	if err := env.Artifact.ComputeID(); err != nil {
		return nil, false, err
	}

	out := env
	if h.Gate != nil && h.Sink != nil {
		e2, err := h.Gate.Emit(ctx, h.Sink, env)
		if err != nil {
			return nil, false, err
		}
		out = e2
	}
	if err := h.Store.SaveArtifact(ctx, runID, out); err != nil {
		return nil, false, err
	}
	if err := h.Store.RegisterFinding(ctx, out.Artifact.BehavioralKey(), out.Artifact.ID, runID); err != nil {
		return nil, false, err
	}
	if err := h.Store.IndexKeys(ctx, out.Artifact.ID, artifact.CrashKeys(crash)); err != nil {
		return nil, false, err
	}
	return out, seen, nil
}

// never hand-assemble: identity comes from artifact.CrashFromPoV; the hint only names a class the run didn't report
func crashFrom(vres *verify.Result, hint, pathSig string, pov []byte) artifact.Crash {
	p := vres.Primary
	c := artifact.CrashFromPoV(p, pathSig, pov)
	if p.Sanitizer.Fired {
		return c
	}
	switch {
	case hint != "":
		c.BugClass = hint
	case p.TermSignal == 0:
		// no observed fault: do not claim a crash class we did not see
		c.BugClass = "differential-crash"
	}
	return c
}

func summarize(e Entry, c artifact.Crash) string {
	loc := "the target"
	if len(c.Sites) > 0 && c.Sites[0] != "" {
		loc = c.Sites[0]
	}
	return fmt.Sprintf("differential-verified %s in %s (%s), patched upstream — reproduced from ARVO entry %s", c.BugClass, loc, e.Project, e.ID)
}

func dedupSuffix(d bool) string {
	if d {
		return " [dedup: behavior already known]"
	}
	return ""
}
