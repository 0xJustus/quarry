package agent

import (
	"github.com/0xjustus/quarry/internal/platform/store"
	"github.com/0xjustus/quarry/internal/verdict/oracle"
	"github.com/0xjustus/quarry/internal/verdict/runner"
	"github.com/0xjustus/quarry/internal/verdict/verify"
)

// Session is the shared state one agent works against: workspace, oracle/target specs, and the verdict it is trying to reach.
type Session struct {
	Store    *store.Store
	Verifier *verify.Verifier

	RunID        string
	HypothesisID string
	Model        string // recorded as PoV provenance

	Workspace *Workspace

	Oracle oracle.Spec     // spec run_pov applies (mutable: propose_reference installs a reference-diff)
	Base   runner.RunSpec  // authoritative target run template
	Fixed  *runner.RunSpec // optional differential fixed-image template (set by propose_reference)

	// TargetSource is the target harness source seeded by the loop; with ReferenceSource it forms the abort-on-divergence differential harness (Next Builds #2).
	TargetSource string
	// ReferenceSource / ReferenceLang record the LAST reference propose_reference installed, so differential_fuzz can recompile the abort-on-divergence harness without re-asking the model.
	ReferenceSource string
	ReferenceLang   string

	// DockerBin backs propose_reference (ADR-0008), building the analyst-authored reference image; empty ⇒ "docker" (only meaningful for image targets).
	DockerBin string

	// Spawned holds sub-hypotheses proposed via spawn_hypothesis for the supervisor.
	Spawned []string

	// Outcome, updated by run_pov.
	Confirmed       bool
	LastVerdict     *oracle.Verdict
	LastResult      *verify.Result
	LastPoV         []byte         // most recent submitted PoV bytes (pass or fail) — when the run ends un-confirmed this is the best failed attempt, fed to the self-correcting retry (ADR-0005)
	ConfirmedPoV    []byte         // PoV bytes that produced the passing verdict
	ConfirmedResult *verify.Result // the passing result, snapshotted so a later failing run_pov can't overwrite it
	PoVSubmissions  int

	// CandidateSink, if set, receives every PoV submitted (pass or fail) — the scientist->fuzzer arrow of the ADR-0005 ensemble; nil in a standalone run.
	CandidateSink func([]byte)

	// CodeNav, if set, backs the callers/callees navigation tools; nil when there is no seeded source (the nav tools are then omitted from the belt).
	CodeNav CodeNavigator

	// CPG, if set, backs the Code Property Graph tools (ADR-0007); nil ⇒ the cpg_* tools are omitted. Every CPG answer is a lead the oracle must still confirm.
	CPG CPGQuerier

	// BinaryPath, if set, is the HOST path to the target binary for the read-only bin_* tools (A4), set only for a source-less host-local black-box target; empty ⇒ the bin_* tools are omitted. Every answer is a lead the oracle confirms.
	BinaryPath string

	// genRuns counts run_generator invocations, giving each batch its own output subdir (the workspace has no delete).
	genRuns int
}
