package core

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/0xjustus/quarry/internal/intake/target"
	"github.com/0xjustus/quarry/internal/platform/audit"
	"github.com/0xjustus/quarry/internal/platform/broker"
	"github.com/0xjustus/quarry/internal/platform/fly"
	"github.com/0xjustus/quarry/internal/platform/toolctl"
	"github.com/0xjustus/quarry/internal/publish/autovet"
	"github.com/0xjustus/quarry/internal/verdict/oracle"
)

const (
	defaultToolStore    = "toolchain/store"
	defaultToolManifest = "toolchain/manifest.yaml"
)

type ToolPopulateRequest struct {
	Caller    Caller `json:"caller,omitempty"`
	Manifest  string `json:"manifest,omitempty"`
	Store     string `json:"store,omitempty"`
	DockerBin string `json:"docker_bin,omitempty"`
	DryRun    bool   `json:"dry_run,omitempty"`
}

type ToolPlan struct {
	Name         string   `json:"name"`
	SourceRepo   string   `json:"source_repo"`
	SourceCommit string   `json:"source_commit"`
	Build        string   `json:"build"`
	Extract      []string `json:"extract,omitempty"`
	ExpectedPin  string   `json:"expected_pin,omitempty"`
	TargetPath   string   `json:"target_path"`
}

type PinnedTool struct {
	Name       string `json:"name"`
	Hash       string `json:"hash"`
	TargetPath string `json:"target_path"`
	Size       int    `json:"size"`
}

type ToolPopulateResult struct {
	DryRun         bool         `json:"dry_run"`
	Plans          []ToolPlan   `json:"plans,omitempty"`
	Pinned         []PinnedTool `json:"pinned,omitempty"`
	ProvenancePath string       `json:"provenance_path,omitempty"`
}

func (e *Engine) ToolPopulate(ctx context.Context, req ToolPopulateRequest) (ToolPopulateResult, error) {
	log := e.logFor(req.Caller.Principal, req.Caller.Session)
	manifest := req.Manifest
	if manifest == "" {
		manifest = defaultToolManifest
	}
	store := req.Store
	if store == "" {
		store = defaultToolStore
	}
	sp := log.Start("core.ToolPopulate", audit.KindCall, fmt.Sprintf("manifest:%s store:%s dryrun:%v", manifest, store, req.DryRun))
	res, err := e.toolPopulate(ctx, log, req, manifest, store)
	sp.End(toolPopulateSummary(res, err), err)
	return res, err
}

func (e *Engine) toolPopulate(ctx context.Context, log audit.Recorder, req ToolPopulateRequest, manifest, store string) (ToolPopulateResult, error) {
	m, baseDir, err := toolctl.Load(manifest)
	if err != nil {
		return ToolPopulateResult{}, err
	}
	bin := req.DockerBin
	if bin == "" {
		bin = e.cfg.DockerBin
	}
	if bin == "" {
		bin = "docker"
	}

	if req.DryRun {
		plans, err := m.Plans(baseDir)
		if err != nil {
			return ToolPopulateResult{}, err
		}
		out := ToolPopulateResult{DryRun: true}
		for _, p := range plans {
			tp := ToolPlan{
				Name:         p.Name,
				SourceRepo:   p.Prov.Source.Repo,
				SourceCommit: p.Prov.Source.Commit,
				Build:        toolctl.Command(bin, p.BuildArgv),
				ExpectedPin:  p.ExpectedPin,
				TargetPath:   p.Prov.TargetPath,
			}
			for _, argv := range p.Extract.Argvs("<scratch>/" + p.Name + ".artifact") {
				tp.Extract = append(tp.Extract, toolctl.Command(bin, argv))
			}
			out.Plans = append(out.Plans, tp)
		}
		return out, nil
	}

	cmd := auditedCommander{inner: dockerCommander{bin: bin}, log: log}
	fresh, err := toolctl.Populate(ctx, m, baseDir, store, cmd, toolctl.PopulateOptions{})
	if err != nil {
		return ToolPopulateResult{}, err
	}
	out := ToolPopulateResult{ProvenancePath: toolctl.ProvenancePath(store)}
	for _, r := range fresh {
		out.Pinned = append(out.Pinned, PinnedTool{Name: r.Name, Hash: r.Hash, TargetPath: r.TargetPath, Size: r.Size})
	}
	return out, nil
}

func toolPopulateSummary(res ToolPopulateResult, err error) string {
	if err != nil {
		return "error"
	}
	if res.DryRun {
		return fmt.Sprintf("planned:%d", len(res.Plans))
	}
	return fmt.Sprintf("pinned:%d", len(res.Pinned))
}

type ToolListRequest struct {
	Caller Caller `json:"caller,omitempty"`
	Store  string `json:"store,omitempty"`
}

type ToolListResult struct {
	Store string               `json:"store"`
	Tools []toolctl.Provenance `json:"tools"`
}

func (e *Engine) ToolList(ctx context.Context, req ToolListRequest) (ToolListResult, error) {
	log := e.logFor(req.Caller.Principal, req.Caller.Session)
	store := req.Store
	if store == "" {
		store = defaultToolStore
	}
	sp := log.Start("core.ToolList", audit.KindAccess, "store:"+store)
	recs, err := toolctl.LoadProvenance(store)
	if err != nil {
		sp.End("error", err)
		return ToolListResult{}, err
	}
	sp.End(fmt.Sprintf("tools:%d", len(recs)), nil)
	return ToolListResult{Store: store, Tools: recs}, nil
}

type ToolVerifyRequest struct {
	Caller Caller `json:"caller,omitempty"`
	Store  string `json:"store,omitempty"`
}

type ToolVerifyItem struct {
	Name string `json:"name"`
	Hash string `json:"hash"`
	OK   bool   `json:"ok"`
	Note string `json:"note,omitempty"`
}

type ToolVerifyResult struct {
	Store string           `json:"store"`
	AllOK bool             `json:"all_ok"`
	Total int              `json:"total"`
	Bad   int              `json:"bad"`
	Items []ToolVerifyItem `json:"items"`
}

func (e *Engine) ToolVerify(ctx context.Context, req ToolVerifyRequest) (ToolVerifyResult, error) {
	log := e.logFor(req.Caller.Principal, req.Caller.Session)
	store := req.Store
	if store == "" {
		store = defaultToolStore
	}
	sp := log.Start("core.ToolVerify", audit.KindAccess, "store:"+store)
	vres, err := toolctl.Verify(store)
	if err != nil {
		sp.End("error", err)
		return ToolVerifyResult{}, err
	}
	out := ToolVerifyResult{Store: store, AllOK: true, Total: len(vres)}
	for _, v := range vres {
		if !v.OK {
			out.AllOK = false
			out.Bad++
		}
		out.Items = append(out.Items, ToolVerifyItem{Name: v.Name, Hash: v.Hash, OK: v.OK, Note: v.Note})
	}
	sp.End(fmt.Sprintf("bad:%d/%d", out.Bad, out.Total), nil)
	return out, nil
}

type dockerCommander struct{ bin string }

func (d dockerCommander) Run(ctx context.Context, argv []string) error {
	cmd := exec.CommandContext(ctx, d.bin, argv...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w\n%s", d.bin, strings.Join(argv, " "), err, string(out))
	}
	return nil
}

type auditedCommander struct {
	inner toolctl.Commander
	log   audit.Recorder
}

func (a auditedCommander) Run(ctx context.Context, argv []string) error {
	verb := "docker"
	if len(argv) > 0 {
		verb += " " + argv[0]
	}
	sp := a.log.Start("docker.Run", audit.KindSideEffect, verb)
	err := a.inner.Run(ctx, argv)
	sp.End(sideEffectSummary(err), err)
	return err
}

type ProvisionPlanRequest struct {
	Caller     Caller   `json:"caller,omitempty"`
	TargetFile string   `json:"target_file"`
	Store      string   `json:"store"`
	ExtraAllow []string `json:"extra_allow,omitempty"`
}

type MountEntry struct {
	HostPath      string `json:"host_path"`
	ContainerPath string `json:"container_path"`
	ReadOnly      bool   `json:"read_only"`
	Hash          string `json:"hash"`
}

type ProvisionPlanResult struct {
	ToolsetDeclared bool         `json:"toolset_declared"`
	Allowlisted     int          `json:"allowlisted"`
	Mounts          []MountEntry `json:"mounts,omitempty"`
}

func (e *Engine) ProvisionPlan(ctx context.Context, req ProvisionPlanRequest) (ProvisionPlanResult, error) {
	log := e.logFor(req.Caller.Principal, req.Caller.Session)
	sp := log.Start("core.ProvisionPlan", audit.KindAccess, fmt.Sprintf("target:%s store:%s", req.TargetFile, req.Store))
	res, err := e.provisionPlan(req)
	sp.End(provisionSummary(res, err), err)
	return res, err
}

func (e *Engine) provisionPlan(req ProvisionPlanRequest) (ProvisionPlanResult, error) {
	if req.TargetFile == "" {
		return ProvisionPlanResult{}, fmt.Errorf("provision: target_file is required")
	}
	if req.Store == "" {
		return ProvisionPlanResult{}, fmt.Errorf("provision: store is required")
	}
	desc, _, err := target.Load(req.TargetFile)
	if err != nil {
		return ProvisionPlanResult{}, fmt.Errorf("provision: load target: %w", err)
	}
	ts := toolsetOf(desc)
	if ts.Empty() {
		return ProvisionPlanResult{ToolsetDeclared: false}, nil
	}
	allow, err := toolctl.Allowlist(req.Store)
	if err != nil {
		return ProvisionPlanResult{}, fmt.Errorf("provision: %w", err)
	}
	for _, h := range req.ExtraAllow {
		if h = strings.TrimSpace(h); h != "" {
			allow = append(allow, h)
		}
	}
	store := broker.NewLocalStore(req.Store, allow)
	pr := broker.NewProvisioner(store)
	plan, err := pr.Provision(ts)
	if err != nil {
		return ProvisionPlanResult{}, fmt.Errorf("provision: %w", err)
	}
	out := ProvisionPlanResult{ToolsetDeclared: true, Allowlisted: len(allow)}
	for _, m := range plan.Mounts {
		out.Mounts = append(out.Mounts, MountEntry{
			HostPath: m.HostPath, ContainerPath: m.ContainerPath, ReadOnly: m.ReadOnly, Hash: m.Hash,
		})
	}
	return out, nil
}

func toolsetOf(d *target.Descriptor) broker.Toolset {
	if len(d.Toolset) == 0 {
		return broker.Toolset{}
	}
	pins := make([]broker.ToolPin, 0, len(d.Toolset))
	for _, p := range d.Toolset {
		pins = append(pins, broker.ToolPin{Hash: p.Hash, TargetPath: p.Path})
	}
	return broker.Toolset{Pins: pins}
}

func provisionSummary(res ProvisionPlanResult, err error) string {
	if err != nil {
		return "error"
	}
	if !res.ToolsetDeclared {
		return "no-toolset"
	}
	return fmt.Sprintf("mounts:%d", len(res.Mounts))
}

type AutovetRequest struct {
	Caller   Caller          `json:"caller,omitempty"`
	Entries  []autovet.Entry `json:"entries"`
	FlyApp   string          `json:"fly_app,omitempty"`
	FlyToken string          `json:"fly_token,omitempty"`
	MemMB    int             `json:"memory_mb,omitempty"`
	TimeoutS int             `json:"timeout_s,omitempty"`
	Tree     string          `json:"tree,omitempty"`
}

type AutovetResult struct {
	Admitted     int              `json:"admitted"`
	Rejected     int              `json:"rejected"`
	Inconclusive int              `json:"inconclusive"`
	Total        int              `json:"total"`
	Vetted       int              `json:"vetted"`
	Results      []autovet.Result `json:"results"`
}

func (e *Engine) Autovet(ctx context.Context, req AutovetRequest) (AutovetResult, error) {
	log := e.logFor(req.Caller.Principal, req.Caller.Session)
	app := req.FlyApp
	if app == "" {
		app = "quarry-vetd"
	}
	sp := log.Start("core.Autovet", audit.KindCall, fmt.Sprintf("app:%s entries:%d", app, len(req.Entries)))
	res, err := e.autovet(ctx, log, req, app)
	sp.End(autovetSummary(res, err), err)
	return res, err
}

func (e *Engine) autovet(ctx context.Context, log audit.Recorder, req AutovetRequest, app string) (AutovetResult, error) {
	token := req.FlyToken
	if token == "" {
		token = os.Getenv("FLY_API_TOKEN")
	}
	if token == "" {
		return AutovetResult{}, fmt.Errorf("autovet: a Fly API token is required (set fly_token or FLY_API_TOKEN)")
	}
	if len(req.Entries) == 0 {
		return AutovetResult{}, fmt.Errorf("autovet: at least one entry is required")
	}
	memMB := req.MemMB
	if memMB <= 0 {
		memMB = 512
	}
	timeoutS := req.TimeoutS
	if timeoutS <= 0 {
		timeoutS = 180
	}
	client := fly.Client{App: app, Token: token}

	esp := log.Start("fly.EnsureEgressDenyPolicy", audit.KindSideEffect, "app:"+app)
	perr := client.EnsureEgressDenyPolicy(ctx)
	esp.End(sideEffectSummary(perr), perr)
	if perr != nil {
		return AutovetResult{}, fmt.Errorf("autovet: %w", perr)
	}

	d := &coreFlyDispatcher{
		client:  client,
		memMB:   memMB,
		timeout: time.Duration(timeoutS) * time.Second,
		log:     log,
	}
	results := autovet.Run(ctx, d, req.Entries)
	admitted, rejected, inconclusive := autovet.Summary(results)

	if req.Tree != "" {
		if werr := autovet.WriteLedger(req.Tree, time.Now().UTC().Format(time.RFC3339), results); werr != nil {
			return AutovetResult{}, fmt.Errorf("autovet: write ledger: %w", werr)
		}
	}

	return AutovetResult{
		Admitted: admitted, Rejected: rejected, Inconclusive: inconclusive,
		Total: len(req.Entries), Vetted: len(results), Results: results,
	}, nil
}

func autovetSummary(res AutovetResult, err error) string {
	if err != nil {
		return "error"
	}
	return fmt.Sprintf("admitted:%d rejected:%d inconclusive:%d", res.Admitted, res.Rejected, res.Inconclusive)
}

type coreFlyDispatcher struct {
	client  fly.Client
	memMB   int
	timeout time.Duration
	log     audit.Recorder
}

func (d *coreFlyDispatcher) Dispatch(ctx context.Context, e autovet.Entry) (autovet.Verdict, error) {
	req, err := inImageVetRequest(e.Binary, e.Argv, e.Sanitizer, e.NoPoV)
	if err != nil {
		return autovet.Verdict{}, err
	}
	sp := d.log.Start("fly.Dispatch", audit.KindSideEffect, fmt.Sprintf("id:%s image:%s", e.ID, e.Image))
	ctx, cancel := context.WithTimeout(ctx, d.timeout+60*time.Second)
	defer cancel()
	code, m, err := toolsDispatchOnce(ctx, d.client, e.Image, d.memMB, req, d.timeout)
	if err != nil {
		sp.End("error", err)
		return autovet.Verdict{}, err
	}
	st, detail := vetOutcome(code)
	sp.End(fmt.Sprintf("machine:%s exit:%d %s", m.ID, code, st), nil)
	return autovet.Verdict{Status: st, ExitCode: code, Detail: detail}, nil
}

func inImageVetRequest(inImageBin string, argv []string, san string, nopov bool) ([]byte, error) {
	run := map[string]any{"sanitizer": san, "binary": inImageBin, "argv": argv}
	if nopov {
		run["nopov"] = true
	}
	reqBody := map[string]any{
		"artifact_id": "autovet",
		"oracle":      anyCrashOracle(),
		"run":         run,
		"pov_b64":     base64.StdEncoding.EncodeToString(nil),
	}
	b, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}
	if len(b) > 900_000 {
		return nil, fmt.Errorf("autovet: vet job is %d bytes; too large to inline via env", len(b))
	}
	return b, nil
}

func toolsDispatchOnce(ctx context.Context, cl fly.Client, flyImage string, memMB int, vetReq []byte, timeout time.Duration) (int, fly.Machine, error) {
	cfg := fly.MachineConfig{
		Image: flyImage,
		Env:   map[string]string{"QUARRY_VET_REQUEST_B64": base64.StdEncoding.EncodeToString(vetReq)},
		Guest: fly.Guest{CPUKind: "shared", CPUs: 1, MemoryMB: memMB},
	}
	return cl.RunOneshot(ctx, cfg, timeout)
}

func vetOutcome(code int) (autovet.Status, string) {
	switch code {
	case 0:
		return autovet.StatusAdmitted, "oracle-confirmed on an air-gapped Machine; auto-destroyed"
	case 3:
		return autovet.StatusRejected, "the candidate did not reproduce on re-execution"
	default:
		return autovet.StatusInconclusive, fmt.Sprintf("vetd exited %d (request/infra error, or the VM was killed): nothing was observed, so this is NOT a rejection", code)
	}
}

func anyCrashOracle() oracle.Spec {
	return oracle.Spec{Require: "any", Conditions: []oracle.Condition{
		{Type: oracle.CondSanitizer, Tool: "asan"},
		{Type: oracle.CondSignal, Signals: []string{"SIGSEGV", "SIGABRT", "SIGBUS", "SIGFPE", "SIGILL"}},
		{Type: oracle.CondTimeout},
	}}
}

func sideEffectSummary(err error) string {
	if err != nil {
		return "error"
	}
	return "ok"
}
