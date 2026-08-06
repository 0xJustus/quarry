package target

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/0xjustus/quarry/internal/discover/fuzz"
	"github.com/0xjustus/quarry/internal/platform/broker"
	"github.com/0xjustus/quarry/internal/verdict/oracle"
	"github.com/0xjustus/quarry/internal/verdict/runner"

	"gopkg.in/yaml.v3"
)

type Kind string

const (
	KindBinary     Kind = "binary"
	KindLocal      Kind = "local"
	KindImage      Kind = "image"
	KindDockerfile Kind = "dockerfile"
	KindEndpoint   Kind = "endpoint"
)

// Descriptor is the on-disk target definition (quarry.yaml).
type Descriptor struct {
	Name      string        `yaml:"name"`
	Ingest    Ingest        `yaml:"ingest"`
	Run       RunConfig     `yaml:"run"`
	Oracle    oracle.Spec   `yaml:"oracle"`
	Fixed     *Ingest       `yaml:"fixed,omitempty"`
	SourceDir string        `yaml:"source_dir,omitempty"`
	CPG       *CPGConfig    `yaml:"cpg,omitempty"`
	Toolset   []ToolPin     `yaml:"toolset,omitempty"`
	Harness   *HarnessBuild `yaml:"harness,omitempty"`
}

// HarnessBuild declares harness SOURCE that quarry recompiles under its own instrumentation.
type HarnessBuild struct {
	SourceDir string   `yaml:"source_dir"`
	Entry     string   `yaml:"entry"` // relative to SourceDir
	Build     []string `yaml:"build,omitempty"`
	Cxx       bool     `yaml:"cxx,omitempty"`
	Apt       []string `yaml:"apt,omitempty"`
	// in-image paths, resolved by the build shell at WORKDIR /src
	IncludeDirs   []string `yaml:"include_dirs,omitempty"`
	LinkArtifacts []string `yaml:"link_artifacts,omitempty"`
	LinkLibs      []string `yaml:"link_libs,omitempty"`
	ExtraCFlags   []string `yaml:"extra_cflags,omitempty"`
	HarnessOut    string   `yaml:"harness_out,omitempty"`
	Cmplog        string   `yaml:"cmplog,omitempty"`
}

func (h *HarnessBuild) BuildSpec(baseDir string) fuzz.BuildSpec {
	return fuzz.BuildSpec{
		SourceDir:     resolve(baseDir, h.SourceDir),
		HarnessSource: h.Entry,
		BuildCommand:  h.Build,
		AptPackages:   h.Apt,
		HarnessCxx:    h.Cxx,
		IncludeDirs:   h.IncludeDirs,
		LinkArtifacts: h.LinkArtifacts,
		LinkLibs:      h.LinkLibs,
		ExtraCFlags:   h.ExtraCFlags,
		HarnessOut:    h.HarnessOut,
		CmplogOut:     h.Cmplog,
	}
}

// ToolPin pins a tool by content hash to an absolute in-container mount path.
type ToolPin struct {
	Hash string `yaml:"hash"`
	Path string `yaml:"path"`
}

func (d *Descriptor) toolset() broker.Toolset {
	if len(d.Toolset) == 0 {
		return broker.Toolset{}
	}
	pins := make([]broker.ToolPin, 0, len(d.Toolset))
	for _, p := range d.Toolset {
		pins = append(pins, broker.ToolPin{Hash: p.Hash, TargetPath: p.Path})
	}
	return broker.Toolset{Pins: pins}
}

// CPGConfig feeds c2cpg: without the real defines/includes it silently drops #ifdef'd code.
type CPGConfig struct {
	Defines  []string `yaml:"defines,omitempty"`
	Includes []string `yaml:"includes,omitempty"` // relative to the source root
}

type Ingest struct {
	Kind       Kind           `yaml:"kind"`
	Path       string         `yaml:"path,omitempty"`
	Build      string         `yaml:"build,omitempty"`
	Dockerfile string         `yaml:"dockerfile,omitempty"`
	Image      string         `yaml:"image,omitempty"`
	Binary     string         `yaml:"binary,omitempty"`
	Endpoint   string         `yaml:"endpoint,omitempty"`
	Service    *ServiceConfig `yaml:"service,omitempty"`
}

type ServiceConfig struct {
	Host    string   `yaml:"host,omitempty"`
	Port    int      `yaml:"port,omitempty"`
	Proto   string   `yaml:"proto,omitempty"` // tcp | udp | unix (default tcp)
	Address string   `yaml:"address,omitempty"`
	Launch  []string `yaml:"launch,omitempty"`
}

func (s ServiceConfig) address(fallback string) string {
	if s.Address != "" {
		return s.Address
	}
	if s.Host != "" && s.Port != 0 {
		return fmt.Sprintf("%s:%d", s.Host, s.Port)
	}
	if s.Port != 0 {
		return fmt.Sprintf("127.0.0.1:%d", s.Port)
	}
	return fallback
}

// RunConfig is the target contract: how to invoke it with a PoV.
type RunConfig struct {
	Argv      []string `yaml:"argv"` // argv[0] is the program; "{poc}" is the PoV placeholder
	StdinPoV  bool     `yaml:"stdin_pov"`
	Sanitizer string   `yaml:"sanitizer"`
	TimeoutS  int      `yaml:"timeout_s"`
	Workdir   string   `yaml:"workdir"`
	Network   bool     `yaml:"network"` // default false ⇒ air-gapped
	NoPoV     bool     `yaml:"no_pov"`  // self-contained reproducer: argv verbatim, no PoV injected
	Env       []string `yaml:"env"`     // the runner strips safety-critical vars
}

// Prepared is a ready-to-run target.
type Prepared struct {
	Runner  runner.Runner
	Base    runner.RunSpec
	Fixed   *runner.RunSpec
	Oracle  oracle.Spec
	Ref     string
	Desc    string
	Sources []string
	CPG     *CPGConfig
	Harness *fuzz.BuildSpec // non-nil ⇒ instrument-from-source: gates the AFL++ engine
}

// Load returns the descriptor and the dir that anchors its relative paths.
func Load(path string) (*Descriptor, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("target: read %s: %w", path, err)
	}
	var wrap struct {
		Target Descriptor `yaml:"target"`
	}
	if err := yaml.Unmarshal(data, &wrap); err == nil && wrap.Target.Ingest.Kind != "" {
		return &wrap.Target, filepath.Dir(path), validate(&wrap.Target)
	}
	var d Descriptor
	if err := yaml.Unmarshal(data, &d); err != nil {
		return nil, "", fmt.Errorf("target: parse %s: %w", path, err)
	}
	return &d, filepath.Dir(path), validate(&d)
}

func validate(d *Descriptor) error {
	// the argv waiver holds only for ingests quarry never invokes by argv
	if len(d.Run.Argv) == 0 {
		if d.Ingest.Kind != KindEndpoint {
			return fmt.Errorf("target %q: run.argv is required", d.Name)
		}
		if d.Fixed != nil && d.Fixed.Kind != KindEndpoint {
			return fmt.Errorf("target %q: run.argv is required: the `fixed:` build is kind %q, which is invoked by argv (only an endpoint fixed build shares the service-mode waiver)", d.Name, d.Fixed.Kind)
		}
	}
	if err := d.Oracle.Validate(); err != nil {
		return err
	}
	if d.Oracle.Differential != nil && d.Fixed == nil {
		return fmt.Errorf("target %q: oracle declares a differential but no `fixed:` build is provided", d.Name)
	}
	// both specs run through ONE Runner: refuse a cross-class fixed build here
	if d.Fixed != nil {
		fc, bc := runnerClass(d.Fixed.Kind), runnerClass(d.Ingest.Kind)
		if fc == "" {
			return fmt.Errorf("target %q: `fixed:` has unknown ingest kind %q", d.Name, d.Fixed.Kind)
		}
		if bc != "" && fc != bc {
			return fmt.Errorf("target %q: `fixed:` kind %q and ingest kind %q need different runners (%s vs %s); the differential runs both builds through one runner, so both must be the same class", d.Name, d.Fixed.Kind, d.Ingest.Kind, fc, bc)
		}
	}
	return nil
}

// runnerClass groups ingest kinds by the runner that executes them; "" is an unknown kind.
func runnerClass(k Kind) string {
	switch k {
	case KindBinary, KindLocal:
		return "local"
	case KindImage, KindDockerfile:
		return "docker"
	case KindEndpoint:
		return "service"
	}
	return ""
}

func (in Ingest) buildDir(baseDir string) string {
	if in.Path != "" {
		return resolve(baseDir, in.Path)
	}
	return resolve(baseDir, ".")
}

func argvTail(argv []string) []string {
	if len(argv) < 2 {
		return nil
	}
	return argv[1:]
}

func (in Ingest) runSpec(ctx context.Context, baseDir string, rc RunConfig, dockerBin string) (runner.Runner, runner.RunSpec, error) {
	spec := runner.RunSpec{
		ArgvTmpl:  nil,
		StdinPoV:  rc.StdinPoV,
		Sanitizer: rc.Sanitizer,
		Workdir:   rc.Workdir,
		Network:   rc.Network,
		NoPoV:     rc.NoPoV,
		Env:       rc.Env,
		Timeout:   time.Duration(rc.TimeoutS) * time.Second,
	}

	// fail closed BEFORE any build: a declared `build:` must run or be refused, never silently dropped.
	switch in.Kind {
	case KindBinary, KindLocal:
		named := in.Kind == KindBinary && in.Binary != ""
		if !named && len(rc.Argv) == 0 {
			return nil, spec, fmt.Errorf("target: ingest kind %q needs run.argv[0] to name the program to run", in.Kind)
		}
		if in.Build != "" {
			if err := runBuild(ctx, in.buildDir(baseDir), in.Build); err != nil {
				return nil, spec, err
			}
		}
	case KindImage, KindDockerfile, KindEndpoint:
		if in.Build != "" {
			return nil, spec, fmt.Errorf("target: ingest kind %q cannot run a `build:` step; build the artifact into the image or Dockerfile instead", in.Kind)
		}
	}

	switch in.Kind {
	case KindBinary:
		binRef := in.Binary
		if binRef == "" {
			binRef = rc.Argv[0]
		}
		spec.Binary = resolve(baseDir, binRef)
		spec.ArgvTmpl = argvTail(rc.Argv)
		if spec.Workdir == "" {
			spec.Workdir = resolve(baseDir, ".")
		}
		return runner.LocalRunner{}, spec, nil

	case KindLocal:
		dir := in.buildDir(baseDir)
		bin := resolve(dir, rc.Argv[0])
		spec.Binary = bin
		spec.ArgvTmpl = argvTail(rc.Argv)
		if spec.Workdir == "" {
			spec.Workdir = dir
		}
		return runner.LocalRunner{}, spec, nil

	case KindImage:
		spec.Image = in.Image
		// best-effort pin: a remote ref is not inspectable until pull, so never fail here
		if id, ierr := dockerImageID(ctx, dockerBin, in.Image); ierr == nil && id != "" {
			spec.Image = id
		}
		spec.ArgvTmpl = rc.Argv
		return runner.DockerRunner{DockerBin: dockerBin}, spec, nil

	case KindDockerfile:
		buildCtx, dockerfile := resolve(baseDir, in.Path), resolve(baseDir, in.Dockerfile)
		tag := "quarry-target/" + dockerfileTag(buildCtx, dockerfile) + ":latest"
		if err := dockerBuild(ctx, dockerBin, buildCtx, dockerfile, tag); err != nil {
			return nil, spec, err
		}
		// fail closed: falling back to the mutable tag reinstates the forgery the pin closes
		id, ierr := dockerImageID(ctx, dockerBin, tag)
		if ierr != nil {
			return nil, spec, fmt.Errorf("target: pin built image %s by content digest: %w", tag, ierr)
		}
		spec.Image = id
		spec.ArgvTmpl = rc.Argv
		return runner.DockerRunner{DockerBin: dockerBin}, spec, nil

	case KindEndpoint:
		svc := &runner.ServiceSpec{Proto: "tcp"}
		if in.Service != nil {
			if in.Service.Proto != "" {
				svc.Proto = in.Service.Proto
			}
			svc.Addr = in.Service.address(in.Endpoint)
			if len(in.Service.Launch) > 0 {
				svc.Launch = resolveLaunch(baseDir, in.Service.Launch)
			}
		} else {
			svc.Addr = in.Endpoint
		}
		if svc.Addr == "" && len(svc.Launch) == 0 {
			return nil, spec, fmt.Errorf("target: service mode needs an endpoint address or a launch command")
		}
		spec.Service = svc
		spec.ArgvTmpl = nil // service mode: the PoV goes over the socket, not argv
		return runner.ServiceRunner{}, spec, nil
	}
	return nil, spec, fmt.Errorf("target: unknown ingest kind %q", in.Kind)
}

func Prepare(ctx context.Context, d *Descriptor, baseDir, dockerBin string) (*Prepared, error) {
	rn, base, err := d.Ingest.runSpec(ctx, baseDir, d.Run, dockerBin)
	if err != nil {
		return nil, err
	}
	ts := d.toolset()
	base.Toolset = ts
	// taint parser only when the oracle declares CondTaint (else it can never fire); default-off otherwise
	if d.Oracle.WantsTaint() {
		base.Taint = runner.MarkerTaintParser{}
	}
	p := &Prepared{
		Runner: rn,
		Base:   base,
		Oracle: d.Oracle,
		Ref:    string(d.Ingest.Kind) + ":" + d.Name,
		Desc:   describe(d),
	}
	if d.SourceDir != "" {
		p.Sources = []string{resolve(baseDir, d.SourceDir)}
	}
	p.CPG = d.CPG
	if d.Harness != nil {
		bs := d.Harness.BuildSpec(baseDir)
		p.Harness = &bs
	}
	if d.Fixed != nil {
		fxRunner, fixed, err := d.Fixed.runSpec(ctx, baseDir, d.Run, dockerBin)
		if err != nil {
			return nil, fmt.Errorf("target: prepare fixed build: %w", err)
		}
		// backstop for a descriptor that never went through validate()
		if reflect.TypeOf(fxRunner) != reflect.TypeOf(rn) {
			return nil, fmt.Errorf("target: `fixed:` kind %q runs on %T but ingest kind %q runs on %T; the differential runs both builds through one runner", d.Fixed.Kind, fxRunner, d.Ingest.Kind, rn)
		}
		fixed.Toolset = ts
		if d.Oracle.WantsTaint() {
			fixed.Taint = runner.MarkerTaintParser{}
		}
		p.Fixed = &fixed
	}
	return p, nil
}

// SetProvisioner injects the toolset provisioner; the CLI owns the store and allowlist.
func (p *Prepared) SetProvisioner(pr *broker.Provisioner) {
	p.Base.Provisioner = pr
	if p.Fixed != nil {
		p.Fixed.Provisioner = pr
	}
}

func describe(d *Descriptor) string {
	var b strings.Builder
	fmt.Fprintf(&b, "name: %s\ningest: %s\n", d.Name, d.Ingest.Kind)
	fmt.Fprintf(&b, "invocation: %s\n", strings.Join(d.Run.Argv, " "))
	if d.Run.Sanitizer != "" {
		fmt.Fprintf(&b, "sanitizer: %s\n", d.Run.Sanitizer)
	}
	if d.Fixed != nil {
		b.WriteString("differential: a fixed build is available (pass_on_vuln_fail_on_fixed)\n")
	}
	return b.String()
}

func runBuild(ctx context.Context, dir, build string) error {
	cmd := exec.CommandContext(ctx, "sh", "-c", build)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("target: build failed: %w\n%s", err, string(out))
	}
	return nil
}

// dockerfileTag digests the ABSOLUTE paths: relative fragments collide across targets.
func dockerfileTag(buildCtx, dockerfile string) string {
	sum := sha256.Sum256([]byte(buildCtx + "\n" + dockerfile))
	name := sanitizeTag(filepath.Base(buildCtx) + "-" + filepath.Base(dockerfile))
	return name + "-" + hex.EncodeToString(sum[:6])
}

// podman prints a bare hex digest where docker prints "sha256:…"; both name content.
func dockerImageID(ctx context.Context, dockerBin, ref string) (string, error) {
	out, err := exec.CommandContext(ctx, dockerOrDefault(dockerBin), "inspect", "--format", "{{.Id}}", ref).Output()
	if err != nil {
		return "", err
	}
	id := strings.TrimSpace(string(out))
	if isHexDigest(id) {
		id = "sha256:" + id
	}
	if !isHexDigest(strings.TrimPrefix(id, "sha256:")) {
		return "", fmt.Errorf("target: unexpected image id %q for %s", id, ref)
	}
	return id, nil
}

func isHexDigest(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func dockerOrDefault(dockerBin string) string {
	if dockerBin == "" {
		return "docker"
	}
	return dockerBin
}

func dockerBuild(ctx context.Context, dockerBin, buildCtx, dockerfile, tag string) error {
	args := []string{"build", "-t", tag}
	if dockerfile != "" {
		args = append(args, "-f", dockerfile)
	}
	if buildCtx == "" {
		buildCtx = "."
	}
	args = append(args, buildCtx)
	cmd := exec.CommandContext(ctx, dockerOrDefault(dockerBin), args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("target: docker build failed: %w\n%s", err, string(out))
	}
	return nil
}

// absolute matters: os/exec resolves a relative binary against the parent cwd.
func resolve(baseDir, p string) string {
	if p == "" {
		return ""
	}
	joined := p
	if !filepath.IsAbs(p) {
		joined = filepath.Join(baseDir, p)
	}
	if abs, err := filepath.Abs(joined); err == nil {
		return abs
	}
	return joined
}

// resolveLaunch anchors a relative path-bearing argv[0]; a bare PATH command stays verbatim.
func resolveLaunch(baseDir string, launch []string) []string {
	out := append([]string(nil), launch...)
	if len(out) > 0 && strings.ContainsRune(out[0], filepath.Separator) && !filepath.IsAbs(out[0]) {
		out[0] = resolve(baseDir, out[0])
	}
	return out
}

func sanitizeTag(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "target"
	}
	if len(out) > 40 {
		out = out[:40]
	}
	return out
}
