package agent

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/0xjustus/quarry/internal/verdict/oracle"
	"github.com/0xjustus/quarry/internal/verdict/runner"
)

const referenceBase = "quarry-fuzz:latest"

// the only runnable program in a reference image; {poc} is the runner's substitution token
const (
	referenceEntrypoint = "/harness"
	referencePoC        = "{poc}"
)

// indirected so tests can stub the docker build
var buildReference = BuildReferenceImage

type proposeReferenceTool struct {
	s         *Session
	installed bool // only a reference THIS tool installed may be refined
}

func (proposeReferenceTool) Name() string { return "propose_reference" }

func (proposeReferenceTool) Description() string {
	return "Author the semantic oracle for a LOGIC/SPEC bug that does not crash. Supply reference_source: a " +
		"self-contained program with the SAME input/output contract as the target harness (read the PoV file at " +
		"argv[1]; print the CORRECT output to stdout; exit 0), encoding what the code SHOULD do per its spec. " +
		"quarry compiles it and installs it as a differential REFERENCE; thereafter run_pov confirms a finding when " +
		"the target and your reference produce DIFFERENT output on the same input (an EXECUTED reference-diff — your " +
		"reference is code that runs, never a claim). Then find a diverging input with run_pov / run_generator. A " +
		"divergence is a sound bug ONLY if your reference is correct, so encode the SPEC, not the target's behavior. " +
		"language: c (default) or cpp."
}

func (proposeReferenceTool) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{` +
		`"reference_source":{"type":"string","description":"C/C++ source of the reference program: read argv[1] (the PoV file), print the CORRECT output to stdout, exit 0. Same I/O contract as the target harness."},` +
		`"language":{"type":"string","enum":["c","cpp"],"description":"c (default) or cpp"},` +
		`"note":{"type":"string","description":"what property/spec this reference encodes"}},"required":["reference_source"]}`)
}

type proposeReferenceArgs struct {
	ReferenceSource string `json:"reference_source"`
	Language        string `json:"language"`
	Note            string `json:"note"`
}

func (t *proposeReferenceTool) Invoke(ctx context.Context, args json.RawMessage) (string, error) {
	var a proposeReferenceArgs
	if err := json.Unmarshal(args, &a); err != nil {
		return "", fmt.Errorf("propose_reference: bad arguments %s: %w", truncateArgs(args), err)
	}
	if strings.TrimSpace(a.ReferenceSource) == "" {
		return "", fmt.Errorf("propose_reference: reference_source is required")
	}
	if t.s.Base.Image == "" {
		return "propose_reference is only available for container-image targets (the reference is built and run as an image).", nil
	}
	// fail closed: an operator-declared oracle is ground truth and is never replaceable
	if !t.installed && (t.s.Oracle.Differential != nil || t.s.Fixed != nil) {
		return "propose_reference REFUSED: this target already declares an operator-provided differential " +
			"oracle (the ground truth for this run). It is authoritative and cannot be replaced by an authored " +
			"reference. Confirm against the declared oracle with run_pov / run_generator instead.", nil
	}
	// no per-run PoV file ⇒ no shared I/O contract ⇒ every divergence is an artifact
	if t.s.Base.NoPoV || t.s.Base.Service != nil {
		return "propose_reference is unavailable for this target: it does not take a per-run PoV file " +
			"(self-contained reproducer or service/network target), so a reference that reads argv[1] cannot " +
			"share its I/O contract and any divergence would be an artifact, not evidence.", nil
	}
	docker := t.s.DockerBin
	if docker == "" {
		docker = "docker"
	}

	img, compileErr, err := buildReference(ctx, docker, a.ReferenceSource, a.Language)
	if err != nil {
		return "", err
	}
	if compileErr != "" {
		return "propose_reference: the reference did not COMPILE — fix it and call propose_reference again. Build error:\n" + compileErr, nil
	}

	fixed := ReferenceRunSpec(t.s.Base, img)
	t.s.Fixed = &fixed
	t.s.Oracle.Differential = &oracle.Differential{FixedImage: img, Rule: oracle.DivergeOnOutput}
	t.installed = true
	t.s.ReferenceSource, t.s.ReferenceLang = a.ReferenceSource, a.Language // differential_fuzz recompiles it

	if t.s.TargetSource != "" {
		return fmt.Sprintf("reference built and installed as the differential oracle (image %s). NEXT: call "+
			"differential_fuzz to FIND the diverging input by coverage-guided search — it compiles your reference and "+
			"the target into an abort-on-divergence harness, fuzzes it, and confirms any hit on the oracle, at zero "+
			"tokens spent guessing inputs. Only if differential_fuzz finds nothing (the target may be correct, or your "+
			"reference is wrong — re-check it against the spec) fall back to run_generator / run_pov with targeted "+
			"inputs, or refine and call propose_reference again.", img), nil
	}
	return fmt.Sprintf("reference built and installed as the differential oracle (image %s). run_pov / run_generator "+
		"now CONFIRM a finding when the target and your reference produce different output on the same input. Submit "+
		"candidate inputs to find a divergence — that divergence is the oracle-confirmed logic bug. If run_pov keeps "+
		"failing, either no input diverges (the target may be correct), or your reference is wrong (re-check it against "+
		"the spec) — refine and call propose_reference again.", img), nil
}

// inherit ONLY the timeout: the target's argv does not exist in a reference image
func ReferenceRunSpec(base runner.RunSpec, image string) runner.RunSpec {
	return runner.RunSpec{
		Image:    image,
		ArgvTmpl: []string{referenceEntrypoint, referencePoC},
		Timeout:  base.Timeout,
		Network:  false, // authored code is untrusted
	}
}

// compileErr ⇒ the source did not compile; err ⇒ an infra failure
func BuildReferenceImage(ctx context.Context, dockerBin, source, language string) (image string, compileErr string, err error) {
	if dockerBin == "" {
		dockerBin = "docker"
	}
	ext, compile := "c", "gcc -O1 /ref.c -o /harness"
	if language == "cpp" {
		ext, compile = "cpp", "g++ -std=c++17 -O1 /ref.cpp -o /harness"
	}
	// prove the local base tag exists before any compile failure can be blamed
	if out, ierr := exec.CommandContext(ctx, dockerBin, "image", "inspect", referenceBase).CombinedOutput(); ierr != nil {
		return "", "", fmt.Errorf("reference build: toolchain base image %s is unavailable (%v: %s) — build it (toolchain/Dockerfile.quarry-fuzz / `quarry toolctl populate`) and check the docker daemon",
			referenceBase, ierr, oneLine(tailLines(string(out), 3), 200))
	}
	sum := sha256.Sum256([]byte(ext + "\x00" + source))
	image = fmt.Sprintf("quarry-ref-%x:latest", sum[:6])
	dir, derr := os.MkdirTemp("", "quarry-ref-*")
	if derr != nil {
		return "", "", derr
	}
	defer os.RemoveAll(dir)
	if werr := os.WriteFile(filepath.Join(dir, "ref."+ext), []byte(source), 0o644); werr != nil {
		return "", "", werr
	}
	dockerfile := fmt.Sprintf("FROM %s\nCOPY ref.%s /ref.%s\nRUN %s\n", referenceBase, ext, ext, compile)
	if werr := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(dockerfile), 0o644); werr != nil {
		return "", "", werr
	}
	build := exec.CommandContext(ctx, dockerBin, "build", "--platform", "linux/amd64", "-t", image, dir)
	if out, berr := build.CombinedOutput(); berr != nil {
		tail := tailLines(string(out), 25)
		// never reached the compile step ⇒ systemErr, not the model's code
		if reason := infraBuildFailure(tail); reason != "" {
			return "", "", fmt.Errorf("reference build: %s — the reference source was never compiled: %s", reason, oneLine(tail, 400))
		}
		return "", tail, nil
	}
	return image, "", nil
}

// unambiguous infra failures only: either misattribution wastes the whole budget
func infraBuildFailure(out string) string {
	l := strings.ToLower(out)
	for _, m := range []struct{ needle, reason string }{
		{"cannot connect to the docker daemon", "the docker daemon is unreachable"},
		{"is the docker daemon running", "the docker daemon is unreachable"},
		{"permission denied while trying to connect", "no permission to reach the docker daemon"},
		{"pull access denied", "the toolchain base image is not available locally"},
		{"manifest unknown", "the toolchain base image is not available locally"},
		{"manifest for " + referenceBase + " not found", "the toolchain base image is not available locally"},
		{"failed to resolve source metadata", "the toolchain base image could not be resolved"},
		{"no match for platform", "no linux/amd64 image or emulation on this host"},
		{"exec format error", "no linux/amd64 emulation on this host"},
		{"cannot execute binary file", "no linux/amd64 emulation on this host"},
		{"no space left on device", "the build host is out of disk space"},
	} {
		if strings.Contains(l, m.needle) {
			return m.reason
		}
	}
	return ""
}
