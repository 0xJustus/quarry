package backend

import (
	"cmp"
	"context"
	"os"

	"github.com/0xjustus/quarry/internal/discover/fuzz"
	"github.com/0xjustus/quarry/internal/discover/synth"
	"github.com/0xjustus/quarry/internal/verdict/oracle"
	"github.com/0xjustus/quarry/internal/verdict/runner"
)

// C delegates BuildImage→synth, RunOnce→runner, Fuzz→fuzz.
type C struct {
	DockerBin string
	ArgvTmpl  []string // in-container harness argv with a {poc} placeholder
	Sanitizer string
	Build     *synth.BuildSpec // nil ⇒ BuildImage is unsupported for this target
}

func (C) Name() string { return "c" }

func (c C) argv() []string {
	if len(c.ArgvTmpl) > 0 {
		return c.ArgvTmpl
	}
	return []string{synth.OracleBinPath, "{poc}"}
}
func (c C) sanitizer() string { return cmp.Or(c.Sanitizer, "asan") }

func (c C) Detect(dir string) bool {
	return detectSource(dir,
		[]string{"CMakeLists.txt", "Makefile", "configure", "configure.ac", "autogen.sh"},
		[]string{".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"})
}

func (c C) SynthHarness(function, kind string) (string, error) {
	return synth.RenderHarness(synth.HarnessSpec{
		Entry:     function,
		EntryCall: function + "(data, size);",
	}), nil
}

// there is no honest generic C build: without a BuildSpec, report the boundary
func (c C) BuildImage(ctx context.Context, dir string) (string, error) {
	if c.Build == nil {
		return "", errUnsupported("C BuildImage needs a target-specific synth.BuildSpec (build system + static-lib paths); none supplied")
	}
	return buildDockerfileImage(ctx, c.DockerBin, dir, synth.RenderDockerfile(*c.Build))
}

func (c C) RunOnce(ctx context.Context, image string, pov []byte) (Fault, error) {
	rr, err := runner.DockerRunner{DockerBin: c.DockerBin}.Run(ctx, runner.RunSpec{
		Image:     image,
		ArgvTmpl:  c.argv(),
		PoV:       pov,
		Sanitizer: c.sanitizer(),
	})
	if err != nil {
		return Fault{}, err
	}
	f := faultFromRunResult(rr)
	f.Output = []byte(rr.Stderr)
	return f, nil
}

func (c C) ClassifyFault(runOutput string) Fault {
	san := runner.ParseSanitizer("", runOutput)
	if !san.Fired {
		return Fault{Faulted: false, Class: FaultNone}
	}
	return Fault{Faulted: true, Class: FaultMemory, Signal: san.BugClass, Site: san.CrashSite}
}

func (c C) Fuzz(ctx context.Context, image, corpusDir string, budgetSecs int) ([][]byte, error) {
	out, err := os.MkdirTemp("", "quarry-c-fuzz-*")
	if err != nil {
		return nil, err
	}
	res, err := fuzz.Campaign{
		Image:       image,
		SeedDir:     corpusDir,
		OutDir:      out,
		DockerBin:   c.DockerBin,
		Duration:    durationSecs(budgetSecs),
		StopOnCrash: true,
	}.Run(ctx)
	if err != nil {
		return nil, err
	}
	crashes := make([][]byte, 0, len(res.Crashes))
	for _, cr := range res.Crashes {
		crashes = append(crashes, cr.Bytes)
	}
	return crashes, nil
}

// richer than the text-only ClassifyFault: signal/timeout/OOM arrive out-of-band
func faultFromRunResult(rr oracle.RunResult) Fault {
	switch {
	case rr.Sanitizer.Fired:
		return Fault{Faulted: true, Class: FaultMemory, Signal: rr.Sanitizer.BugClass, Site: rr.Sanitizer.CrashSite}
	case rr.OOMKilled:
		return Fault{Faulted: true, Class: FaultTimeout, Signal: "oom"}
	case rr.TimedOut:
		return Fault{Faulted: true, Class: FaultTimeout, Signal: "timeout"}
	case rr.TermSignal != 0:
		return Fault{Faulted: true, Class: FaultMemory, Signal: signalName(rr.TermSignal)}
	default:
		return Fault{Faulted: false, Class: FaultNone}
	}
}

var _ Fuzzer = C{}
