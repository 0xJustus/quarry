package backend

import (
	"cmp"
	"context"
	"fmt"
	"strings"
)

func detectPython(dir string) bool {
	return detectSource(dir,
		[]string{"pyproject.toml", "setup.py", "requirements.txt"},
		[]string{".py"})
}

// Python is the Atheris discovery backend.
type Python struct {
	DockerBin string
	BaseImage string
	Module    string
	Function  string
	Catch     []string // exception types the harness swallows; empty ⇒ any uncaught exception is a finding
}

func (Python) Name() string { return "python" }

func (p Python) baseImage() string { return cmp.Or(p.BaseImage, "python:3.12") }
func (p Python) module() string    { return cmp.Or(p.Module, "target") }
func (p Python) function() string  { return cmp.Or(p.Function, "process") }

func (p Python) Detect(dir string) bool { return detectPython(dir) }

func (p Python) SynthHarness(function, kind string) (string, error) {
	if function == "" {
		function = p.function()
	}
	catch := "()" // empty tuple never matches, so nothing is swallowed
	if len(p.Catch) > 0 {
		catch = "(" + strings.Join(p.Catch, ", ") + ")"
	}
	return fmt.Sprintf(`import atheris
import sys

with atheris.instrument_imports():
    import %s

@atheris.instrument_func
def TestOneInput(data):
    try:
        %s.%s(data)
    except %s:
        return

atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()
`, p.module(), p.module(), function, catch), nil
}

// atheris has no arm64 wheel: clang builds its libFuzzer bindings in-image
func (p Python) dockerfile() string {
	return "FROM " + p.baseImage() + "\n" +
		"RUN apt-get update -qq && apt-get install -y -qq clang && rm -rf /var/lib/apt/lists/*\n" +
		"RUN CLANG_BIN=clang pip install --quiet atheris\n" +
		"WORKDIR /app\nCOPY . /app\n"
}

func (p Python) BuildImage(ctx context.Context, dir string) (string, error) {
	harness, err := p.SynthHarness(p.function(), "fuzz")
	if err != nil {
		return "", err
	}
	return buildWithFiles(ctx, p.DockerBin, dir, p.dockerfile(), genFile{"quarry_harness.py", harness})
}

func (p Python) RunOnce(ctx context.Context, image string, pov []byte) (Fault, error) {
	return runPoV(ctx, p.DockerBin, "quarry-atheris-pov-*", image, pov, nil,
		[]string{"python", "/app/quarry_harness.py", "/pov"}, ClassifyPython)
}

func (p Python) ClassifyFault(runOutput string) Fault { return ClassifyPython(runOutput) }

func (p Python) Fuzz(ctx context.Context, image, corpusDir string, budgetSecs int) ([][]byte, error) {
	return fuzzCampaign(ctx, p.DockerBin, "quarry-atheris-out-*", budgetSecs, func(out string, budget int) []string {
		args := []string{"run", "--rm", "--network", "none", "-v", out + ":/crashes"}
		if corpusDir != "" {
			args = append(args, "-v", corpusDir+":/corpus:ro")
		}
		args = append(args, image, "python", "/app/quarry_harness.py",
			fmt.Sprintf("-max_total_time=%d", budget), "-artifact_prefix=/crashes/")
		if corpusDir != "" {
			args = append(args, "/corpus")
		}
		return args
	})
}

// PythonBackend is the lightweight verifier the grounding path uses: run the target script directly.
type PythonBackend struct {
	DockerBin string
	BaseImage string
	Entry     string
}

func (p PythonBackend) Name() string { return "python" }

func (p PythonBackend) baseImage() string { return cmp.Or(p.BaseImage, "python:3.12-slim") }
func (p PythonBackend) entry() string     { return cmp.Or(p.Entry, "target.py") }

func (p PythonBackend) Detect(dir string) bool { return detectPython(dir) }

func (p PythonBackend) BuildImage(ctx context.Context, dir string) (string, error) {
	df := "FROM " + p.baseImage() + "\nWORKDIR /app\nCOPY . /app\n"
	return buildDockerfileImage(ctx, p.DockerBin, dir, df)
}

func (p PythonBackend) RunOnce(ctx context.Context, image string, pov []byte) (Fault, error) {
	return runPoV(ctx, p.DockerBin, "quarry-py-pov-*", image, pov, nil,
		[]string{"python", "/app/" + p.entry(), "/pov"}, ClassifyPython)
}

func (p PythonBackend) ClassifyFault(runOutput string) Fault { return ClassifyPython(runOutput) }

var _ Fuzzer = Python{}

// verify-only by design: the capability split is per-capability, not per-language
var _ Verifier = PythonBackend{}
