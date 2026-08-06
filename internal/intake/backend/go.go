package backend

import (
	"cmp"
	"context"
	"strings"
)

type Go struct {
	DockerBin string
	BaseImage string
	RunArgv   []string // in-container run argv with a {poc} placeholder
	FuzzFunc  string   // the testing.F target name Fuzz needs
}

func (Go) Name() string { return "go" }

func (g Go) baseImage() string { return cmp.Or(g.BaseImage, "golang:1.23") }

func (g Go) Detect(dir string) bool {
	return detectSource(dir, []string{"go.mod"}, []string{".go"})
}

func (g Go) SynthHarness(function, kind string) (string, error) {
	fn := "Fuzz" + capitalize(function)
	return "func " + fn + "(f *testing.F) {\n" +
		"\tf.Fuzz(func(t *testing.T, data []byte) {\n" +
		"\t\t_ = " + function + "(data)\n" +
		"\t})\n}\n", nil
}

func (g Go) BuildImage(ctx context.Context, dir string) (string, error) {
	df := "FROM " + g.baseImage() + "\nWORKDIR /app\nCOPY . /app\n" +
		"RUN go build -o /app/target ./... || go build -o /app/target .\n"
	return buildDockerfileImage(ctx, g.DockerBin, dir, df)
}

func (g Go) RunOnce(ctx context.Context, image string, pov []byte) (Fault, error) {
	argv := g.RunArgv
	if len(argv) == 0 {
		argv = []string{"/app/target", "{poc}"}
	}
	run := make([]string, 0, len(argv))
	for _, a := range argv {
		run = append(run, strings.ReplaceAll(a, "{poc}", "/pov"))
	}
	return runPoV(ctx, g.DockerBin, "quarry-go-pov-*", image, pov, nil, run, ClassifyGo)
}

func (g Go) ClassifyFault(runOutput string) Fault { return ClassifyGo(runOutput) }

func (g Go) Fuzz(ctx context.Context, image, corpusDir string, budgetSecs int) ([][]byte, error) {
	if g.FuzzFunc == "" {
		return nil, errUnsupported("Go Fuzz needs a FuzzFunc (the testing.F target name)")
	}
	return nil, errUnsupported("Go native-fuzz crash harvest is target-layout specific (testdata/fuzz/" + g.FuzzFunc + "); wire per-target")
}

var _ Fuzzer = Go{}
