package corpus

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type BuildPairOptions struct {
	Repo        string
	VulnSHA     string
	FixSHA      string
	BuildCmd    string   // MUST produce a binary at /harness
	RunArgv     []string // "{poc}" is the PoV placeholder
	Base        string
	DockerBin   string
	Name        string
	OutDir      string
	HarnessFile string
	HarnessDest string
	TimeoutS    int
}

type BuildPairResult struct {
	VulnImage string
	FixImage  string
	YAMLPath  string
}

func BuildPair(ctx context.Context, o BuildPairOptions) (BuildPairResult, error) {
	if o.Repo == "" || o.VulnSHA == "" || o.FixSHA == "" || o.BuildCmd == "" {
		return BuildPairResult{}, fmt.Errorf("corpus.BuildPair: Repo, VulnSHA, FixSHA, BuildCmd are required")
	}
	base := o.Base
	if base == "" {
		base = "quarry-fuzz:latest"
	}
	docker := o.DockerBin
	if docker == "" {
		docker = "docker"
	}
	name := o.Name
	if name == "" {
		name = "corpus-" + shortSHA8(o.FixSHA)
	}
	argv := o.RunArgv
	if len(argv) == 0 {
		argv = []string{"/harness", "{poc}"}
	}

	build := func(sha, tag string) (string, error) {
		img := tag + ":latest"
		dir, err := os.MkdirTemp("", "corpus-build-*")
		if err != nil {
			return "", err
		}
		defer os.RemoveAll(dir)
		// git archive, not checkout: never mutates the caller's worktree
		tarPath := filepath.Join(dir, "src.tar")
		tf, err := os.Create(tarPath)
		if err != nil {
			return "", err
		}
		arch := exec.CommandContext(ctx, "git", "-C", o.Repo, "archive", "--format=tar", sha)
		arch.Stdout = tf
		if err := arch.Run(); err != nil {
			tf.Close()
			return "", fmt.Errorf("git archive %s: %w", sha, err)
		}
		tf.Close()
		srcDir := filepath.Join(dir, "src")
		if err := os.MkdirAll(srcDir, 0o755); err != nil {
			return "", err
		}
		if out, err := exec.CommandContext(ctx, "tar", "-xf", tarPath, "-C", srcDir).CombinedOutput(); err != nil {
			return "", fmt.Errorf("tar extract %s: %v: %s", sha, err, out)
		}
		if o.HarnessFile != "" {
			dest := o.HarnessDest
			if dest == "" {
				dest = "harness.c"
			}
			hb, herr := os.ReadFile(o.HarnessFile)
			if herr != nil {
				return "", fmt.Errorf("read harness %s: %w", o.HarnessFile, herr)
			}
			if werr := os.WriteFile(filepath.Join(srcDir, dest), hb, 0o644); werr != nil {
				return "", werr
			}
		}
		dockerfile := fmt.Sprintf("FROM %s\nCOPY . /src\nWORKDIR /src\nRUN %s\n", base, o.BuildCmd)
		if err := os.WriteFile(filepath.Join(srcDir, "Dockerfile"), []byte(dockerfile), 0o644); err != nil {
			return "", err
		}
		b := exec.CommandContext(ctx, docker, "build", "--platform", "linux/amd64", "-t", img, srcDir)
		if out, err := b.CombinedOutput(); err != nil {
			return "", fmt.Errorf("build %s did not compile: %s", sha, tailStr(string(out), 25))
		}
		return img, nil
	}

	vulnImg, err := build(o.VulnSHA, name+"-vuln")
	if err != nil {
		return BuildPairResult{}, err
	}
	fixImg, err := build(o.FixSHA, name+"-fix")
	if err != nil {
		return BuildPairResult{}, err
	}

	outDir := o.OutDir
	if outDir == "" {
		outDir, err = os.MkdirTemp("", "corpus-target-*")
		if err != nil {
			return BuildPairResult{}, err
		}
	} else if err := os.MkdirAll(outDir, 0o755); err != nil {
		return BuildPairResult{}, err
	}
	timeoutS := o.TimeoutS
	if timeoutS <= 0 {
		timeoutS = 20
	}
	// emit every value through the YAML marshaler; hand-quoting can ship a descriptor that runs a DIFFERENT command (vault: Corpus and Grading)
	var renderErr error
	keep := func(out string, err error) string {
		if err != nil && renderErr == nil {
			renderErr = err
		}
		return out
	}
	nameY := keep(yamlScalar(name))
	vulnY := keep(yamlScalar(vulnImg))
	fixY := keep(yamlScalar(fixImg))
	argvY := keep(argvYAML(argv))
	if renderErr != nil {
		return BuildPairResult{}, fmt.Errorf("corpus.BuildPair: cannot render descriptor: %w", renderErr)
	}
	doc := fmt.Sprintf(`# Silent-fix reference-diff target (ADR-0008 / Next Builds #4). Vuln build = target; fix build =
# GROUND-TRUTH reference. diverge_on_output confirms a SOUND bug on executed divergence (incl. an
# asymmetric hang: the vuln loops where the fix returns).
# repo=%s vuln=%s fix=%s
target:
  name: %s
  ingest: { kind: image, image: %s }
  fixed:  { kind: image, image: %s }
  run: { argv: %s, timeout_s: %d }
  oracle:
    require: any
    differential: { fixed_image: %s, rule: diverge_on_output }
`, commentSafe(o.Repo), commentSafe(o.VulnSHA), commentSafe(o.FixSHA), nameY, vulnY, fixY, argvY, timeoutS, fixY)
	// self-check: a rendering slip must fail the build, not ship a target that runs something else
	if err := verifyDescriptor(doc, name, vulnImg, fixImg, argv); err != nil {
		return BuildPairResult{}, err
	}
	yamlPath := filepath.Join(outDir, "quarry.yaml")
	if err := os.WriteFile(yamlPath, []byte(doc), 0o644); err != nil {
		return BuildPairResult{}, err
	}
	return BuildPairResult{VulnImage: vulnImg, FixImage: fixImg, YAMLPath: yamlPath}, nil
}

// argv as a single-line YAML flow sequence, each element quoted by the emitter
func argvYAML(argv []string) (string, error) {
	n := &yaml.Node{Kind: yaml.SequenceNode, Style: yaml.FlowStyle}
	for _, a := range argv {
		n.Content = append(n.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: a})
	}
	return marshalInline(n)
}

func yamlScalar(s string) (string, error) {
	return marshalInline(&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: s})
}

// fails unless the node renders on ONE line: it is interpolated into a flow mapping
func marshalInline(n *yaml.Node) (string, error) {
	b, err := yaml.Marshal(n)
	if err != nil {
		return "", err
	}
	out := strings.TrimRight(string(b), "\n")
	if strings.ContainsAny(out, "\n\r") {
		return "", fmt.Errorf("value does not render as a single-line YAML node: %q", out)
	}
	return out, nil
}

// flatten newlines: interpolated into a YAML comment, a newline would inject descriptor keys
func commentSafe(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' {
			return ' '
		}
		return r
	}, s)
}

// fail-closed backstop: reject a descriptor that doesn't declare exactly name/images/argv (vault: Corpus and Grading)
func verifyDescriptor(doc, name, vulnImg, fixImg string, argv []string) error {
	var back struct {
		Target struct {
			Name   string `yaml:"name"`
			Ingest struct {
				Image string `yaml:"image"`
			} `yaml:"ingest"`
			Fixed struct {
				Image string `yaml:"image"`
			} `yaml:"fixed"`
			Run struct {
				Argv []string `yaml:"argv"`
			} `yaml:"run"`
			Oracle struct {
				Differential struct {
					FixedImage string `yaml:"fixed_image"`
				} `yaml:"differential"`
			} `yaml:"oracle"`
		} `yaml:"target"`
	}
	if err := yaml.Unmarshal([]byte(doc), &back); err != nil {
		return fmt.Errorf("corpus.BuildPair: generated descriptor does not parse: %w", err)
	}
	t := back.Target
	for _, c := range []struct{ what, got, want string }{
		{"name", t.Name, name},
		{"ingest.image", t.Ingest.Image, vulnImg},
		{"fixed.image", t.Fixed.Image, fixImg},
		{"differential.fixed_image", t.Oracle.Differential.FixedImage, fixImg},
	} {
		if c.got != c.want {
			return fmt.Errorf("corpus.BuildPair: generated descriptor %s = %q, want %q", c.what, c.got, c.want)
		}
	}
	if len(t.Run.Argv) != len(argv) {
		return fmt.Errorf("corpus.BuildPair: generated descriptor argv has %d element(s), want %d", len(t.Run.Argv), len(argv))
	}
	for i := range argv {
		if t.Run.Argv[i] != argv[i] {
			return fmt.Errorf("corpus.BuildPair: generated descriptor argv[%d] = %q, want %q", i, t.Run.Argv[i], argv[i])
		}
	}
	return nil
}

func shortSHA8(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	return s
}

func tailStr(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
