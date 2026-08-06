package backend

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// unsupportedError is an honest capability boundary, not a failure; callers errors.As it.
type unsupportedError struct{ msg string }

func (e unsupportedError) Error() string { return "backend: unsupported: " + e.msg }
func errUnsupported(msg string) error    { return unsupportedError{msg} }

func IsUnsupported(err error) bool {
	_, ok := err.(unsupportedError)
	return ok
}

func durationSecs(n int) time.Duration {
	if n <= 0 {
		return 60 * time.Second
	}
	return time.Duration(n) * time.Second
}

func signalName(sig int) string {
	switch sig {
	case 11:
		return "SIGSEGV"
	case 6:
		return "SIGABRT"
	case 4:
		return "SIGILL"
	case 8:
		return "SIGFPE"
	case 7:
		return "SIGBUS"
	default:
		return fmt.Sprintf("signal-%d", sig)
	}
}

func dockerBin(bin string) string { return cmp.Or(bin, "docker") }

func truncate(b []byte, n int) string {
	if len(b) > n {
		return string(b[:n]) + "…"
	}
	return string(b)
}

// exit status is ignored: a faulting target exits non-zero and the OUTPUT is what gets classified
func execCombined(ctx context.Context, bin string, args ...string) ([]byte, error) {
	out, err := exec.CommandContext(ctx, bin, args...).CombinedOutput()
	return out, err
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	if s[0] >= 'a' && s[0] <= 'z' {
		return string(s[0]-32) + s[1:]
	}
	return s
}

// detectSource recognizes a target by build-file marker or by source extension.
func detectSource(dir string, markers, exts []string) bool {
	for _, f := range markers {
		if _, err := os.Stat(filepath.Join(dir, f)); err == nil {
			return true
		}
	}
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		n := strings.ToLower(e.Name())
		for _, ext := range exts {
			if strings.HasSuffix(n, ext) {
				return true
			}
		}
	}
	return false
}

func buildDockerfileImage(ctx context.Context, bin, dir, dockerfile string) (string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(abs + "\x00" + dockerfile))
	tag := "quarry-backend-" + hex.EncodeToString(sum[:6])
	dfPath := filepath.Join(abs, "Dockerfile.quarry-backend")
	if err := os.WriteFile(dfPath, []byte(dockerfile), 0o644); err != nil {
		return "", err
	}
	defer os.Remove(dfPath)
	cmd := exec.CommandContext(ctx, dockerBin(bin), "build", "-f", dfPath, "-t", tag, abs)
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("backend: docker build: %w\n%s", err, truncate(out, 600))
	}
	return tag, nil
}

type genFile struct{ name, body string }

// buildWithFiles bakes generated harness files into the target dir for the build, then removes them.
func buildWithFiles(ctx context.Context, bin, dir, dockerfile string, files ...genFile) (string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	for _, g := range files {
		p := filepath.Join(abs, g.name)
		if err := os.WriteFile(p, []byte(g.body), 0o644); err != nil {
			return "", err
		}
		defer os.Remove(p)
	}
	return buildDockerfileImage(ctx, bin, dir, dockerfile)
}

// runPoV mounts pov read-only at /pov and classifies the run output.
func runPoV(ctx context.Context, bin, tmpPrefix, image string, pov []byte, opts, argv []string, classify func(string) Fault) (Fault, error) {
	f, err := os.CreateTemp("", tmpPrefix)
	if err != nil {
		return Fault{}, err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(pov); err != nil {
		return Fault{}, err
	}
	f.Close()
	// --network none: the target is untrusted, it never gets the network
	args := append([]string{"run", "--rm", "--network", "none", "-v", f.Name() + ":/pov:ro"}, opts...)
	args = append(args, image)
	args = append(args, argv...)
	out, _ := execCombined(ctx, dockerBin(bin), args...)
	fault := classify(string(out))
	fault.Output = out
	return fault, nil
}

// fuzzCampaign runs one engine campaign against a host artifact dir and harvests what it wrote there.
func fuzzCampaign(ctx context.Context, bin, tmpPrefix string, budgetSecs int, args func(outDir string, budgetSecs int) []string) ([][]byte, error) {
	out, err := os.MkdirTemp("", tmpPrefix)
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(out)
	if budgetSecs <= 0 {
		budgetSecs = 60
	}
	_, _ = execCombined(ctx, dockerBin(bin), args(out, budgetSecs)...)
	return harvestArtifacts(out)
}

func harvestArtifacts(dir string) ([][]byte, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var crashes [][]byte
	for _, e := range ents {
		n := e.Name()
		if strings.HasPrefix(n, "crash-") || strings.HasPrefix(n, "oom-") || strings.HasPrefix(n, "timeout-") {
			if b, err := os.ReadFile(filepath.Join(dir, n)); err == nil {
				crashes = append(crashes, b)
			}
		}
	}
	return crashes, nil
}

type Capability struct {
	Name        string
	Fuzzer      bool
	Implemented bool
	Fuzzers     string
	Note        string
}

// Implemented must match Verifiers(); a planned row must never be constructible.
var Registry = []Capability{
	{Name: "c", Fuzzer: true, Implemented: true, Fuzzers: "AFL++ (source) / AFL++ QEMU (binary)", Note: "memory-unsafe: rich crash surface; delegates to synth+runner+fuzz"},
	{Name: "go", Fuzzer: true, Implemented: true, Fuzzers: "go test -fuzz (native)", Note: "memory-safe: panics route to semantic-impact"},
	{Name: "python", Fuzzer: true, Implemented: true, Fuzzers: "Atheris (native, arm64-validated)", Note: "coverage-guided discovery + grounding; managed exceptions route to semantic-impact; no Fly"},
	{Name: "java", Fuzzer: true, Implemented: true, Fuzzers: "Jazzer (native, arm64-validated)", Note: "coverage-guided discovery + grounding; JVM exceptions route to semantic-impact; no Fly"},
	{Name: "rust", Fuzzer: true, Implemented: true, Fuzzers: "cargo-fuzz (native, arm64-validated)", Note: "DUAL-GRADER: unsafe-Rust ASan → crash-primitive; safe-Rust panic → semantic-impact; no Fly"},
	{Name: "js", Fuzzer: true, Implemented: true, Fuzzers: "Jazzer.js (native, arm64-validated)", Note: "coverage-guided discovery; JS errors → semantic-impact; needs GLIBC≥2.38 (Ubuntu 24.04 base); no Fly"},
	{Name: "php", Fuzzer: true, Implemented: true, Fuzzers: "php-fuzzer (thin, no value-profile)", Note: "LOW capability: coverage-guided but no cmplog — solves structural triggers, weak on magic bytes"},
}

func Verifiers() map[string]Verifier {
	return map[string]Verifier{
		"c":      C{},
		"go":     Go{},
		"rust":   Rust{},
		"java":   Java{},
		"python": Python{},
		"js":     JS{},
		"php":    PHP{},
	}
}

// order is load-bearing: a mixed repo's compiled core is the fuzz target, not its scripts
func Detect(dir string) Verifier {
	order := []Verifier{C{}, Rust{}, Go{}, Java{}, Python{}, JS{}, PHP{}}
	for _, b := range order {
		if b.Detect(dir) {
			return b
		}
	}
	return nil
}
