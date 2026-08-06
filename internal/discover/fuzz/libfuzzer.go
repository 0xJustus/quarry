package fuzz

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// a NATIVE libFuzzer harness: its own driver is main, no afl-fuzz (see HasAFL)
type LibFuzzerCampaign struct {
	Image     string
	Harness   string // in-container path
	SeedDir   string // mounted read-only; empty ⇒ cold start
	Duration  time.Duration
	MaxLen    int
	DockerBin string
	Log       func(string)

	// mounted WRITABLE (created if absent): libFuzzer persists new-coverage units here
	CorpusDir string
	// extra read-only startup corpora — libFuzzer's analogue of AFL's -F import
	ImportDirs []string
}

type LibFuzzerResult struct {
	Crashes []Crash
	Execs   int64
	Command string
}

func (c LibFuzzerCampaign) log(s string) {
	if c.Log != nil {
		c.Log(s)
	}
}

var libfuzzExecs = regexp.MustCompile(`stat::number_of_executed_units:\s*(\d+)`)

func (c LibFuzzerCampaign) Run(ctx context.Context) (LibFuzzerResult, error) {
	if c.Image == "" || c.Harness == "" {
		return LibFuzzerResult{}, fmt.Errorf("libfuzz: Image and Harness are required")
	}
	bin := c.DockerBin
	if bin == "" {
		bin = "docker"
	}
	dur := c.Duration
	if dur <= 0 {
		dur = 60 * time.Second
	}
	secs := int(dur.Seconds())
	if secs < 1 {
		secs = 1
	}

	outDir, err := os.MkdirTemp("", "quarry-libfuzz-")
	if err != nil {
		return LibFuzzerResult{}, err
	}
	defer os.RemoveAll(outDir)

	var corpusAbs string
	if c.CorpusDir != "" {
		if e := os.MkdirAll(c.CorpusDir, 0o755); e != nil {
			return LibFuzzerResult{}, e
		}
		if corpusAbs, err = filepath.Abs(c.CorpusDir); err != nil {
			return LibFuzzerResult{}, err
		}
	}
	var seedAbs string
	if c.SeedDir != "" {
		if seedAbs, err = filepath.Abs(c.SeedDir); err != nil {
			return LibFuzzerResult{}, err
		}
	}
	var importAbs []string
	for _, d := range c.ImportDirs {
		da, e := filepath.Abs(d)
		if e != nil {
			return LibFuzzerResult{}, e
		}
		importAbs = append(importAbs, da)
	}

	name := fmt.Sprintf("quarry-libfuzz-%d-%d", os.Getpid(), time.Now().UnixNano())
	args := c.buildArgs(name, outDir, corpusAbs, seedAbs, importAbs, secs)

	// backstop for a wedged run; the deadline sits past it so SIGKILL can't cut the stats
	stopAfter := dur + 30*time.Second
	rctx, cancel := context.WithTimeout(ctx, stopAfter+statsFlushGrace+stopSlack)
	defer cancel()
	cmd := exec.CommandContext(rctx, bin, args...)
	res := LibFuzzerResult{Command: bin + " " + strings.Join(args, " ")}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return res, err
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		return res, fmt.Errorf("libfuzz: start (%s): %w", bin, err)
	}
	stopped := make(chan struct{})
	defer close(stopped)
	go func() {
		t := time.NewTimer(stopAfter)
		defer t.Stop()
		select {
		case <-t.C:
		case <-rctx.Done():
		case <-stopped:
			return
		}
		stopContainer(bin, name)
	}()
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		c.log(line)
		if m := libfuzzExecs.FindStringSubmatch(line); m != nil {
			res.Execs, _ = strconv.ParseInt(m[1], 10, 64)
		}
	}
	_, _ = io.Copy(io.Discard, stdout)
	waitErr := cmd.Wait() // a non-zero exit on crash is expected; the artifact is the signal

	if entries, e := os.ReadDir(outDir); e == nil {
		for _, ent := range entries {
			n := ent.Name()
			if strings.HasPrefix(n, "crash-") || strings.HasPrefix(n, "oom-") || strings.HasPrefix(n, "leak-") {
				if b, rerr := os.ReadFile(filepath.Join(outDir, n)); rerr == nil {
					res.Crashes = append(res.Crashes, Crash{Name: n, Bytes: b})
				}
			}
		}
	}
	// fail closed: no crash and no exec count ⇒ it never ran (vault: Fuzzing)
	if waitErr != nil && len(res.Crashes) == 0 && res.Execs == 0 {
		return res, fmt.Errorf("libfuzz: harness produced no crashes and no exec count (%w) — cmd: %s", waitErr, res.Command)
	}
	return res, nil
}

// pure; libFuzzer writes new units to the FIRST corpus dir, so /corpus leads
func (c LibFuzzerCampaign) buildArgs(name, crashesAbs, corpusAbs, seedAbs string, importAbs []string, secs int) []string {
	args := []string{"run", "--rm", "--name", name,
		"-u", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
		"-e", "HOME=/tmp",
		"-v", crashesAbs + ":/crashes",
	}
	var corpora []string
	if corpusAbs != "" {
		args = append(args, "-v", corpusAbs+":/corpus")
		corpora = append(corpora, "/corpus")
	}
	if seedAbs != "" {
		args = append(args, "-v", seedAbs+":/seeds:ro")
		corpora = append(corpora, "/seeds")
	}
	for i, im := range importAbs {
		in := fmt.Sprintf("/import%d", i)
		args = append(args, "-v", im+":"+in+":ro")
		corpora = append(corpora, in)
	}
	args = append(args, c.Image, c.Harness,
		"-max_total_time="+strconv.Itoa(secs),
		"-artifact_prefix=/crashes/",
		"-print_final_stats=1",
		// without -print_coverage the per-function cold-set steer has nothing to consume
		"-print_coverage=1",
	)
	if c.MaxLen > 0 {
		args = append(args, "-max_len="+strconv.Itoa(c.MaxLen))
	}
	args = append(args, corpora...)
	return args
}

// afl-fuzz at /out/afl-fuzz ⇒ drive the harness with Campaign, not LibFuzzerCampaign
func HasAFL(ctx context.Context, dockerBin, image string) bool {
	bin := dockerBin
	if bin == "" {
		bin = "docker"
	}
	out, _ := exec.CommandContext(ctx, bin, "run", "--rm", "--entrypoint", "sh", image,
		"-c", "test -x /out/afl-fuzz && echo yes || echo no").CombinedOutput()
	return strings.Contains(string(out), "yes")
}
