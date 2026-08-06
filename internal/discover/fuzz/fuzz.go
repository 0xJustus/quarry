// Package fuzz runs bounded coverage-guided campaigns; the oracle re-confirms every crash.
package fuzz

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

var defaultHarness = []string{"/harness", "@@"}

// with -M, AFL writes out/<name>/ instead of out/default/
const aflSyncName = "quarry"

const analystDictIn = "/quarry-analyst-dict.txt"

// keeps afl-fuzz from bailing inside a container; unknown vars are ignored
var tuningEnv = []string{
	"AFL_SKIP_CPUFREQ=1",
	"AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1",
	"AFL_NO_AFFINITY=1",
}

// SIGTERM at the budget, never SIGKILL: afl-fuzz flushes stats on exit
const (
	statsFlushGrace = 15 * time.Second
	selfStopGrace   = 60 * time.Second
	stopSlack       = 5 * time.Second
)

func stopContainer(dockerBin, name string) {
	_ = exec.Command(dockerBin, "stop", "-t", strconv.Itoa(int(statsFlushGrace.Seconds())), name).Run()
}

type Campaign struct {
	Image        string
	SeedDir      string
	OutDir       string
	DictPath     string   // dictionary path INSIDE the image
	DictHostFile string   // host dictionary file, mounted in and added with -x
	ForeignDirs  []string // host dirs imported with afl-fuzz -F
	CmplogBin    string   // CMPLOG binary path INSIDE the image
	HarnessArgv  []string // in-container argv with @@ (default /harness @@)
	Duration     time.Duration
	StopOnCrash  bool
	DockerBin    string
	ExtraEnv     []string

	AflBin string // afl-fuzz INSIDE the image (ARVO ships it at /out/afl-fuzz, off PATH)
	// ARVO's target binaries live in /out: AFL output mounted there shadows the harness
	OutMount string
	// classic AFL 2.52b has no -V, so the supervisor bounds the run instead
	NoWallClock bool
	// "" ⇒ classic-vs-AFL++ is inferred from NoWallClock
	Engine Engine
	MOpt   bool
	// AFL++ QEMU mode needs a NATIVE x86-64 host; it breaks under nested emulation
	QEMUMode bool

	Log func(string)
}

// classic AFL 2.52b: no -V, no -c, no -F, no -L
func (c Campaign) classic() bool {
	return c.NoWallClock || c.Engine == EngineClassicAFL
}

type Crash struct {
	Name  string
	Bytes []byte
}

type Result struct {
	Crashes  []Crash
	Execs    int64
	Coverage string // bitmap_cvg as AFL prints it ("12.06%")
	Stats    map[string]string
	OutDir   string
	Command  string
}

func (c Campaign) log(s string) {
	if c.Log != nil {
		c.Log(s)
	}
}

func (c Campaign) Run(ctx context.Context) (Result, error) {
	if c.Image == "" {
		return Result{}, fmt.Errorf("fuzz: Image is required")
	}
	if fi, err := os.Stat(c.SeedDir); err != nil || !fi.IsDir() {
		return Result{}, fmt.Errorf("fuzz: SeedDir %q must be a directory: %v", c.SeedDir, err)
	}
	if empty, err := dirEmpty(c.SeedDir); err != nil || empty {
		return Result{}, fmt.Errorf("fuzz: SeedDir %q has no seed files (a coverage-guided mutator needs a valid seed to mutate, not a blank page)", c.SeedDir)
	}
	if c.OutDir == "" {
		return Result{}, fmt.Errorf("fuzz: OutDir is required")
	}
	if err := os.MkdirAll(c.OutDir, 0o755); err != nil {
		return Result{}, err
	}
	clearPriorRun(c.OutDir)
	dur := c.Duration
	if dur <= 0 {
		dur = 60 * time.Second
	}
	// round, never truncate: -V 0 disables AFL's wall-clock stop and runs unbounded
	vsecs := int(math.Round(dur.Seconds()))
	if vsecs < 1 {
		vsecs = 1
	}
	harness := c.HarnessArgv
	if len(harness) == 0 {
		harness = defaultHarness
	}
	bin := c.DockerBin
	if bin == "" {
		bin = "docker"
	}

	seedAbs, err := filepath.Abs(c.SeedDir)
	if err != nil {
		return Result{}, err
	}
	outAbs, err := filepath.Abs(c.OutDir)
	if err != nil {
		return Result{}, err
	}

	name := fmt.Sprintf("quarry-fuzz-%d-%d", os.Getpid(), time.Now().UnixNano())

	var dictHostAbs string
	if c.DictHostFile != "" {
		dictHostAbs, err = filepath.Abs(c.DictHostFile)
		if err != nil {
			return Result{}, err
		}
	}
	var foreignAbs []string
	for _, fd := range c.ForeignDirs {
		fdAbs, ferr := filepath.Abs(fd)
		if ferr != nil {
			return Result{}, ferr
		}
		foreignAbs = append(foreignAbs, fdAbs)
	}

	args, useWallClock := c.buildArgs(name, seedAbs, outAbs, dictHostAbs, foreignAbs, vsecs, harness)

	// the supervisor stop is a MANDATORY backstop: -V has been seen to overrun its budget
	stopAfter := dur
	if useWallClock {
		stopAfter = dur + selfStopGrace
	}
	// the deadline sits past the stop so the CLI SIGKILL cannot land mid stats-flush
	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(ctx, stopAfter+statsFlushGrace+stopSlack)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, args...)
	res := Result{OutDir: outAbs, Command: bin + " " + strings.Join(args, " ")}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return res, err
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		return res, fmt.Errorf("fuzz: start afl-fuzz (%s): %w", bin, err)
	}
	// CommandContext kills only the docker CLI, orphaning the container: stop it explicitly
	stopped := make(chan struct{})
	defer close(stopped)
	go func() {
		t := time.NewTimer(stopAfter)
		defer t.Stop()
		select {
		case <-t.C:
		case <-ctx.Done():
		case <-stopped:
			return
		}
		stopContainer(bin, name)
	}()
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		c.log(sc.Text())
	}
	// drain: a line the scanner won't tokenize must not back up the pipe and block the child
	_, _ = io.Copy(io.Discard, stdout)
	waitErr := cmd.Wait()

	res.Crashes = harvestCrashes(outAbs)
	res.Stats = parseStats(outAbs)
	if v, ok := res.Stats["execs_done"]; ok {
		res.Execs, _ = strconv.ParseInt(strings.TrimSpace(v), 10, 64)
	}
	if v, ok := res.Stats["bitmap_cvg"]; ok {
		res.Coverage = strings.TrimSpace(v)
	}
	// fail closed: neither crashes nor stats ⇒ it never ran (vault: Fuzzing)
	if waitErr != nil && len(res.Crashes) == 0 && len(res.Stats) == 0 {
		return res, fmt.Errorf("fuzz: afl-fuzz produced no output (%w) — cmd: %s", waitErr, res.Command)
	}
	return res, nil
}

// pure over its inputs; useWallClock=false ⇒ no -V, so the caller must bound the run
func (c Campaign) buildArgs(name, seedAbs, outAbs, dictHostAbs string, foreignAbs []string, vsecs int, harness []string) (args []string, useWallClock bool) {
	aflBin := c.AflBin
	if aflBin == "" {
		aflBin = "afl-fuzz"
	}
	outMount := c.OutMount
	if outMount == "" {
		outMount = "/out"
	}

	// -u host user: root-owned 0600 crash files would harvest as zero findings
	args = []string{"run", "--rm", "--name", name,
		"-u", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
		"-e", "HOME=/tmp",
	}
	// ExtraEnv goes last: docker takes the last -e, so a caller can override the tuning
	for _, e := range tuningEnv {
		args = append(args, "-e", e)
	}
	args = append(args,
		"-v", seedAbs+":/seeds:ro",
		"-v", outAbs+":"+outMount,
	)
	if dictHostAbs != "" {
		args = append(args, "-v", dictHostAbs+":"+analystDictIn+":ro")
	}
	var foreignIn []string
	for i, fdAbs := range foreignAbs {
		in := fmt.Sprintf("/foreign%d", i)
		args = append(args, "-v", fdAbs+":"+in+":ro")
		foreignIn = append(foreignIn, in)
	}
	// a -M main runs the deterministic stage, which starves the corpus on a gated target
	if len(foreignIn) > 0 && !c.classic() {
		args = append(args, "-e", "AFL_DISABLE_DETERMINISTIC=1")
	}
	if c.StopOnCrash {
		args = append(args, "-e", "AFL_BENCH_UNTIL_CRASH=1")
	}
	for _, e := range c.ExtraEnv {
		args = append(args, "-e", e)
	}
	args = append(args, c.Image, aflBin, "-i", "/seeds", "-o", outMount)
	if c.QEMUMode && !c.classic() {
		args = append(args, "-Q")
	}
	if c.DictPath != "" {
		args = append(args, "-x", c.DictPath)
	}
	if dictHostAbs != "" {
		args = append(args, "-x", analystDictIn) // AFL merges multiple -x
	}
	if c.CmplogBin != "" && !c.classic() {
		args = append(args, "-c", c.CmplogBin)
	}
	if c.MOpt && !c.classic() {
		args = append(args, "-L", "0")
	}
	// -F requires -M, and -M moves the output the harvest reads to out/<aflSyncName>/
	if len(foreignIn) > 0 && !c.classic() {
		args = append(args, "-M", aflSyncName)
		for _, in := range foreignIn {
			args = append(args, "-F", in)
		}
	}
	// -m none: ASan's huge virtual-memory reservation trips the AFL memory cap
	args = append(args, "-m", "none")
	if !c.classic() {
		args = append(args, "-V", strconv.Itoa(vsecs))
		useWallClock = true
	}
	args = append(args, "--")
	args = append(args, harness...)
	return args, useWallClock
}

// only these are cleared: callers keep their own files (PoVs, dicts) in OutDir
var flatAFLArtifacts = []string{"crashes", "hangs", "queue", "fuzzer_stats", "plot_data", "fuzz_bitmap", "cmdline"}

// clear EVERY layout the harvest reads: stale output must not read as this run's
func clearPriorRun(outDir string) {
	for _, sub := range []string{"default", aflSyncName} {
		_ = os.RemoveAll(filepath.Join(outDir, sub))
	}
	for _, name := range flatAFLArtifacts {
		_ = os.RemoveAll(filepath.Join(outDir, name))
	}
}

// the layouts a campaign may have written, newest first: -M sync, plain, classic FLAT
func aflArtifactPaths(outDir, name string) []string {
	return []string{
		filepath.Join(outDir, aflSyncName, name),
		filepath.Join(outDir, "default", name),
		filepath.Join(outDir, name),
	}
}

func harvestCrashes(outDir string) []Crash {
	for _, sub := range aflArtifactPaths(outDir, "crashes") {
		ents, err := os.ReadDir(sub)
		if err != nil {
			continue
		}
		var crashes []Crash
		for _, e := range ents {
			if e.IsDir() || !strings.HasPrefix(e.Name(), "id:") {
				continue
			}
			b, err := os.ReadFile(filepath.Join(sub, e.Name()))
			if err != nil {
				continue
			}
			crashes = append(crashes, Crash{Name: e.Name(), Bytes: b})
		}
		if len(crashes) > 0 {
			sort.Slice(crashes, func(i, j int) bool { return crashes[i].Name < crashes[j].Name })
			return crashes
		}
	}
	return nil
}

// AFL's fuzzer_stats: "key : value" lines
func parseStats(outDir string) map[string]string {
	for _, p := range aflArtifactPaths(outDir, "fuzzer_stats") {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		m := map[string]string{}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := sc.Text()
			i := strings.Index(line, ":")
			if i < 0 {
				continue
			}
			m[strings.TrimSpace(line[:i])] = strings.TrimSpace(line[i+1:])
		}
		f.Close()
		if len(m) > 0 {
			return m
		}
	}
	return nil
}

func dirEmpty(dir string) (bool, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return false, err
	}
	for _, e := range ents {
		if !e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
			return false, nil
		}
	}
	return true, nil
}
