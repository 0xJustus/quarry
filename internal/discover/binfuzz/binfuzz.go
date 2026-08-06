// Package binfuzz is the AFL++ QEMU-mode crash oracle for uninstrumented binaries.
package binfuzz

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/0xjustus/quarry/internal/platform/fly"
	"github.com/0xjustus/quarry/internal/verdict/oracle"
)

const (
	// deliberately not 0: every accidental exit produces 0
	ExitConfirmed     = 42
	ExitError         = 1
	ExitNoVerdict     = 0 // no verdict line reached — never "clean"
	ExitNoCrash       = 3 // no crash in budget, by a fuzzer that provably ran
	ExitNotReproduced = 4
	ExitInconclusive  = 5
)

// a hang yields no exit status: ExitInconclusive, not "not reproduced"
const confirmTimeoutS = 120

// true wait status: bash's $? collapses signal N into 128+N, python does not
const pyStatus = `import subprocess,sys;print(subprocess.run(sys.argv[1:],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode)`

type Spec struct {
	SourceC   string
	BinaryB64 string            // gzip+base64 of a prebuilt linux/amd64 ELF
	Seeds     map[string][]byte // each must be non-crashing
	Dict      []string
	Argv      []string // "@@" is the input placeholder (default ["./target","@@"])
	BudgetS   int
	QASan     bool
	Cmplog    bool
	// fuzzes ONE function in a loop (vault: Execution Substrate)
	PersistentAddr string
}

func (s Spec) argv() []string {
	if len(s.Argv) == 0 {
		return []string{"./target", "@@"}
	}
	return s.Argv
}

func (s Spec) budget() int {
	if s.BudgetS <= 0 {
		return 120
	}
	return s.BudgetS
}

// Script renders the self-contained bash oneshot. Pure over Spec.
func (s Spec) Script() (string, error) {
	if s.SourceC == "" && s.BinaryB64 == "" {
		return "", fmt.Errorf("binfuzz: Spec needs SourceC or BinaryB64")
	}
	if s.SourceC != "" && s.BinaryB64 != "" {
		return "", fmt.Errorf("binfuzz: Spec has both SourceC and BinaryB64 (pick one)")
	}
	if len(s.Seeds) == 0 {
		return "", fmt.Errorf("binfuzz: Spec needs at least one seed (a coverage-guided mutator needs a valid seed)")
	}
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format, a...); b.WriteByte('\n') }

	w("#!/bin/bash")
	w("set -e; cd /tmp")
	w(`echo "HOST_ARCH=$(uname -m)  (expect x86_64 = native; QEMU mode is unusable under nested emulation)"`)
	// refuse to fuzz rather than reach a confirm we cannot make sound
	w(`command -v python3 >/dev/null || { echo "BINFUZZ_RESULT=INCONCLUSIVE_NO_PYTHON3 (cannot tell a fatal signal from a voluntary exit(128+N) without it)"; exit %d; }`, ExitInconclusive)

	if s.SourceC != "" {
		w("base64 -d > t.c <<'B64EOF'\n%s\nB64EOF", b64(s.SourceC))
		w("gcc -O2 -o target t.c && strip target")
	} else {
		w("base64 -d <<'B64EOF' | gunzip > target\n%s\nB64EOF", s.BinaryB64)
		w("chmod +x target")
	}
	w(`echo "BINFUZZ_TARGET: $(file target | cut -d, -f1-3); symbols: $(nm target 2>&1 | head -1)"`)

	// sorted for a deterministic script; a sanitize() collision must not drop a seed
	w("mkdir -p seeds")
	names := make([]string, 0, len(s.Seeds))
	for name := range s.Seeds {
		names = append(names, name)
	}
	sort.Strings(names)
	taken := map[string]bool{}
	for _, name := range names {
		fn := sanitize(name)
		for i := 2; taken[fn]; i++ {
			fn = fmt.Sprintf("%s-%d", sanitize(name), i)
		}
		taken[fn] = true
		w("base64 -d > %s <<'B64EOF'\n%s\nB64EOF", shQuote("seeds/"+fn), b64(string(s.Seeds[name])))
	}
	dictFlag := ""
	if len(s.Dict) > 0 {
		w("base64 -d > d.dict <<'B64EOF'\n%s\nB64EOF", b64(strings.Join(s.Dict, "\n")+"\n"))
		dictFlag = " -x d.dict"
	}

	qasanEnv := ""
	mode := "QEMU"
	if s.QASan {
		qasanEnv = "AFL_USE_QASAN=1 "
		mode = "QEMU+QASan"
	}
	w("export AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_NO_AFFINITY=1 AFL_BENCH_UNTIL_CRASH=1")
	if s.QASan {
		w("export AFL_USE_QASAN=1") // exported, not inline: it must reach afl-fuzz
	}
	if s.PersistentAddr != "" {
		w("export AFL_QEMU_PERSISTENT_ADDR=%s AFL_QEMU_PERSISTENT_GPR=1", s.PersistentAddr)
	}
	w(`echo "== AFL++ %s-mode fuzz of the UNINSTRUMENTED binary (no source, no instrumentation) =="`, mode)
	fuzzArgv := strings.Join(quoteAll(s.argv()), " ")
	cmplogFlag := ""
	if s.Cmplog {
		cmplogFlag = " -c 0" // QEMU CMPLOG/RedQueen
	}
	// no assignment may precede `timeout`; </dev/null keeps the target off the script's fd 0
	w("timeout %d afl-fuzz -Q%s -i seeds -o out%s -V %d -- %s </dev/null >/tmp/afl.log 2>&1 || true",
		s.budget()+45, cmplogFlag, dictFlag, s.budget(), fuzzArgv)
	w(`echo "--- afl-fuzz tail ---"; tail -6 /tmp/afl.log; echo "--- end ---"`)
	// "did not fuzz" is its own state: an aborted session leaves the same empty out/
	w(`stats=$(find out -name fuzzer_stats 2>/dev/null | head -1)`)
	w(`if [ -z "$stats" ]; then echo "BINFUZZ_RESULT=FUZZER_DID_NOT_RUN (no fuzzer_stats: afl-fuzz never started a session)"; exit %d; fi`, ExitError)
	w(`execs=$(awk -F: '/^execs_done/{gsub(/[^0-9]/,"",$2); print $2; exit}' "$stats")`)
	w(`case "$execs" in ''|*[!0-9]*) echo "BINFUZZ_RESULT=FUZZER_DID_NOT_RUN (fuzzer_stats carries no execs_done)"; exit %d;; esac`, ExitError)
	w(`if [ "$execs" -le 0 ]; then echo "BINFUZZ_RESULT=FUZZER_DID_NOT_RUN execs_done=0 (session started, executed no input)"; exit %d; fi`, ExitError)
	w(`echo "BINFUZZ_EXECS=$execs"`)
	w(`crash=$(find out -path '*crashes*' -name 'id:*' 2>/dev/null | head -1)`)
	w(`if [ -z "$crash" ]; then echo "BINFUZZ_RESULT=NO_CRASH_FOUND execs=$execs"; exit %d; fi`, ExitNoCrash)
	w(`echo "BINFUZZ_CRASH_INPUT=$crash"`)
	// under QASan the fault is the sanitizer's abort, so the confirm re-runs under QEMU
	confirmArgv := strings.Join(quoteAll(replacePoc(s.argv(), `$crash`)), " ")
	if s.QASan {
		confirmArgv = "afl-qemu-trace " + confirmArgv
	}
	// qasanEnv stays a shell assignment PREFIX, so it precedes `timeout`
	w(`set +e; rc=$(%stimeout -s KILL %d python3 -c %s %s); set -e`,
		qasanEnv, confirmTimeoutS, shQuote(pyStatus), confirmArgv)
	w(`echo "BINFUZZ_CONFIRM_STATUS=${rc:-<none>}  (negative = died on that signal; positive = exited voluntarily)"`)
	// no status at all: nothing measured, nothing claimed
	w(`case "$rc" in ''|*[!0-9-]*) echo "BINFUZZ_RESULT=INCONCLUSIVE_CONFIRM_NO_STATUS rc=${rc:-<none>} (hang/timeout or harness error on the re-run)"; exit %d;; esac`, ExitInconclusive)
	w(`sig=0; case "$rc" in -*) sig=${rc#-};; esac`)
	w(`case "$sig" in %s) echo "BINFUZZ_RESULT=CONFIRMED_CRASH signal=$sig"; exit %d;; esac`, crashSignalAlts(), ExitConfirmed)
	w(`echo "BINFUZZ_RESULT=CRASH_NOT_REPRODUCED status=$rc (not a crash-fault signal: only %s attest a crash; a kill or a voluntary exit does not)"; exit %d`, crashSignalAlts(), ExitNotReproduced)
	return b.String(), nil
}

// ask oracle.IsCrashSignal instead of restating the numbers: no drift
func crashSignalAlts() string {
	var alts []string
	for n := 1; n <= 64; n++ {
		if oracle.IsCrashSignal(n) {
			alts = append(alts, strconv.Itoa(n))
		}
	}
	return strings.Join(alts, "|")
}

// RunOnFly runs the oneshot on a native x86-64 Fly Machine and returns the Verdict code.
func RunOnFly(ctx context.Context, cl fly.Client, image string, guest fly.Guest, spec Spec, wait time.Duration) (int, fly.Machine, error) {
	script, err := spec.Script()
	if err != nil {
		return ExitError, fly.Machine{}, err
	}
	if image == "" {
		image = "aflplusplus/aflplusplus:latest"
	}
	// gzip: a raw script with an embedded binary exceeds Fly's init-cmd size limit
	enc := GzB64([]byte(script))
	cfg := fly.MachineConfig{
		Image: image,
		Guest: guest,
		Init: &fly.Init{
			Entrypoint: []string{"/bin/bash"},
			// run from a FILE, not a pipe: a pipe leaves the script on fd 0 and hides truncation
			Cmd: []string{"-c", "set -o pipefail; echo " + enc +
				" | base64 -d | gunzip > /tmp/binfuzz.sh && exec bash /tmp/binfuzz.sh </dev/null"},
		},
	}
	return cl.RunOneshot(ctx, cfg, wait)
}

func VerdictString(code int) string {
	switch code {
	case ExitConfirmed:
		return "CONFIRMED — crash found in the stripped binary and reproduced an un-forgeable crash-fault"
	case ExitNoVerdict:
		return "INCONCLUSIVE — the oneshot exited 0 without reaching a verdict line (truncated/partial init script, or the target consumed the script on stdin); NOT a crash and NOT a clean budget"
	case ExitInconclusive:
		return "INCONCLUSIVE — a crash was found but the confirm re-run produced no exit status (hang/timeout or a missing python3); nothing measured, nothing claimed"
	case ExitNoCrash:
		return "NO CRASH — no crashing input found within the budget by a fuzzer that provably ran (recall, not soundness)"
	case ExitNotReproduced:
		return "NOT REPRODUCED — a saved crash did not re-fault with a crash-class signal on re-run (rejected)"
	default:
		return fmt.Sprintf("ERROR — oneshot failed (exit %d: build/setup/run error)", code)
	}
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func GzB64(raw []byte) string {
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	_, _ = zw.Write(raw)
	_ = zw.Close()
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

func replacePoc(argv []string, repl string) []string {
	out := make([]string, len(argv))
	for i, a := range argv {
		if a == "@@" {
			out[i] = repl
		} else {
			out[i] = a
		}
	}
	return out
}

func quoteAll(argv []string) []string {
	out := make([]string, len(argv))
	for i, a := range argv {
		switch {
		case a == "@@":
			out[i] = "@@"
		case a == "$crash":
			out[i] = `"$crash"`
		default:
			out[i] = shQuote(a)
		}
	}
	return out
}

// shell quoting, not Go's %q (which leaves `$(id)` live)
func shQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// safe basename: seed names are attacker-influenced and interpolated into a root script
func sanitize(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := strings.TrimLeft(b.String(), "-.")
	if out == "" {
		return "seed"
	}
	return out
}
