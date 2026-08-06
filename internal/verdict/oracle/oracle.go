// Package oracle evaluates a composable Spec against a RunResult.
package oracle

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

type RunResult struct {
	TermSignal int             `json:"term_signal"`
	ExitCode   int             `json:"exit_code"` // meaningful only when TermSignal == 0
	Stdout     string          `json:"stdout"`
	Stderr     string          `json:"stderr"`
	Sanitizer  SanitizerReport `json:"sanitizer"`
	Duration   time.Duration   `json:"duration"`
	TimedOut   bool            `json:"timed_out"`
	OOMKilled  bool            `json:"oom_killed"` // true cgroup OOM kill only; a bare SIGKILL is forgeable

	// reachability attested by an instrumented runner: a LEAD, never a crash
	TaintReached bool   `json:"taint_reached,omitempty"`
	TaintSink    string `json:"taint_sink,omitempty"`
}

type SanitizerReport struct {
	Fired      bool     `json:"fired"`
	Tool       string   `json:"tool"` // asan | ubsan | msan | tsan
	BugClass   string   `json:"bug_class"`
	CrashSite  string   `json:"crash_site"`
	Frames     []string `json:"frames,omitempty"`
	DedupToken string   `json:"dedup_token"`
}

type Spec struct {
	Require      string        `yaml:"require" json:"require"` // "any" | "all"
	Conditions   []Condition   `yaml:"conditions" json:"conditions"`
	Differential *Differential `yaml:"differential,omitempty" json:"differential,omitempty"`
	// staged chain, mutually exclusive with Conditions; judged by EvaluateSequence
	Sequence []Stage `yaml:"sequence,omitempty" json:"sequence,omitempty"`
}

// WantsTaint reports whether any condition (top-level or staged) declares CondTaint.
func (s Spec) WantsTaint() bool {
	for _, c := range s.Conditions {
		if c.Type == CondTaint {
			return true
		}
	}
	for _, st := range s.Sequence {
		for _, c := range st.Conditions {
			if c.Type == CondTaint {
				return true
			}
		}
	}
	return false
}

type Stage struct {
	Name       string      `yaml:"name,omitempty" json:"name,omitempty"`
	Require    string      `yaml:"require,omitempty" json:"require,omitempty"` // "any" | "all"; empty ⇒ "all"
	Conditions []Condition `yaml:"conditions" json:"conditions"`
}

func (st Stage) require() string {
	if st.Require == "" {
		return "all"
	}
	return st.Require
}

type ConditionType string

const (
	CondSignal    ConditionType = "signal"
	CondSanitizer ConditionType = "sanitizer"
	CondOutput    ConditionType = "output"
	CondExit      ConditionType = "exit"
	CondTimeout   ConditionType = "timeout"
	// un-forgeable cgroup OOM kill, not a bare SIGKILL
	CondResource    ConditionType = "resource"
	CondTaint       ConditionType = "taint"
	CondDivergence  ConditionType = "divergence"
	CondScript      ConditionType = "script"
	CondMetamorphic ConditionType = "metamorphic"
)

// Condition is one predicate over a RunResult; only Type-relevant fields are read.
type Condition struct {
	Type ConditionType `yaml:"type" json:"type"`

	Signals []string `yaml:"signals,omitempty" json:"signals,omitempty"`

	Tool      string   `yaml:"tool,omitempty" json:"tool,omitempty"`
	BugClass  []string `yaml:"bug_class,omitempty" json:"bug_class,omitempty"`
	CrashSite string   `yaml:"crash_site,omitempty" json:"crash_site,omitempty"`

	Stream   string    `yaml:"stream,omitempty" json:"stream,omitempty"` // stdout | stderr | any
	Regex    string    `yaml:"regex,omitempty" json:"regex,omitempty"`
	ExitCode *IntMatch `yaml:"exit_code,omitempty" json:"exit_code,omitempty"`

	Sink string `yaml:"sink,omitempty" json:"sink,omitempty"` // empty matches any sink

	Baseline *Baseline `yaml:"baseline,omitempty" json:"baseline,omitempty"`

	Script string `yaml:"script,omitempty" json:"script,omitempty"`

	// the invariant that MUST hold; a finding fires when it is VIOLATED
	Relation string `yaml:"relation,omitempty" json:"relation,omitempty"`
}

// Baseline is the EXPECTED behavior; the condition passes when the run diverges from any set facet.
type Baseline struct {
	Stream   string    `yaml:"stream,omitempty" json:"stream,omitempty"` // stdout | stderr | any
	Equals   *string   `yaml:"equals,omitempty" json:"equals,omitempty"`
	Matches  string    `yaml:"matches,omitempty" json:"matches,omitempty"`
	ExitCode *IntMatch `yaml:"exit_code,omitempty" json:"exit_code,omitempty"`
}

type IntMatch struct {
	Eq *int `yaml:"eq,omitempty" json:"eq,omitempty"`
	Ne *int `yaml:"ne,omitempty" json:"ne,omitempty"`
	Gt *int `yaml:"gt,omitempty" json:"gt,omitempty"`
	Lt *int `yaml:"lt,omitempty" json:"lt,omitempty"`
}

func (m *IntMatch) match(v int) bool {
	if m == nil {
		return true
	}
	if m.Eq != nil && v != *m.Eq {
		return false
	}
	if m.Ne != nil && v == *m.Ne {
		return false
	}
	if m.Gt != nil && v <= *m.Gt {
		return false
	}
	if m.Lt != nil && v >= *m.Lt {
		return false
	}
	return true
}

type DiffRule string

// conditions hold on vuln, not on fixed
const PassOnVulnFailOnFixed DiffRule = "pass_on_vuln_fail_on_fixed"

// a sound bug label only when the reference is GROUND TRUTH (vault: Verdict Core)
const DivergeOnOutput DiffRule = "diverge_on_output"

type Differential struct {
	FixedImage string   `yaml:"fixed_image" json:"fixed_image"`
	Rule       DiffRule `yaml:"rule" json:"rule"`
}

type Verdict struct {
	Pass          bool              `json:"pass"`
	Conditions    []ConditionResult `json:"conditions"`
	Differential  *DiffResult       `json:"differential,omitempty"`
	PartialCredit []string          `json:"partial_credit,omitempty"`
	Stages        []StageResult     `json:"stages,omitempty"` // populated only by EvaluateSequence
}

type ConditionResult struct {
	Type    ConditionType `json:"type"`
	Matched bool          `json:"matched"`
	Detail  string        `json:"detail"`
}

type StageResult struct {
	Name       string            `json:"name,omitempty"`
	Matched    bool              `json:"matched"`
	Conditions []ConditionResult `json:"conditions"`
}

type DiffResult struct {
	Rule           DiffRule `json:"rule"`
	MatchedOnVuln  bool     `json:"matched_on_vuln"`
	MatchedOnFixed bool     `json:"matched_on_fixed"`
	Satisfied      bool     `json:"satisfied"`
	Detail         string   `json:"detail,omitempty"`
}

// Linux numbering is canonical: targets run in Linux containers.
var linuxSignals = map[string]int{
	"SIGHUP": 1, "SIGINT": 2, "SIGQUIT": 3, "SIGILL": 4, "SIGTRAP": 5,
	"SIGABRT": 6, "SIGIOT": 6, "SIGBUS": 7, "SIGFPE": 8, "SIGKILL": 9,
	"SIGSEGV": 11, "SIGPIPE": 13, "SIGALRM": 14, "SIGTERM": 15,
	"HUP": 1, "INT": 2, "QUIT": 3, "ILL": 4, "ABRT": 6, "BUS": 7,
	"FPE": 8, "SEGV": 11, "TERM": 15,
}

func SignalNumber(name string) (int, bool) {
	n, ok := linuxSignals[strings.ToUpper(strings.TrimSpace(name))]
	return n, ok
}

// fault signals only: every other terminating signal is target-controllable
var crashSignals = map[int]bool{4: true, 6: true, 7: true, 8: true, 11: true}

func IsCrashSignal(n int) bool { return crashSignals[n] }

// Incomplete runs are INCONCLUSIVE: never "clean", never "crashed" (vault: Verdict Core).
func Incomplete(r RunResult) (bool, string) {
	switch {
	case r.TimedOut:
		return true, "timed out"
	case r.OOMKilled:
		return true, "was OOM-killed"
	case r.TermSignal != 0 && !IsCrashSignal(r.TermSignal):
		return true, fmt.Sprintf("was killed by signal %d (not a crash signal)", r.TermSignal)
	}
	return false, ""
}

// Observation is the comparable observable set a divergence is decided on.
type Observation struct {
	Completed bool
	Signal    int
	Exit      int
	Stdout    string
}

func Observe(r RunResult) Observation {
	bad, _ := Incomplete(r)
	return Observation{
		Completed: !bad,
		Signal:    r.TermSignal,
		Exit:      r.ExitCode,
		Stdout:    strings.TrimRight(r.Stdout, "\n"),
	}
}

func (o Observation) String() string {
	switch {
	case !o.Completed:
		return "<did not complete>"
	case o.Signal != 0:
		return fmt.Sprintf("signal=%d", o.Signal)
	default:
		return fmt.Sprintf("exit=%d stdout=%q", o.Exit, o.Stdout)
	}
}

func (s Spec) Validate() error {
	if len(s.Sequence) > 0 {
		return s.validateSequence()
	}
	// a pure reference-diff needs no conditions: the divergence IS the check
	if s.Differential != nil && s.Differential.Rule == DivergeOnOutput && len(s.Conditions) == 0 {
		if s.Differential.FixedImage == "" {
			return fmt.Errorf("oracle: diverge_on_output needs a fixed_image (the reference build)")
		}
		return nil
	}
	switch s.Require {
	case "any", "all":
	case "":
		return fmt.Errorf("oracle: require must be set to \"any\" or \"all\"")
	default:
		return fmt.Errorf("oracle: require must be \"any\" or \"all\", got %q", s.Require)
	}
	if len(s.Conditions) == 0 {
		return fmt.Errorf("oracle: at least one condition is required")
	}
	for i, c := range s.Conditions {
		if err := validateCondition(i, c); err != nil {
			return err
		}
	}
	if s.Differential != nil {
		if s.Differential.FixedImage == "" {
			return fmt.Errorf("oracle: differential needs a fixed_image")
		}
		if s.Differential.Rule != PassOnVulnFailOnFixed && s.Differential.Rule != DivergeOnOutput {
			return fmt.Errorf("oracle: differential rule %q not supported", s.Differential.Rule)
		}
	}
	return nil
}

func (s Spec) validateSequence() error {
	if len(s.Conditions) > 0 {
		return fmt.Errorf("oracle: a sequence Spec must not also set top-level conditions")
	}
	if s.Differential != nil {
		return fmt.Errorf("oracle: differential is not supported on a sequence Spec")
	}
	// inert here, but never accept a bogus value: a silent typo hides operator intent
	switch s.Require {
	case "", "any", "all":
	default:
		return fmt.Errorf("oracle: require must be \"any\" or \"all\", got %q (a sequence Spec's stages carry their own require)", s.Require)
	}
	for si, st := range s.Sequence {
		switch st.require() {
		case "any", "all":
		default:
			return fmt.Errorf("oracle: stage %d require must be \"any\" or \"all\", got %q", si, st.Require)
		}
		if len(st.Conditions) == 0 {
			return fmt.Errorf("oracle: stage %d needs at least one condition", si)
		}
		for i, c := range st.Conditions {
			if err := validateCondition(i, c); err != nil {
				return fmt.Errorf("oracle: stage %d: %w", si, err)
			}
		}
	}
	return nil
}

func validateCondition(i int, c Condition) error {
	switch c.Type {
	case CondSignal:
		if len(c.Signals) == 0 {
			return fmt.Errorf("oracle: condition %d (signal) needs at least one signal", i)
		}
		for _, sig := range c.Signals {
			if _, ok := SignalNumber(sig); !ok {
				return fmt.Errorf("oracle: condition %d references unknown signal %q", i, sig)
			}
		}
	case CondSanitizer:
		if c.Tool == "" {
			return fmt.Errorf("oracle: condition %d (sanitizer) needs a tool", i)
		}
	case CondOutput:
		if c.Regex == "" {
			return fmt.Errorf("oracle: condition %d (output) needs a regex", i)
		}
		if _, err := regexp.Compile(c.Regex); err != nil {
			return fmt.Errorf("oracle: condition %d has invalid regex: %w", i, err)
		}
		if !validStream(c.Stream) {
			return fmt.Errorf("oracle: condition %d has unknown stream %q (want stdout|stderr|any)", i, c.Stream)
		}
	case CondExit:
		if c.ExitCode == nil {
			return fmt.Errorf("oracle: condition %d (exit) needs an exit_code matcher", i)
		}
	case CondTimeout, CondResource, CondTaint:
	case CondMetamorphic:
		switch c.Relation {
		case "", "equal":
		default:
			return fmt.Errorf("oracle: condition %d (metamorphic) has unknown relation %q (want equal)", i, c.Relation)
		}
		// one real stream only: the combined stream can forge the second observable
		switch c.Stream {
		case "", "stdout", "stderr":
		default:
			return fmt.Errorf("oracle: condition %d (metamorphic) stream must be stdout or stderr (got %q); the pair must come from a single stream", i, c.Stream)
		}
	case CondDivergence:
		if c.Baseline == nil {
			return fmt.Errorf("oracle: condition %d (divergence) needs a baseline", i)
		}
		b := c.Baseline
		if b.Equals == nil && b.Matches == "" && b.ExitCode == nil {
			return fmt.Errorf("oracle: condition %d (divergence) baseline needs one of equals/matches/exit_code", i)
		}
		if b.Matches != "" {
			if _, err := regexp.Compile(b.Matches); err != nil {
				return fmt.Errorf("oracle: condition %d has invalid baseline regex: %w", i, err)
			}
		}
		if !validStream(b.Stream) {
			return fmt.Errorf("oracle: condition %d has unknown baseline stream %q (want stdout|stderr|any)", i, b.Stream)
		}
		// exact text needs one real stream; the combined stream would diverge on every run
		if b.Equals != nil {
			switch b.Stream {
			case "", "stdout", "stderr":
			default:
				return fmt.Errorf("oracle: condition %d (divergence) baseline stream must be stdout or stderr when equals is set (got %q); the combined stream is a fabricated concatenation", i, b.Stream)
			}
		}
	case CondScript:
		if c.Script == "" {
			return fmt.Errorf("oracle: condition %d (script) needs a script name", i)
		}
	default:
		return fmt.Errorf("oracle: condition %d has unknown type %q", i, c.Type)
	}
	return nil
}

// Evaluate applies the Spec to a RunResult; fixed may be nil.
func (s Spec) Evaluate(primary RunResult, fixed *RunResult) Verdict {
	v := Verdict{}
	// fail closed: a chain must be judged by EvaluateSequence, never by one run
	if len(s.Sequence) > 0 {
		v.Conditions = []ConditionResult{{Matched: false,
			Detail: fmt.Sprintf("spec declares a staged sequence of %d stages; it must be judged with EvaluateSequence over every stage's result, not one run", len(s.Sequence))}}
		v.PartialCredit = partialCredit(primary)
		return v
	}
	matched, results := s.conditionsMatch(primary)
	v.Conditions = results

	if s.Differential == nil {
		v.Pass = matched
		v.PartialCredit = partialCredit(primary)
		return v
	}

	dr := &DiffResult{Rule: s.Differential.Rule, MatchedOnVuln: matched}
	if s.Differential.Rule == DivergeOnOutput {
		// a missing reference run is never a pass
		if fixed != nil {
			diverged, detail := OutputsDiverge(primary, *fixed)
			dr.Satisfied = diverged
			dr.Detail = detail
		} else {
			dr.Detail = "no reference build run; divergence cannot be evaluated"
		}
		// declared conditions are load-bearing: a divergence alone must not confirm
		if len(s.Conditions) > 0 && !matched {
			dr.Satisfied = false
			dr.Detail = fmt.Sprintf("%s; the spec's require:%s conditions did not match the target run", dr.Detail, s.Require)
		}
		v.Differential = dr
		v.Pass = dr.Satisfied
		v.PartialCredit = partialCredit(primary)
		return v
	}
	if fixed != nil {
		matchedFixed, _ := s.conditionsMatch(*fixed)
		dr.MatchedOnFixed = matchedFixed
	}
	// fire on vuln, not on fixed; a missing fixed run is never a pass
	dr.Satisfied = fixed != nil && dr.MatchedOnVuln && !dr.MatchedOnFixed
	v.Differential = dr
	v.Pass = dr.Satisfied
	v.PartialCredit = partialCredit(primary)
	return v
}

// asymmetric: only the TARGET's failure to complete diverges (vault: Verdict Core)
func OutputsDiverge(target, reference RunResult) (bool, string) {
	tBad, tWhy := Incomplete(target)
	rBad, rWhy := Incomplete(reference)
	switch {
	case tBad && rBad:
		return false, fmt.Sprintf("neither run completed (target %s, reference %s); divergence inconclusive", tWhy, rWhy)
	case rBad:
		return false, fmt.Sprintf("the reference run %s, so it shows no correct behavior to diverge from; divergence inconclusive", rWhy)
	case tBad:
		return true, fmt.Sprintf("completion diverges: the target %s where the reference returns", tWhy)
	}
	t, r := Observe(target), Observe(reference)
	if t.Signal != r.Signal {
		return true, fmt.Sprintf("terminating signal differs: target=%d reference=%d", t.Signal, r.Signal)
	}
	if t.Exit != r.Exit {
		return true, fmt.Sprintf("exit code differs: target=%d reference=%d", t.Exit, r.Exit)
	}
	if t.Stdout != r.Stdout {
		return true, fmt.Sprintf("stdout differs (target %dB vs reference %dB)", len(target.Stdout), len(reference.Stdout))
	}
	return false, "target and reference agree (no divergence)"
}

func (s Spec) conditionsMatch(r RunResult) (bool, []ConditionResult) {
	results := make([]ConditionResult, 0, len(s.Conditions))
	// fail closed: zero conditions is zero evidence, never vacuously satisfied
	if len(s.Conditions) == 0 {
		return false, results
	}
	anyMatched, allMatched := false, true
	for _, c := range s.Conditions {
		ok, detail := c.eval(r)
		results = append(results, ConditionResult{Type: c.Type, Matched: ok, Detail: detail})
		if ok {
			anyMatched = true
		} else {
			allMatched = false
		}
	}
	if s.Require == "all" {
		return allMatched, results
	}
	return anyMatched, results
}

func (c Condition) eval(r RunResult) (bool, string) {
	switch c.Type {
	case CondSignal:
		if r.TermSignal == 0 {
			return false, "no terminating signal"
		}
		for _, name := range c.Signals {
			if n, ok := SignalNumber(name); ok && n == r.TermSignal {
				return true, fmt.Sprintf("terminated by %s (%d)", strings.ToUpper(name), n)
			}
		}
		return false, fmt.Sprintf("signal %d not in allowlist", r.TermSignal)

	case CondSanitizer:
		if !r.Sanitizer.Fired {
			return false, "no sanitizer report"
		}
		if !strings.EqualFold(r.Sanitizer.Tool, c.Tool) {
			return false, fmt.Sprintf("sanitizer tool %q != %q", r.Sanitizer.Tool, c.Tool)
		}
		if len(c.BugClass) > 0 && !containsFold(c.BugClass, r.Sanitizer.BugClass) {
			return false, fmt.Sprintf("bug_class %q not in allowlist", r.Sanitizer.BugClass)
		}
		if c.CrashSite != "" && !strings.Contains(r.Sanitizer.CrashSite, c.CrashSite) {
			return false, fmt.Sprintf("crash_site %q does not contain %q", r.Sanitizer.CrashSite, c.CrashSite)
		}
		return true, fmt.Sprintf("%s %s at %s", r.Sanitizer.Tool, r.Sanitizer.BugClass, r.Sanitizer.CrashSite)

	case CondOutput:
		re, err := regexp.Compile(c.Regex)
		if err != nil {
			return false, "invalid regex: " + err.Error()
		}
		hay := c.streamText(r)
		if !re.MatchString(hay) {
			return false, fmt.Sprintf("regex %q did not match %s", c.Regex, c.streamName())
		}
		if c.ExitCode != nil {
			if r.TermSignal != 0 {
				return false, fmt.Sprintf("regex matched but process was killed by signal %d (exit_code not meaningful)", r.TermSignal)
			}
			if !c.ExitCode.match(r.ExitCode) {
				return false, fmt.Sprintf("regex matched but exit_code %d failed matcher", r.ExitCode)
			}
		}
		return true, fmt.Sprintf("regex %q matched %s", c.Regex, c.streamName())

	case CondExit:
		// signal-killed: the exit code is meaningless and must not satisfy an exit oracle
		if r.TermSignal != 0 {
			return false, fmt.Sprintf("process was killed by signal %d; exit code not meaningful", r.TermSignal)
		}
		if c.ExitCode.match(r.ExitCode) {
			return true, fmt.Sprintf("exit_code %d matched", r.ExitCode)
		}
		return false, fmt.Sprintf("exit_code %d did not match", r.ExitCode)

	case CondTimeout:
		if r.TimedOut {
			return true, fmt.Sprintf("timed out after %s (hang / DoS)", r.Duration.Round(time.Millisecond))
		}
		return false, "did not time out"

	case CondResource:
		if r.OOMKilled {
			return true, "kernel OOM-killed (memory-exhaustion DoS)"
		}
		return false, "not OOM-killed"

	case CondTaint:
		if !r.TaintReached {
			return false, "tainted input did not reach a sink"
		}
		if c.Sink != "" && !strings.Contains(r.TaintSink, c.Sink) {
			return false, fmt.Sprintf("taint reached sink %q, not %q", r.TaintSink, c.Sink)
		}
		if r.TaintSink != "" {
			return true, "tainted input reached sink " + r.TaintSink
		}
		return true, "tainted input reached a sink"

	case CondDivergence:
		return c.evalDivergence(r)

	case CondScript:
		return c.evalScript(r)

	case CondMetamorphic:
		return c.evalMetamorphic(r)
	}
	return false, "unknown condition type"
}

// a run that did not complete makes the pair unreadable: inconclusive, never a finding
func (c Condition) evalMetamorphic(r RunResult) (bool, string) {
	if r.TermSignal != 0 || r.TimedOut || r.OOMKilled {
		return false, "run did not complete (crash/timeout/oom); metamorphic relation inconclusive"
	}
	// one real stream only: a stray stderr line must not forge the second observable
	stream := c.Stream
	if stream == "" {
		stream = "stdout"
	}
	var lines []string
	for _, ln := range strings.Split(streamTextOf(r, stream), "\n") {
		if t := strings.TrimSpace(ln); t != "" {
			lines = append(lines, t)
		}
	}
	// exactly two: with extra lines we cannot tell which two are the observables
	if len(lines) != 2 {
		return false, fmt.Sprintf("expected exactly 2 metamorphic observables on %s, got %d; relation inconclusive", stream, len(lines))
	}
	a, b := lines[0], lines[1]
	switch c.Relation {
	case "equal", "":
		if a != b {
			return true, fmt.Sprintf("metamorphic relation violated: observables differ (%q vs %q)", a, b)
		}
		return false, fmt.Sprintf("relation holds: observables equal (%q)", a)
	default:
		return false, "unknown metamorphic relation " + c.Relation
	}
}

func validStream(s string) bool {
	switch s {
	case "", "any", "stdout", "stderr":
		return true
	}
	return false
}

func (c Condition) streamName() string {
	if c.Stream == "" {
		return "any"
	}
	return c.Stream
}

func (c Condition) streamText(r RunResult) string {
	return streamTextOf(r, c.Stream)
}

func streamTextOf(r RunResult, stream string) string {
	switch stream {
	case "stdout":
		return r.Stdout
	case "stderr":
		return r.Stderr
	default:
		return r.Stdout + "\n" + r.Stderr
	}
}

func (c Condition) evalDivergence(r RunResult) (bool, string) {
	b := c.Baseline
	if b == nil {
		return false, "divergence needs a baseline"
	}
	// a supervisor kill is not the program's behavior; a real crash still diverges below
	if bad, why := Incomplete(r); bad {
		return false, fmt.Sprintf("run %s; divergence inconclusive", why)
	}
	if b.Equals != nil {
		// exact text reads one real stream; trailing newlines trimmed as OutputsDiverge does
		stream := b.Stream
		if stream == "" {
			stream = "stdout"
		}
		if strings.TrimRight(streamTextOf(r, stream), "\n") != strings.TrimRight(*b.Equals, "\n") {
			return true, fmt.Sprintf("output diverged from baseline on %s", stream)
		}
	}
	if b.Matches != "" {
		re, err := regexp.Compile(b.Matches)
		if err != nil {
			return false, "invalid baseline regex: " + err.Error()
		}
		// a regex is a search, not an identity test, so the combined stream is safe here
		if !re.MatchString(streamTextOf(r, b.Stream)) {
			return true, fmt.Sprintf("output no longer matches baseline regex %q on %s", b.Matches, baselineStreamName(b.Stream))
		}
	}
	if b.ExitCode != nil {
		if r.TermSignal != 0 {
			return true, fmt.Sprintf("exit diverged: process killed by signal %d, baseline expects a clean exit", r.TermSignal)
		}
		if !b.ExitCode.match(r.ExitCode) {
			return true, fmt.Sprintf("exit code %d diverged from baseline", r.ExitCode)
		}
	}
	return false, "behavior matched the baseline (no divergence)"
}

func baselineStreamName(s string) string {
	if s == "" {
		return "any"
	}
	return s
}

// stage i is judged against results[i]; a missing result fails the chain
func (s Spec) EvaluateSequence(results []RunResult) Verdict {
	v := Verdict{}
	allMatched := len(s.Sequence) > 0
	for i, st := range s.Sequence {
		sr := StageResult{Name: st.Name}
		if i >= len(results) {
			sr.Matched = false
			sr.Conditions = []ConditionResult{{Matched: false, Detail: "no run result for this stage"}}
			allMatched = false
			v.Stages = append(v.Stages, sr)
			continue
		}
		sub := Spec{Require: st.require(), Conditions: st.Conditions}
		matched, cres := sub.conditionsMatch(results[i])
		sr.Matched = matched
		sr.Conditions = cres
		if !matched {
			allMatched = false
		}
		v.Stages = append(v.Stages, sr)
	}
	v.Pass = allMatched
	if len(results) > 0 {
		v.PartialCredit = partialCredit(results[len(results)-1])
	}
	return v
}

// partialCredit surfaces interesting signals even when the oracle did not fire.
func partialCredit(r RunResult) []string {
	var pc []string
	if r.TimedOut {
		pc = append(pc, "timed_out")
	}
	if r.OOMKilled {
		pc = append(pc, "oom_killed")
	}
	if r.TermSignal != 0 {
		pc = append(pc, fmt.Sprintf("terminated_by_signal:%d", r.TermSignal))
	}
	if r.Sanitizer.Fired {
		pc = append(pc, "sanitizer_fired:"+r.Sanitizer.Tool)
	}
	if r.TaintReached {
		if r.TaintSink != "" {
			pc = append(pc, "taint_reached:"+r.TaintSink)
		} else {
			pc = append(pc, "taint_reached")
		}
	}
	return pc
}

func containsFold(hay []string, needle string) bool {
	for _, h := range hay {
		if strings.EqualFold(h, needle) {
			return true
		}
	}
	return false
}
