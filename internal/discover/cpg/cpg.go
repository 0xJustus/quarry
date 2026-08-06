// Package cpg answers reachability and data-flow questions over a Joern CPG.
package cpg

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

const (
	reachDepth = 30
	authzDepth = 20
)

// every repeat() must dedup: a call-graph cycle OOMs the JVM (vault: Code Property Graph)
func closureBehaviour(depth int) string {
	return `(_.emit.dedup.maxDepth(` + strconv.Itoa(depth) + `))`
}

// required on any template printing raw .code: a newline breaks the RESULT framing
const flattenNL = `.replace("\n", " ")`

// guards every value interpolated into a template: names only, never CPGQL
var identRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func validIdent(s string) bool { return identRe.MatchString(s) }

type GenSpec struct {
	Src string
	Out string
	// mandatory for a complete graph: c2cpg silently drops #ifdef'd code without them
	Defines       []string
	Includes      []string
	JoernParseBin string
	// content-hash cache of built graphs; empty disables caching
	CacheDir string
}

type GenResult struct {
	CpgPath  string
	Methods  int
	Calls    int
	Cached   bool
	CacheKey string
}

func Generate(ctx context.Context, spec GenSpec) (GenResult, error) {
	if strings.TrimSpace(spec.Src) == "" || strings.TrimSpace(spec.Out) == "" {
		return GenResult{}, fmt.Errorf("cpg.Generate: Src and Out are required")
	}
	var key string
	if strings.TrimSpace(spec.CacheDir) != "" {
		// any cache failure degrades to a fresh build, never fatal
		if k, err := CacheKey(spec); err == nil {
			key = k
			cached := filepath.Join(spec.CacheDir, key+".cpg.bin")
			if fi, err := os.Stat(cached); err == nil && fi.Size() > 0 {
				if err := copyFile(cached, spec.Out); err == nil {
					res := GenResult{CpgPath: spec.Out, Cached: true, CacheKey: key}
					probeSize(ctx, &res, spec.Out)
					return res, nil
				}
			}
		}
	}
	bin := resolveBin(spec.JoernParseBin, "joern-parse")
	args := []string{spec.Src, "--output", spec.Out}
	if len(spec.Defines) > 0 || len(spec.Includes) > 0 {
		// frontend args must ride after the separator, verbatim to c2cpg
		args = append(args, "--frontend-args")
		for _, d := range spec.Defines {
			args = append(args, "--define", d)
		}
		for _, inc := range spec.Includes {
			args = append(args, "--include", inc)
		}
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	if wd, werr := os.MkdirTemp("", "quarry-joern-wd-*"); werr == nil {
		defer os.RemoveAll(wd)
		cmd.Dir = wd // joern writes ./workspace/ scratch into CWD
	}
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	if err := cmd.Run(); err != nil {
		return GenResult{}, fmt.Errorf("cpg.Generate: joern-parse failed: %w\n%s", err, tail(buf.String(), 800))
	}
	if _, err := os.Stat(spec.Out); err != nil {
		return GenResult{}, fmt.Errorf("cpg.Generate: no cpg written at %s: %w", spec.Out, err)
	}
	res := GenResult{CpgPath: spec.Out, CacheKey: key}
	probeSize(ctx, &res, spec.Out)
	if key != "" {
		if err := os.MkdirAll(spec.CacheDir, 0o755); err == nil {
			_ = copyFile(spec.Out, filepath.Join(spec.CacheDir, key+".cpg.bin"))
		}
	}
	return res, nil
}

func probeSize(ctx context.Context, res *GenResult, cpgPath string) {
	c := New(cpgPath)
	if c == nil {
		return
	}
	if out, err := c.Run(ctx, `println("RESULT methods=" + cpg.method.size)`+"\n"+`println("RESULT calls=" + cpg.call.size)`); err == nil {
		if m, err := requireResults(out, "methods", "calls"); err == nil {
			res.Methods = atoi(m["methods"])
			res.Calls = atoi(m["calls"])
		}
	}
}

// content identity of a build: flag order must not change it, any source byte must
func CacheKey(spec GenSpec) (string, error) {
	srcHash, err := sourceHash(spec.Src)
	if err != nil {
		return "", err
	}
	defs := append([]string(nil), spec.Defines...)
	incs := append([]string(nil), spec.Includes...)
	sort.Strings(defs)
	sort.Strings(incs)
	h := sha256.New()
	io.WriteString(h, "quarry/cpg/cache/v1\n")
	io.WriteString(h, "src="+srcHash+"\n")
	io.WriteString(h, "defines="+strings.Join(defs, "\x00")+"\n")
	io.WriteString(h, "includes="+strings.Join(incs, "\x00")+"\n")
	return hex.EncodeToString(h.Sum(nil)), nil
}

func sourceHash(src string) (string, error) {
	fi, err := os.Stat(src)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	if !fi.IsDir() {
		f, err := os.Open(src)
		if err != nil {
			return "", err
		}
		defer f.Close()
		io.WriteString(h, filepath.Base(src)+"\x00")
		if _, err := io.Copy(h, f); err != nil {
			return "", err
		}
		return hex.EncodeToString(h.Sum(nil)), nil
	}
	var files []string
	err = filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	sort.Strings(files) // digest must not depend on directory-iteration order
	for _, p := range files {
		rel, err := filepath.Rel(src, p)
		if err != nil {
			rel = p
		}
		io.WriteString(h, filepath.ToSlash(rel)+"\x00")
		f, err := os.Open(p)
		if err != nil {
			return "", err
		}
		if _, err := io.Copy(h, f); err != nil {
			f.Close()
			return "", err
		}
		f.Close()
		io.WriteString(h, "\x00")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func copyFile(src, dst string) error {
	if src == dst {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dst)
}

// Client queries a built CPG, one JVM per call unless Open attaches a warm session.
type Client struct {
	CpgPath  string
	JoernBin string

	mu   sync.Mutex // guards sess: Run retires a dead session while others query
	sess *Session

	// prior art by node name; caller-populated (never imports loop/commons)
	NodeAnnotations map[string][]PriorArtTag
}

type PriorArtTag struct {
	BugClass string
	Abstract string
}

func (c *Client) Annotate(names ...string) []PriorArtTag {
	if len(c.NodeAnnotations) == 0 {
		return nil
	}
	var out []PriorArtTag
	seen := map[string]bool{}
	for _, n := range names {
		for _, t := range c.NodeAnnotations[n] {
			k := t.BugClass + "\x00" + t.Abstract
			if !seen[k] {
				seen[k] = true
				out = append(out, t)
			}
		}
	}
	return out
}

func New(cpgPath string) *Client { return &Client{CpgPath: cpgPath} }

// Open attaches a warm Joern REPL with the CPG pre-loaded. Idempotent.
func (c *Client) Open(ctx context.Context) error {
	if c.session() != nil {
		return nil
	}
	s, err := StartSession(ctx, c.CpgPath, c.JoernBin)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sess != nil { // lost a race: keep the attached session, drop ours
		_ = s.Close()
		return nil
	}
	c.sess = s
	return nil
}

func (c *Client) Close() error {
	c.mu.Lock()
	s := c.sess
	c.sess = nil
	c.mu.Unlock()
	if s != nil {
		return s.Close()
	}
	return nil
}

func (c *Client) session() *Session {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sess
}

func (c *Client) retire(s *Session) {
	c.mu.Lock()
	if c.sess == s { // only detach s, so a concurrent Open/Close is not clobbered
		c.sess = nil
	}
	c.mu.Unlock()
	_ = s.Close()
}

// Run's body is trusted glue text: never interpolate an unvalidated name
func (c *Client) Run(ctx context.Context, body string) (string, error) {
	if s := c.session(); s != nil {
		out, err := s.Query(ctx, body)
		if err == nil {
			return out, nil
		}
		// Session.query killed the REPL, so retire it and let later queries go one-shot
		c.retire(s)
		if !errors.Is(err, errSessionDead) || ctx.Err() != nil {
			// this call killed the session: report honestly, never pay the cost twice
			return out, fmt.Errorf("cpg: warm session retired, later queries fall back to shell-per-query: %w", err)
		}
	}
	f, err := os.CreateTemp("", "quarry-cpg-*.sc")
	if err != nil {
		return "", err
	}
	defer os.Remove(f.Name())
	script := "importCpg(\"" + escapeScala(c.CpgPath) + "\")\n" + body + "\n"
	if _, err := f.WriteString(script); err != nil {
		f.Close()
		return "", err
	}
	f.Close()
	cmd := exec.CommandContext(ctx, resolveBin(c.JoernBin, "joern"), "--script", f.Name())
	if wd, werr := os.MkdirTemp("", "quarry-joern-wd-*"); werr == nil {
		defer os.RemoveAll(wd)
		cmd.Dir = wd // joern writes ./workspace/ scratch into CWD
	}
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	err = cmd.Run()
	out := buf.String()
	if err != nil {
		return out, fmt.Errorf("cpg: joern query failed: %w\n%s", err, tail(out, 600))
	}
	return out, nil
}

func tmplCallers(fn string) string {
	return `println("RESULT callers=" + cpg.method.name("` + fn + `").caller.name.dedup.sorted.l.mkString("|"))`
}

func tmplCallees(fn string) string {
	return `println("RESULT callees=" + cpg.method.name("` + fn + `").callee.name.dedup.sorted.l.mkString("|"))`
}

func tmplReaches(from, to string, depth int) string {
	return `val up = cpg.method.name("` + to + `").repeat(_.caller)` + closureBehaviour(depth) + `.name.dedup.toSet` + "\n" +
		`println("RESULT reaches=" + up.contains("` + from + `"))` + "\n" +
		`println("RESULT transitive_callers=" + up.size)`
}

func tmplTaintFlows(source, sink string) string {
	return `val flows = cpg.method.name("` + sink + `").parameter.reachableByFlows(cpg.method.name("` + source + `").parameter).l` + "\n" +
		`println("RESULT flow_count=" + flows.size)` + "\n" +
		`flows.take(3).zipWithIndex.foreach { case (f,i) => println("RESULT flow_" + i + "=" + f.elements.code.l.map(_` + flattenNL + `).mkString(" ~> ")) }`
}

func tmplBoundsChecks(fn string) string {
	return `println("RESULT bounds_checks=" + cpg.method.name("` + fn + `").ast.isCall.name("<operator>.(lessThan|greaterThan|lessEqualsThan|greaterEqualsThan|equals|notEquals)").code.dedup.l.take(40).map(_` + flattenNL + `).mkString("|"))`
}

// two questions: does entry reach sink, and does it reach it bypassing authGate
func tmplMissingAuthz(entry, sink, authGate string) string {
	b := closureBehaviour(authzDepth)
	return `val fromEntry = cpg.method.name("` + entry + `").repeat(_.callee)` + b + `.name.dedup.l` + "\n" +
		`val noAuth = cpg.method.name("` + entry + `").repeat(_.callee.nameNot("` + authGate + `"))` + b + `.name.dedup.l` + "\n" +
		`println("RESULT reaches_sink=" + fromEntry.contains("` + sink + `"))` + "\n" +
		`println("RESULT unauthed_path=" + noAuth.contains("` + sink + `"))` + "\n" +
		`println("RESULT auth_present=" + fromEntry.contains("` + authGate + `"))`
}

// backward DDG closure from the fn's dangerous ops, NOT from its parameters
func tmplSlice(fn string) string {
	alt := strings.Join(sinkNames, "|")
	return `val idxW = cpg.method.name("` + fn + `").call.nameExact("<operator>.assignment").where(_.argument(1).isCall.name(".*ndexAccess.*"))` + "\n" +
		`val sinkC = cpg.method.name("` + fn + `").call.name("(` + alt + `)")` + "\n" +
		`val slice = (idxW.l ++ sinkC.l).iterator.repeat(_.ddgIn)(_.emit.maxDepth(15)).code.dedup.l.take(40)` + "\n" +
		`println("RESULT slice_count=" + slice.size)` + "\n" +
		`slice.zipWithIndex.foreach { case (s,i) => println("RESULT slice_" + i + "=" + s` + flattenNL + `) }`
}

// keep in sync with loop's static sink table
var sinkNames = []string{
	"strcpy", "strcat", "stpcpy", "wcscpy", "wcscat", "vsprintf", "sprintf", "gets", "alloca",
	"system", "popen", "execve", "execvp", "execlp", "execl", "execv",
	"memcpy", "memmove", "memset", "bcopy", "strncpy", "strncat", "vsnprintf", "snprintf",
	"malloc", "realloc", "calloc",
}

type SinkSite struct {
	Callee string
	Func   string
	Line   int
	Prior  []PriorArtTag // empty means "no known match", never "safe"
}

func tmplSinks() string {
	alt := strings.Join(sinkNames, "|")
	return `val ss = cpg.call.name("(` + alt + `)").map(c => c.name + "@" + c.method.name + ":" + c.lineNumber.getOrElse(-1).toString).dedup.l` + "\n" +
		`println("RESULT sink_count=" + ss.size)` + "\n" +
		`println("RESULT sinks=" + ss.take(400).mkString("|"))`
}

func (c *Client) Sinks(ctx context.Context) ([]SinkSite, error) {
	out, err := c.Run(ctx, tmplSinks())
	if err != nil {
		return nil, err
	}
	m, err := requireResults(out, "sink_count", "sinks")
	if err != nil {
		return nil, err
	}
	var sites []SinkSite
	for _, tok := range splitList(m["sinks"]) {
		s := parseSinkTok(tok)
		s.Prior = c.Annotate(s.Callee, s.Func)
		sites = append(sites, s)
	}
	return sites, nil
}

// parseSinkTok splits "callee@func:line".
func parseSinkTok(tok string) SinkSite {
	at := strings.LastIndex(tok, "@")
	if at < 0 {
		return SinkSite{Callee: tok}
	}
	s := SinkSite{Callee: tok[:at]}
	rest := tok[at+1:]
	if colon := strings.LastIndex(rest, ":"); colon >= 0 {
		s.Func, s.Line = rest[:colon], atoi(rest[colon+1:])
	} else {
		s.Func = rest
	}
	return s
}

func (c *Client) Callers(ctx context.Context, fn string) ([]string, error) {
	return c.namesQuery(ctx, fn, tmplCallers(fn), "callers")
}

func (c *Client) Callees(ctx context.Context, fn string) ([]string, error) {
	return c.namesQuery(ctx, fn, tmplCallees(fn), "callees")
}

func (c *Client) Reaches(ctx context.Context, from, to string) (reaches bool, transitiveCallers int, err error) {
	if !validIdent(from) || !validIdent(to) {
		return false, 0, fmt.Errorf("cpg.Reaches: from/to must be identifiers")
	}
	out, err := c.Run(ctx, tmplReaches(from, to, reachDepth))
	if err != nil {
		return false, 0, err
	}
	m, err := requireResults(out, "reaches", "transitive_callers")
	if err != nil {
		return false, 0, err
	}
	return m["reaches"] == "true", atoi(m["transitive_callers"]), nil
}

func (c *Client) TaintFlows(ctx context.Context, source, sink string) (count int, paths []string, err error) {
	if !validIdent(source) || !validIdent(sink) {
		return 0, nil, fmt.Errorf("cpg.TaintFlows: source/sink must be identifiers")
	}
	out, err := c.Run(ctx, tmplTaintFlows(source, sink))
	if err != nil {
		return 0, nil, err
	}
	m, err := requireResults(out, "flow_count")
	if err != nil {
		return 0, nil, err
	}
	count = atoi(m["flow_count"])
	for i := 0; i < 3; i++ {
		if p, ok := m["flow_"+strconv.Itoa(i)]; ok && p != "" {
			paths = append(paths, p)
		}
	}
	return count, paths, nil
}

func (c *Client) BoundsChecks(ctx context.Context, fn string) ([]string, error) {
	return c.namesQuery(ctx, fn, tmplBoundsChecks(fn), "bounds_checks")
}

type AuthzResult struct {
	ReachesSink  bool
	UnauthedPath bool
	AuthPresent  bool
}

func (a AuthzResult) Missing() bool { return a.ReachesSink && a.UnauthedPath }

func (c *Client) MissingAuthz(ctx context.Context, entry, sink, authGate string) (AuthzResult, error) {
	if !validIdent(entry) || !validIdent(sink) || !validIdent(authGate) {
		return AuthzResult{}, fmt.Errorf("cpg.MissingAuthz: entry/sink/authGate must be identifiers")
	}
	out, err := c.Run(ctx, tmplMissingAuthz(entry, sink, authGate))
	if err != nil {
		return AuthzResult{}, err
	}
	m, err := requireResults(out, "reaches_sink", "unauthed_path", "auth_present")
	if err != nil {
		return AuthzResult{}, err
	}
	return AuthzResult{
		ReachesSink:  m["reaches_sink"] == "true",
		UnauthedPath: m["unauthed_path"] == "true",
		AuthPresent:  m["auth_present"] == "true",
	}, nil
}

// Slice returns the backward program slice for fn, one statement per line.
func (c *Client) Slice(ctx context.Context, fn string) (string, error) {
	if !validIdent(fn) {
		return "", fmt.Errorf("cpg.Slice: %q is not a valid function identifier", fn)
	}
	out, err := c.Run(ctx, tmplSlice(fn))
	if err != nil {
		return "", err
	}
	m, err := requireResults(out, "slice_count")
	if err != nil {
		return "", err
	}
	var lines []string
	// each statement may contain '|': collect whole, never splitList
	for i := 0; i < atoi(m["slice_count"]); i++ {
		if s, ok := m["slice_"+strconv.Itoa(i)]; ok && strings.TrimSpace(s) != "" {
			lines = append(lines, s)
		}
	}
	return strings.Join(lines, "\n"), nil
}

func (c *Client) namesQuery(ctx context.Context, fn, body, key string) ([]string, error) {
	if !validIdent(fn) {
		return nil, fmt.Errorf("cpg: %q is not a valid function identifier", fn)
	}
	out, err := c.Run(ctx, body)
	if err != nil {
		return nil, err
	}
	m, err := requireResults(out, key)
	if err != nil {
		return nil, err
	}
	return splitList(m[key]), nil
}

// fail closed: a missing key is "did not answer", never an empty answer
func requireResults(out string, keys ...string) (map[string]string, error) {
	m := parseResults(out)
	var missing []string
	for _, k := range keys {
		if _, ok := m[k]; !ok {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("cpg: query did not answer (no RESULT %s line; the CPG may not be loaded or the query errored):\n%s",
			strings.Join(missing, "/"), tail(strings.TrimSpace(out), 400))
	}
	return m, nil
}

// substring match tolerates the REPL's "joern> " prompt prefix
func parseResults(out string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		i := strings.Index(line, "RESULT ")
		if i < 0 {
			continue
		}
		if k, v, ok := strings.Cut(line[i+len("RESULT "):], "="); ok {
			m[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return m
}

func splitList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, "|") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func atoi(s string) int { n, _ := strconv.Atoi(strings.TrimSpace(s)); return n }

// LookPath only (no JVM start), so callers can cheaply gate CPG generation
func JoernAvailable() bool {
	_, err := exec.LookPath(resolveBin("", "joern-parse"))
	return err == nil
}

func resolveBin(override, name string) string {
	if strings.TrimSpace(override) != "" {
		return override
	}
	if home := os.Getenv("QUARRY_JOERN_HOME"); home != "" {
		return filepath.Join(home, name)
	}
	return name
}

func escapeScala(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), `"`, `\"`)
}

func tail(s string, n int) string {
	if len(s) > n {
		return "…" + s[len(s)-n:]
	}
	return s
}
