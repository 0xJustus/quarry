package synth

import (
	"fmt"
	"path"
	"strings"
)

// BuildSpec parameterizes the dual build: instrumented (fuzzer) + plain-ASan (oracle).
type BuildSpec struct {
	BaseImage   string // must carry afl-clang-fast, clang and ASan
	BuildSystem string // cmake | autotools | make | plain
	SrcDir      string
	Spec        HarnessSpec // model-authored: its flags are allowlisted, not trusted
	IncludeDirs []string

	FuzzBuildCmd   string
	OracleBuildCmd string
	// required: the in-image .a paths those builds produce and the harness links
	StaticLibFuzz   string
	StaticLibOracle string

	WithCmplog bool
	// CMPLOG instrumentation is per translation unit, so the LIBRARY must be rebuilt
	CmplogBuildCmd  string
	StaticLibCmplog string
}

const (
	HarnessSrcPath = "/harness.c"
	FuzzBinPath    = "/harness.fuzz"
	OracleBinPath  = "/harness.oracle"
	CmplogBinPath  = "/harness.cmplog"
	defaultBaseImg = "aflplusplus/aflplusplus:latest"
	defaultSrcDir  = "/src"

	fuzzBuildDirName   = "build.fuzz"
	oracleBuildDirName = "build.oracle"
	cmplogBuildDirName = "build.cmplog"
)

// DefaultBuildCommand must produce a static library; the caller names its path in BuildSpec.
func DefaultBuildCommand(buildSystem, srcDir, buildDir, cc string) string {
	asan := "-g -O1 -fsanitize=address -fno-omit-frame-pointer"
	switch normBuildSystem(buildSystem) {
	case "cmake":
		return fmt.Sprintf(
			"cmake -S %s -B %s -DCMAKE_C_COMPILER=%s -DCMAKE_BUILD_TYPE=Debug "+
				"-DCMAKE_C_FLAGS='%s' -DBUILD_SHARED_LIBS=OFF && cmake --build %s -j\"$(nproc)\"",
			srcDir, buildDir, cc, asan, buildDir)
	case "autotools", "autoconf":
		return fmt.Sprintf(
			"mkdir -p %s && cd %s && %s/configure CC=%s CFLAGS='%s' --disable-shared --enable-static && make -j\"$(nproc)\"",
			buildDir, buildDir, srcDir, cc, asan)
	case "make", "makefile":
		return fmt.Sprintf("make -C %s clean >/dev/null 2>&1 || true; make -C %s CC=%s CFLAGS='%s' -j\"$(nproc)\"",
			srcDir, srcDir, cc, asan)
	default: // plain: no library build — the harness compile pulls the sources in directly
		return "true"
	}
}

func normBuildSystem(buildSystem string) string {
	return strings.ToLower(strings.TrimSpace(buildSystem))
}

func RenderDockerfile(s BuildSpec) string {
	base := s.BaseImage
	if base == "" {
		base = defaultBaseImg
	}
	src := s.SrcDir
	if src == "" {
		src = defaultSrcDir
	}
	fuzzBuildDir := path.Join(src, fuzzBuildDirName)
	oracleBuildDir := path.Join(src, oracleBuildDirName)

	fuzzBuild := s.FuzzBuildCmd
	if fuzzBuild == "" {
		fuzzBuild = DefaultBuildCommand(s.BuildSystem, src, fuzzBuildDir, "afl-clang-fast")
	}
	oracleBuild := s.OracleBuildCmd
	if oracleBuild == "" {
		oracleBuild = DefaultBuildCommand(s.BuildSystem, src, oracleBuildDir, "clang")
	}

	// include dirs are the caller's; only the spec's flags go through the allowlist
	incFlags := ""
	for _, d := range s.IncludeDirs {
		incFlags += " -I" + d
	}
	incFlags += " -I" + src
	specCFlags, droppedFlags := splitSafeFlags(s.Spec.ExtraCFlags, safeCompileFlag)
	linkFlags, droppedLinks := splitSafeFlags(s.Spec.LinkLibs, safeLinkFlag)
	droppedFlags = append(droppedFlags, droppedLinks...)

	// quarry's flags come LAST: clang honours the last -f{,no-}sanitize
	compile := func(cc, staticLib, out string, cmplog bool) string {
		env := ""
		if cc == "afl-clang-fast" {
			env = "AFL_USE_ASAN=1 "
			if cmplog {
				env = "AFL_USE_ASAN=1 AFL_LLVM_CMPLOG=1 "
			}
		}
		return fmt.Sprintf("RUN %s%s%s%s -g -O1 -fsanitize=address -fno-omit-frame-pointer %s %s%s -o %s",
			env, cc, incFlags, specCFlags, HarnessSrcPath, staticLib, linkFlags, out)
	}

	var b strings.Builder
	b.WriteString("# Synthesized by quarry synth: dual-build harness image.\n")
	b.WriteString("# fuzz = afl-clang-fast + ASan (coverage); oracle = clang + ASan (trusted re-confirm).\n")
	if len(droppedFlags) > 0 {
		fmt.Fprintf(&b, "# quarry synth: DROPPED %d spec-supplied flag(s) — not plain compile/link flags, or they touch what quarry owns.\n", len(droppedFlags))
		for _, d := range droppedFlags {
			fmt.Fprintf(&b, "#   dropped: %s\n", commentSafe(d))
		}
	}
	fmt.Fprintf(&b, "FROM %s\n", base)
	fmt.Fprintf(&b, "COPY . %s\n", src)
	fmt.Fprintf(&b, "COPY harness.c %s\n", HarnessSrcPath)
	b.WriteString("# --- instrumented (fuzz) build ---\n")
	fmt.Fprintf(&b, "RUN %s\n", fuzzBuild)
	b.WriteString(compile("afl-clang-fast", s.StaticLibFuzz, FuzzBinPath, false) + "\n")
	// must stay before the oracle build: an in-tree `make clean` would remove the archive
	if s.WithCmplog {
		cmplogBuild, cmplogLib, ok, why := cmplogRecipe(s, src, path.Join(src, cmplogBuildDirName))
		if !ok {
			fmt.Fprintf(&b, "# --- CMPLOG build OMITTED: %s ---\n", commentSafe(why))
		} else {
			b.WriteString("# --- CMPLOG (input-to-state) build: the LIBRARY rebuilt with AFL_LLVM_CMPLOG=1, ---\n")
			b.WriteString("# --- because CMPLOG instrumentation is per translation unit. ---\n")
			if cmplogBuild != "" {
				fmt.Fprintf(&b, "RUN %s\n", cmplogBuild)
			}
			b.WriteString(compile("afl-clang-fast", cmplogLib, CmplogBinPath, true) + "\n")
		}
	}
	b.WriteString("# --- plain-ASan (oracle) build ---\n")
	fmt.Fprintf(&b, "RUN %s\n", oracleBuild)
	b.WriteString(compile("clang", s.StaticLibOracle, OracleBinPath, false) + "\n")
	return b.String()
}

// ok=false when quarry cannot produce genuine library comparison data: emit no cmplog binary.
func cmplogRecipe(s BuildSpec, src, cmplogBuildDir string) (build, lib string, ok bool, why string) {
	if s.StaticLibCmplog != "" {
		cmd := s.CmplogBuildCmd
		if cmd == "" {
			cmd = DefaultBuildCommand(s.BuildSystem, src, cmplogBuildDir, "afl-clang-fast")
		}
		return withCmplogEnv(cmd), s.StaticLibCmplog, true, ""
	}
	if s.CmplogBuildCmd != "" {
		return "", "", false, "CmplogBuildCmd was supplied without StaticLibCmplog, so quarry cannot tell which archive carries the CMPLOG instrumentation"
	}
	if s.FuzzBuildCmd != "" {
		return "", "", false, "a caller-supplied FuzzBuildCmd has no derivable CMPLOG counterpart (set CmplogBuildCmd + StaticLibCmplog); linking the non-CMPLOG library would carry no comparison data"
	}
	switch normBuildSystem(s.BuildSystem) {
	case "cmake", "autotools", "autoconf":
		// AFL_LLVM_CMPLOG is an env var, not a cflag: a FRESH build dir is required
		l, swapped := swapPathElem(s.StaticLibFuzz, fuzzBuildDirName, cmplogBuildDirName)
		if !swapped {
			return "", "", false, "StaticLibFuzz is not under the default " + fuzzBuildDirName + " dir, so quarry cannot derive the CMPLOG archive path (set StaticLibCmplog)"
		}
		return withCmplogEnv(DefaultBuildCommand(s.BuildSystem, src, cmplogBuildDir, "afl-clang-fast")), l, true, ""
	case "make", "makefile":
		return withCmplogEnv(DefaultBuildCommand(s.BuildSystem, src, cmplogBuildDir, "afl-clang-fast")), s.StaticLibFuzz, true, ""
	default:
		// plain: no library build, so CMPLOG on the harness compile already covers the sources
		return "", s.StaticLibFuzz, true, ""
	}
}

// export, never a `VAR=1 cmd` prefix: a prefix would apply only to the first command
func withCmplogEnv(cmd string) string { return "export AFL_LLVM_CMPLOG=1; " + cmd }

func swapPathElem(p, from, to string) (string, bool) {
	elems := strings.Split(p, "/")
	found := false
	for i, e := range elems {
		if e == from {
			elems[i], found = to, true
		}
	}
	if !found {
		return p, false
	}
	return strings.Join(elems, "/"), true
}

// characters that let a flag stop being one argument and start being a command
const shellMeta = " \t\n\r\v\f\"'`$;&|<>(){}[]*?!\\~#"

// allowlist, not blocklist: an unrecognized flag is DROPPED, never spliced into the RUN line.
func splitSafeFlags(flags []string, allow func(string) bool) (spliced string, dropped []string) {
	var b strings.Builder
	for _, f := range flags {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if strings.ContainsAny(f, shellMeta) || !allow(f) {
			dropped = append(dropped, f)
			continue
		}
		// the allowlist already rejected quotes, so single-quoting is exact
		b.WriteString(" '" + f + "'")
	}
	return b.String(), dropped
}

func safeCompileFlag(f string) bool {
	if quarryOwnedFlag(f) {
		return false
	}
	switch {
	case strings.HasPrefix(f, "-I") && len(f) > 2,
		strings.HasPrefix(f, "-iquote"), strings.HasPrefix(f, "-isystem"),
		strings.HasPrefix(f, "-D") && len(f) > 2,
		strings.HasPrefix(f, "-U") && len(f) > 2,
		strings.HasPrefix(f, "-std="),
		f == "-pthread",
		strings.HasPrefix(f, "-W") && !strings.HasPrefix(f, "-Wl,"), // warnings, not a linker passthrough
		strings.HasPrefix(f, "-f"):
		return true
	}
	return false
}

func safeLinkFlag(l string) bool {
	if quarryOwnedFlag(l) {
		return false
	}
	switch {
	case strings.HasPrefix(l, "-l") && len(l) > 2,
		strings.HasPrefix(l, "-L") && len(l) > 2,
		l == "-pthread":
		return true
	}
	// an absolute archive only: a bare word would be another source file to the compiler
	return strings.HasPrefix(l, "/") && (strings.HasSuffix(l, ".a") || strings.HasSuffix(l, ".o"))
}

// what quarry decides, not the model: sanitizer, frame pointer, output path, compiler plugins
func quarryOwnedFlag(f string) bool {
	switch {
	case strings.Contains(f, "sanitize"), strings.Contains(f, "omit-frame-pointer"),
		strings.HasPrefix(f, "-fplugin"), strings.HasPrefix(f, "-fpass-plugin"),
		strings.HasPrefix(f, "-fprofile"), strings.HasPrefix(f, "-o"),
		strings.HasPrefix(f, "-B"), strings.HasPrefix(f, "-specs"),
		strings.HasPrefix(f, "@"):
		return true
	}
	return false
}

// in a Dockerfile comment a newline would end the comment and start an INSTRUCTION
func commentSafe(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			r = '?'
		}
		b.WriteRune(r)
		if b.Len() >= 120 {
			b.WriteString("…")
			break
		}
	}
	return b.String()
}
