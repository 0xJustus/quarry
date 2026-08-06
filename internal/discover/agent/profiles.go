package agent

import "github.com/0xjustus/quarry/internal/platform/broker"

// Profile is one Analysis Tool Image layer surfaced to the agent as a tool group (provisioned ⇔ its Artifact hash is in store provenance).
type Profile struct {
	Name     string        // layer id: "baseline", "fuzzing+", "static+", "re+", "symbolic+", "triage+", "remote-pwn+", "web+"
	Desc     string        // one-line human description of the layer
	Artifact string        // toolctl manifest tool name whose pinned image backs this layer ("" ⇒ no dedicated image)
	Target   string        // absolute in-container mount path of the backing artifact ("" when Artifact is "")
	AlwaysOn bool          // baseline: provisioned unconditionally, independent of any artifact
	Tools    []broker.Tool // catalog entries this layer provides
}

// Role-scope groups; empty tool Roles ⇒ every role.
var (
	roleOffense  = []string{"exploit-dev"}
	roleAnalysis = []string{"analyst", "exploit-dev"}
	roleRE       = []string{"analyst", "exploit-dev", "triage"}
	roleTriage   = []string{"triage", "exploit-dev"}
)

// caps: analysis output is verbose; the broker truncates past these.
const (
	capSmall  = 32 << 10
	capMedium = 128 << 10
	capLarge  = 256 << 10
)

// AnalysisProfiles is the source of truth for what layers exist.
func AnalysisProfiles() []Profile {
	return []Profile{
		{
			Name: "baseline", Desc: "always-on binutils + sanitizers + scriptable RE (small, no role gate)",
			AlwaysOn: true,
			Tools: []broker.Tool{
				{Name: "objdump", Description: "Disassemble/inspect an object or binary (objdump).", OutputCap: capLarge},
				{Name: "readelf", Description: "Read ELF headers, sections, and symbols (readelf).", OutputCap: capMedium},
				{Name: "nm_symbols", Description: "List symbols in a binary, demangled (nm -C).", OutputCap: capMedium},
				{Name: "strings_scan", Description: "Extract printable strings that hint at the input grammar (strings).", OutputCap: capMedium},
				{Name: "checksec", Description: "Report a binary's exploit-mitigation posture (checksec).", OutputCap: capSmall},
				{Name: "semgrep_scan", Description: "Lightweight source-pattern scan for suspect sinks (semgrep).", OutputCap: capMedium},
				{Name: "radare2", Description: "Scriptable disassembly/analysis over r2/rizin commands.", OutputCap: capLarge},
			},
		},
		{
			Name: "fuzzing+", Desc: "coverage-guided fuzzers (AFL++ CMPLOG/redqueen, honggfuzz)",
			Artifact: "quarry-fuzz", Target: "/tools/quarry-fuzz.tar",
			Tools: []broker.Tool{
				{Name: "aflpp_fuzz", Description: "Run AFL++ (CMPLOG/redqueen) over a harness to break magic-value gates.", Roles: roleOffense, OutputCap: capMedium},
				{Name: "honggfuzz", Description: "Run honggfuzz over a harness for a decorrelated fuzzing arm.", Roles: roleOffense, OutputCap: capMedium},
			},
		},
		{
			Name: "static+", Desc: "deep static analysis (CodeQL, cppcheck, clang-tidy, Infer)",
			Artifact: "quarry-static", Target: "/tools/quarry-static.tar",
			Tools: []broker.Tool{
				{Name: "codeql_query", Description: "Run a CodeQL query for source-level reachability/data-flow leads.", Roles: roleAnalysis, OutputCap: capLarge},
				{Name: "cppcheck", Description: "Static C/C++ defect scan (cppcheck).", Roles: roleAnalysis, OutputCap: capMedium},
				{Name: "clang_tidy", Description: "clang-tidy static checks over a compilation unit.", Roles: roleAnalysis, OutputCap: capMedium},
				{Name: "infer", Description: "Facebook Infer interprocedural static analysis.", Roles: roleAnalysis, OutputCap: capMedium},
			},
		},
		{
			Name: "re+", Desc: "decompilers (Ghidra headless, Binary Ninja + MCP)",
			Artifact: "quarry-re", Target: "/tools/quarry-re.tar",
			Tools: []broker.Tool{
				{Name: "ghidra_decompile", Description: "Decompile a function via Ghidra headless — read C-like source of a source-less target.", Roles: roleRE, OutputCap: capLarge},
				{Name: "binja_decompile", Description: "Decompile a function via the Binary Ninja MCP sidecar.", Roles: roleRE, OutputCap: capLarge},
			},
		},
		{
			Name: "symbolic+", Desc: "symbolic/concolic execution (angr, unicorn, KLEE)",
			Artifact: "quarry-symbolic", Target: "/tools/quarry-symbolic.tar",
			Tools: []broker.Tool{
				{Name: "angr_explore", Description: "Symbolically explore paths to a target address (angr).", Roles: roleAnalysis, OutputCap: capMedium},
				{Name: "unicorn_emulate", Description: "Emulate a code range over the Unicorn engine.", Roles: roleAnalysis, OutputCap: capMedium},
				{Name: "klee_run", Description: "Run KLEE over an LLVM bitcode harness for path-driven inputs.", Roles: roleAnalysis, OutputCap: capMedium},
			},
		},
		{
			Name: "triage+", Desc: "crash triage / deterministic replay (rr, valgrind)",
			Artifact: "quarry-triage", Target: "/tools/quarry-triage.tar",
			Tools: []broker.Tool{
				{Name: "rr_replay", Description: "Record/replay a crash deterministically (rr) for root-cause triage.", Roles: roleTriage, OutputCap: capMedium},
				{Name: "valgrind", Description: "Run under valgrind/memcheck to localize a memory error.", Roles: roleTriage, OutputCap: capMedium},
			},
		},
		{
			Name: "remote-pwn+", Desc: "modern remote-pwn helpers (libc-database, seccomp-tools)",
			Tools: []broker.Tool{
				{Name: "libc_database", Description: "Identify a libc and resolve gadget/symbol offsets (libc-database + one_gadget).", Roles: roleOffense, OutputCap: capSmall},
				{Name: "seccomp_tools", Description: "Dump/analyze a target's seccomp filter (seccomp-tools).", Roles: roleOffense, OutputCap: capSmall},
			},
		},
		{
			Name: "web+", Desc: "web-target recon (nmap, ffuf, sqlmap, mitmproxy)",
			Tools: []broker.Tool{
				{Name: "nmap", Description: "Scan a web/service target's open ports (nmap).", Roles: roleOffense, OutputCap: capMedium},
				{Name: "ffuf", Description: "Fuzz web paths/parameters (ffuf).", Roles: roleOffense, OutputCap: capMedium},
				{Name: "sqlmap", Description: "Probe for SQL injection (sqlmap).", Roles: roleOffense, OutputCap: capMedium},
			},
		},
	}
}

func BaselineProfile() Profile {
	for _, p := range AnalysisProfiles() {
		if p.Name == "baseline" {
			return p
		}
	}
	return Profile{Name: "baseline"}
}

// ProfileCatalog flattens profiles into one catalog, deduping by tool name (first wins).
func ProfileCatalog(profiles ...Profile) broker.Catalog {
	var cat broker.Catalog
	seen := map[string]bool{}
	for _, p := range profiles {
		for _, t := range p.Tools {
			if t.Name == "" || seen[t.Name] {
				continue
			}
			seen[t.Name] = true
			cat.Tools = append(cat.Tools, t)
		}
	}
	return cat
}

// ProvisionedProfiles returns the always-on baseline plus every "+" layer whose backing artifact is provisioned (fail-closed; no dedicated Artifact ⇒ never auto-provisioned).
func ProvisionedProfiles(provisioned map[string]bool) []Profile {
	var out []Profile
	for _, p := range AnalysisProfiles() {
		if p.AlwaysOn || (p.Artifact != "" && provisioned[p.Artifact]) {
			out = append(out, p)
		}
	}
	return out
}

// ProvisionedCatalog is the catalog for exactly the provisioned layers, role-filtered later by the broker.
func ProvisionedCatalog(provisioned map[string]bool) broker.Catalog {
	return ProfileCatalog(ProvisionedProfiles(provisioned)...)
}

// LayerToolset resolves the provisioned "+" layers to mount pins, one per backing artifact (fail-closed: an unresolved hash is skipped; baseline / no-Artifact layers contribute no pin).
func LayerToolset(provisioned map[string]bool, hashOf func(artifact string) (string, bool)) broker.Toolset {
	var ts broker.Toolset
	seen := map[string]bool{}
	for _, p := range ProvisionedProfiles(provisioned) {
		if p.Artifact == "" || p.Target == "" || seen[p.Artifact] {
			continue
		}
		hash, ok := hashOf(p.Artifact)
		if !ok || hash == "" {
			continue
		}
		seen[p.Artifact] = true
		ts.Pins = append(ts.Pins, broker.ToolPin{Hash: hash, TargetPath: p.Target})
	}
	return ts
}

// profileVisibleTo reports a profile's tools a role may see (empty Roles ⇒ every role; role "" ⇒ unscoped).
func profileVisibleTo(p Profile, role string) []broker.Tool {
	var out []broker.Tool
	for _, t := range p.Tools {
		if role == "" || len(t.Roles) == 0 || sliceHas(t.Roles, role) {
			out = append(out, t)
		}
	}
	return out
}

func sliceHas(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
