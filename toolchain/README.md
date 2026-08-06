# quarry-fuzz toolchain image

The fuzzing toolchain **quarry owns and pins**. Per ADR-0004 (*Direct, Don't Craft*) and the
*Analysis Tool Image* design, quarry must not inherit whatever fuzzer a target image happens to
bake in — it controls the coverage-guided byte-generator end to end. This image is that
control point: a pinned base with AFL++, libFuzzer, and the sanitizer runtimes, on top of which
`internal/fuzz.BuildSpec` recompiles a target's harness **from source** with quarry's own
instrumentation and then fuzzes the harness *quarry* built.

## What's in it

| Component | Pin | Purpose |
|---|---|---|
| Ubuntu 24.04 (noble) | `--build-arg BASE_DIGEST=sha256:…` | reproducible base OS |
| clang / LLVM | `--build-arg LLVM_VERSION=18` (noble default) | afl-clang-fast/-lto backends, libFuzzer (`-fsanitize=fuzzer`), ASan/UBSan/MSan runtimes, `lld` for LTO |
| AFL++ | `--build-arg AFLPP_TAG=v4.21c` + `AFLPP_COMMIT=…` | `afl-fuzz` (modern `-V`/CMPLOG `-c`/MOpt `-L`), `afl-clang-fast`, `afl-clang-lto` |

Build tooling for arbitrary targets (make/cmake/ninja/autotools/pkg-config) is included so a
target's own build system runs unmodified under the AFL++ compiler wrappers. Heavier RE /
symbolic / static tools are **opt-in sidecars** (Analysis Tool Image doc), not baked here.

## Build

```sh
cd bench/toolchain

# 1. Resolve the base digest to pin (do this once; record it in this file / CI).
BASE_DIGEST=$(docker buildx imagetools inspect ubuntu:24.04 --format '{{.Manifest.Digest}}')

# 2. Resolve the AFL++ tag → commit to verify (guards a moved tag).
AFLPP_TAG=v4.21c
AFLPP_COMMIT=$(git ls-remote https://github.com/AFLplusplus/AFLplusplus "refs/tags/${AFLPP_TAG}^{}" | cut -f1)

docker build \
  -f Dockerfile.quarry-fuzz \
  --build-arg BASE_DIGEST="${BASE_DIGEST}" \
  --build-arg AFLPP_TAG="${AFLPP_TAG}" \
  --build-arg AFLPP_COMMIT="${AFLPP_COMMIT}" \
  -t quarry-fuzz:latest \
  .
```

`quarry-fuzz:latest` is the tag `internal/fuzz.QuarryFuzzImage` refers to.

## Pinning the produced digest (content-addressed, pull-only — Tool Provisioning)

The image must be consumed **by digest**, not by the `:latest` tag, so a campaign is
reproducible and a mutated tag can never silently swap the fuzzer. After building, capture the
digest and record it:

```sh
# Local (buildx / containerd store):
docker buildx imagetools inspect quarry-fuzz:latest --format '{{.Manifest.Digest}}'
# …or after pushing to the pinned, pull-only mirror:
docker push <registry>/quarry-fuzz:latest
docker buildx imagetools inspect <registry>/quarry-fuzz:latest --format '{{.Manifest.Digest}}'
```

Then pin downstream by digest:

```
quarry-fuzz@sha256:<digest>
```

- Set `internal/fuzz` consumers' `BuildSpec.BaseImage` to the `…@sha256:…` form for a pinned
  build, or leave it empty to use the `QuarryFuzzImage` alias in dev.
- The registry that serves this image should be the **content-addressed, pull-only package
  mirror** ADR-0004 tier-3 and [[Tool Provisioning]] call for — curated once, broadly, behind
  the scoped network hole — never a per-run `apt-get install` of a niche library.

### Digest record

| Built | Base `ubuntu:24.04` digest | AFL++ commit | `quarry-fuzz` digest |
|---|---|---|---|
| _TBD on first build_ | _TBD_ | _TBD_ | _TBD_ |

> These are intentionally left `TBD`: this environment cannot run `docker build`, so no real
> digest exists yet. The recipe is correct-by-construction; the row is filled from the `docker
> buildx imagetools inspect` output the first time the image is built in CI (see
> `infra_deferred` in the build handoff). Do **not** invent a digest here — an unpinned or
> fabricated digest defeats the entire point of quarry owning the toolchain.

## Analysis Tool Image opt-in layers (static+ / triage+ / re+ / symbolic+)

Alongside the always-on fuzzing base, the opt-in *Analysis Tool Image* layers are provisioned
the **same way** — pinned source → recipe → content-addressed image → pinned in the store —
so a layer's tools become broker-exposed only once its bytes are recorded. Each is a manifest
entry (`bench/toolchain/manifest.yaml`) backed by a recipe here and a broker profile
(`internal/agent.AnalysisProfiles`):

| Layer | Recipe | Manifest / image | Pinned tool(s) | State |
|---|---|---|---|---|
| `static+` | `Dockerfile.quarry-static` | `quarry-static` → `/tools/quarry-static.tar` | cppcheck (source-pinned) + clang-tidy/scan-build (pinned LLVM) | full recipe |
| `triage+` | `Dockerfile.quarry-triage` | `quarry-triage` → `/tools/quarry-triage.tar` | valgrind/memcheck (source-pinned) | full recipe (rr deferred — needs host perf counters) |
| `re+` | `Dockerfile.quarry-re` | `quarry-re` → `/tools/quarry-re.tar` | Ghidra headless (source-pinned) | **stub** — heavy Gradle build deferred; Binary Ninja is MCP-only/commercial |
| `symbolic+` | `Dockerfile.quarry-symbolic` | `quarry-symbolic` → `/tools/quarry-symbolic.tar` | angr (source-pinned) | **stub** — heavy wheel stack + KLEE deferred |

The linkage: `AnalysisProfiles()` layers carry `Artifact` (the manifest name) + `Target` (the
mount path). `agent.ProvisionedProfiles/ProvisionedCatalog` expose a layer's tools **iff** its
artifact hash is recorded in the store's provenance, and `agent.LayerToolset` turns the
provisioned layers into the broker `Toolset` a run bind-mounts. `remote-pwn+` / `web+` remain
pure profile metadata (no recipe yet) — surfaced as *available on request*, not auto-provisioned.

### Source-commit pins (analysis layers)

The recipes pin the human **tag**; the exact commit is the `*_COMMIT` build arg, verified by a
guard identical to `quarry-fuzz`'s `AFLPP_COMMIT` check (a moved tag fails the build). The
committed manifest carries the **40-zero not-yet-pinned sentinel** for these commits: this
environment has no network to resolve `tag→commit`, and fabricating a real-looking hash would
defeat the pin. Resolve + record them on the first build, e.g.:

```sh
git ls-remote https://github.com/danmar/cppcheck            "refs/tags/2.16.0^{}"
git ls-remote https://github.com/tklengyel/valgrind         "refs/tags/VALGRIND_3_24_0^{}"
git ls-remote https://github.com/NationalSecurityAgency/ghidra "refs/tags/Ghidra_11.3_build^{}"
git ls-remote https://github.com/angr/angr                  "refs/tags/v9.2.145^{}"
```

The layer images are content-addressed **whole** (`mode: image`, `docker save`), exactly like
`quarry-fuzz`; their `pin:` slots stay empty until the first `quarry toolctl populate` records
the produced `sha256:…` (see the pinning procedure above).

## How a target uses it (from-source instrumentation)

`internal/fuzz.BuildSpec` generates a Dockerfile that does `FROM quarry-fuzz@sha256:…`, injects
`AFL_USE_ASAN=1` + `CC=afl-clang-fast`, runs the target's own build command (now instrumented),
and compiles the harness against it — plus an optional `AFL_LLVM_CMPLOG=1` build for
`afl-fuzz -c`. `BuildSpec.InstrumentedCampaign()` then returns an `EngineAFLPlusPlus` campaign
(MOpt on, CMPLOG wired, real `-V` wall-clock) pointed at the harness quarry just built —
**not** the image's baked binary. `bench/targets/freetype-cve-2025-27363/Dockerfile.fuzz` is a
hand-written instance of exactly this shape.
