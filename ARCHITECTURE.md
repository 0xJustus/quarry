# Architecture

Quarry points a coding agent at a target and judges the result with a
deterministic oracle. The agent proposes candidates; the oracle confirms them. A
finding is an oracle-verified fact, not the model's claim.

There are two ways to use it:

- **Verify.** Check a candidate proof-of-vulnerability against a runnable target.
  Deterministic, offline, no model in the loop.
- **Discover.** Run an agent loop that constructs and tests candidates, with the
  same oracle as the referee.

Either way, quarry is an embeddable **core**: a Go frontend imports
`internal/core`; any other frontend speaks JSON-RPC over stdio to `quarry serve`
(or `quarry call OP` for one-shots). Every operation flows through an `Engine`
that records it on a hash-chained, tamper-evident audit trail — there is no
un-audited path to a model or a target.

## Guiding principle

An offline, deterministic verifier is the source of truth. Everything else
either feeds it or records what it confirmed. OSS-Fuzz and ClusterFuzz work the
same way: a crash under a sanitizer is ground truth. Quarry adds a composable
verdict and an agent that proposes the inputs.

## Components

| Component | Package | Role |
|---|---|---|
| Oracle | `internal/verdict/oracle` | Composable verdict over a run result: sanitizer class and site, terminating signal, exit code, output, timeout, and an optional differential (vulnerable vs fixed) clause. |
| Runner | `internal/verdict/runner` | Executes the target air-gapped (`--network none`, pinned sanitizer options, capped output) and parses sanitizer reports into normalized frames. |
| Agent | `internal/discover/agent` | A framework-free ReAct loop over a fixed tool belt (read, edit, exec, run_pov), with iteration, token, and stall governors, plus context compaction. |
| Loop | `internal/discover/loop` | The supervisor: plan an objective, fan out parallel hypotheses, backtrack into sub-hypotheses, aggregate confirmed findings. |
| Router | `internal/platform/router` | Model selection by role and task kind. Cheap tier for checkable work, strong tier for open reasoning, budget cascade. Routes by **checkability**, not function (ADR-0003). |
| Analyst | `internal/discover/loop` (`ModelAnalyst`) | Strong-tier source analysis → ranked work items for weak executors. Directs the frontier; does not gate it (undirected breadth reserved). |
| Datastore | `internal/platform/store` | SQLite plus content-addressed blobs. Records the full replayable trajectory and tags facts, observations, and hypotheses. |
| Artifact | `internal/publish/artifact` | The atomic unit: a content-addressed `{specimen, crash}` core with a derived behavioral key in the style of ClusterFuzz crash state. |
| Target | `internal/intake/target` | Ingests a binary, a local build, a Dockerfile, or an image into a runnable target, plus optional white-box source. |
| Commons | `internal/publish/gitcommons` (+ the `quarry-commons` data repo) | An optional shared store of verified crash abstracts as a git-native, content-addressed tree: a Bloom root digest for cheap existence checks, a prefix-sharded behavioral-key index, and a CI verify gate. Retrieval is never authoritative. |
| Core | `internal/core` (+ `internal/core/corerpc`) | The embeddable `Engine` every operation hangs off; injects audited decorators so no un-audited runner or model escapes into an op. Bindable over stdio JSON-RPC; the `schema` op self-describes every op's typed parameters. |
| Audit | `internal/platform/audit` | Hash-chained, tamper-evident trail of every access, action, and side-effect. Each entry commits the prior entry's hash, so a break is detectable at a specific sequence number. |

## The oracle

A run produces a `RunResult`: the terminating signal, exit code, stdout and
stderr, a parsed sanitizer report, and timing. The oracle evaluates a `Spec`
against it. A spec is an `any` or `all` set of conditions over the sanitizer
class and site, the signal, the exit code, output patterns, and a timeout, with
an optional differential clause that passes on the vulnerable build and fails on
the fixed one.

Two properties make the verdict trustworthy:

- **Corroboration.** A sanitizer report counts only when the process also
  terminated abnormally. A target that prints a fabricated `AddressSanitizer`
  line and exits cleanly is rejected. This makes the verdict hard to forge, which
  model-based triage cannot offer.
- **Air-gap.** The judged run happens in a fresh container the agent cannot
  reach, so the agent cannot tamper with the thing that judges it.

## The agent loop

The `investigate` op runs a reason-act-observe loop over the fixed tool belt
(`mode` `discover` for autonomous breadth, `copilot` for objective-guided). The
loop is deliberately framework-free and sits behind a `model.Model` seam, so a
framework such as Eino can drop in without changing the loop itself.

The supervisor plans an objective into independent hypotheses, runs them as
parallel scientists, and lets a stuck scientist spawn a narrower sub-hypothesis
that the supervisor backtracks into (bounded by a depth cap). Confirmed findings
aggregate. A run that never confirms ends with a bounded "exhausted within
budget" report, never a claim that no bug exists.

Under ADR-0003 (capability-assigned roles), a white-box discover run (or
`--analyst`) uses a strong **Analyst** that reads seeded source and emits ranked
structured work items (target section, reachability, bug class, attack angle).
Weak **Executors** work each item under the oracle. The Analyst directs recall;
the oracle still owns correctness. One undirected frontier slot is reserved so a
wrong analysis cannot blind the run.

## Staying grounded

Long unattended runs drift. Five mechanisms guard against this:

1. The oracle is ground truth, so the agent cannot declare a false success.
2. A stall governor halts a scientist that stops producing new observations.
3. Sub-hypothesis backtracking decomposes a stuck line instead of looping on it.
4. A fresh-context critic reviews a dead-ended line with clean context.
5. Context compaction keeps the working context bounded by reprojecting it over
   the durable trajectory, carrying ruled-out lines forward so a dead end is
   never re-tried. See `internal/discover/agent/compact.go`.

## Model routing and budgets

Every model call goes through the router, keyed by role (supervisor, analyst,
harness, critic, verifier, exploit-dev) and task kind. The routing invariant is
**checkability**, not function: checkable work (a PoV or harness the oracle will
judge, including compaction digests) runs on a cheap tier; open reasoning
(Analyst, Critic, planning) runs on a strong tier. A budget cascade drops to the
cheap tier as the token envelope runs down. `MultiModel` dispatches by model
name so the strong tier can sit on a different provider than the cheap tier
(e.g. Claude + GLM) without a litellm sidecar.

Budgets are enforced per hypothesis, with token and iteration caps, and real
per-call cost is recorded from the model proxy.

## Verification and reporting

The `verify` op takes a runnable target and a candidate PoV and returns a
composable verdict — confirmed or not — by re-executing air-gapped and applying
the oracle. The `report` op turns that verdict into a SARIF 2.1.0 bug-candidate
aligned with the OSS-CRS libCRS contract: a correlation id derived from the
behavioral key, verification carried in the result level and properties, a
numeric `security-severity`, and source and revision provenance.

Packaging the report loop as a standalone OSS-CRS `bug-finding-triage` CRS
(consume a campaign's candidate PoVs, re-ground each, dedup by behavioral key,
submit verified SARIF) lives in local-only deployment infrastructure, not the
shipped core.

## The commons

The commons is a git-native, content-addressed tree (`internal/publish/gitcommons`,
materialized as the `quarry-commons` data repo): public crash abstracts
under `artifacts/<id[:2]>/<id>.json`, a prefix-sharded behavioral-key index under
`keys/`, and a Bloom root digest (`digest/keys.bloom`) a consumer pulls alone to
answer "novel or prior art?" locally, sparse-fetching one shard on a probable hit.
Identity is content-addressed, so the same crash produces the same id everywhere;
git is transport, dedup, and distribution. Writes are gated in CI by the
`commons.verify` anti-poisoning gate instead of a shared secret. Retrieval
is never authoritative: a hit is a candidate the client re-grounds against its own
oracle-confirmed PoV, and a miss is a definitive "novel". Seeded from ARVO and
OSS-Fuzz reproducers. The client consults a pulled tree via the `commons_tree`
param (or the `query` op); it never phones home.

## What is built, and what is not

| Area | Status |
|---|---|
| Oracle, runner, agent, routing, budgets, anti-drift, datastore | Built and tested. |
| Core engine + audit spine + stdio JSON-RPC transport | Built and tested; every op audited, no blind spots. |
| `verify` and `report` (SARIF) ops | Built, tested, validated on a real CVE (FreeType CVE-2025-27363). |
| OSS-CRS triage-CRS packaging | Lives in local-only deployment infra, not the shipped core; the SARIF `report` op is the product surface. |
| Commons store (git-native `quarry-commons`) | Built and tested: content-addressed tree + Bloom digest + `commons-verify` anti-poisoning gate. Seeded from ARVO (4,378 abstracts). |
| Semantic and vector matching | Deferred. No git-native equivalent for ANN; would return as a hosted index. Not built. |
| Capability chains (multi-step) | Data structures and graph search are built. No real chain data feeds them yet. |
| Training flywheel | Substrate only. The datastore is replay-ready; there is no training pipeline. |
| Service and network targets | Out of scope today. File-input targets only. |

## References

Quarry builds on established work rather than reinventing it:

- **OSS-Fuzz** and **ClusterFuzz** for the sanitizer-crash-as-truth model and
  crash-state deduplication.
- **ARVO** (Atlas of Reproducible Vulnerabilities) for reproducible seed data.
- **AFL++** and **libFuzzer** for the coverage-guided baseline quarry measures
  against.
- **SARIF 2.1.0** and the **OSS-CRS / libCRS** contract for the bug-candidate
  wire format.
- **AIxCC** and **OSS-CRS** for the cyber-reasoning-system context quarry plugs
  into.
