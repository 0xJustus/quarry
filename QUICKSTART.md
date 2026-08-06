# quarry quickstart

Agent-native vulnerability discovery + exploit-dev, judged by a deterministic
oracle. The agent proposes candidate findings; the oracle decides. A finding is
real only when a fresh, air-gapped re-run confirms it.

quarry is an embeddable **core** with a bindable interface — there is no
per-command CLI. A Go frontend imports `internal/core`; any other frontend speaks
JSON-RPC over stdio to `quarry serve`. For a one-shot from the shell, `quarry call`
dispatches a single op. Every access, action, and side-effect is recorded on a
hash-chained, tamper-evident audit trail — no blind spots.

For the design, see [ARCHITECTURE.md](ARCHITECTURE.md) and [`docs/`](docs/README.md).

## 1. Install

Pure Go, no cgo, so it builds anywhere with a recent Go toolchain.

```sh
make build            # → bin/quarry  (+ bin/quarry-vetd, bin/quarry-shim)
bin/quarry version
```

Docker is optional but recommended (the air-gapped target runner and the agent
sandbox use it).

## 2. The shape: serve / call / audit

Three entry points, and two discovery ops that make the rest self-describing:

```sh
bin/quarry call ops                         # list every operation
bin/quarry call schema '{"op":"verify"}'    # typed parameter schema for an op
```

`schema` returns each field's name, render type (`string|int|number|bool|bytes|string[]|json`)
and whether it is optional — the same contract a frontend renders a form from. A
`bytes` field is base64 on the wire.

Every `call` appends to an audit log (`--audit PATH`, default `quarry-audit.jsonl`;
`--principal ID` tags the caller). Verify it any time:

```sh
bin/quarry audit verify quarry-audit.jsonl   # intact / broken-at-seq
```

## 3. Point it at a model (no sidecar required)

quarry speaks provider APIs natively (Anthropic Messages + OpenAI-compatible).
Configure the model through the environment; the core reads it at startup:

```sh
# Claude (provider inferred from the model name)
export QUARRY_API_KEY=sk-ant-...
export QUARRY_MODEL=claude-sonnet-4-5

# GLM via z.ai's Anthropic-compatible endpoint
export QUARRY_API_KEY=...                    # z.ai key
export QUARRY_MODEL=glm-5.2
export QUARRY_PROVIDER=anthropic
export QUARRY_PROXY_URL=https://api.z.ai/api/anthropic/v1
```

`QUARRY_PROVIDER` is inferred from the model name (`-ant` suffix or `claude`
prefix → Anthropic) unless set. A tiered setup adds a strong planner:
`QUARRY_MODEL_STRONG` (+ `QUARRY_PROVIDER_STRONG`, `QUARRY_MODEL_STRONG_URL`,
`QUARRY_MODEL_STRONG_KEY`). With a strong tier configured, reasoning ops route
cheap-for-checkable-work / strong-for-planning automatically, and the
divergence-corroboration backstop gets its independent strong reference.

## 4. Verify a finding (free, offline, no key)

Hand `verify` a target descriptor plus a candidate PoV and it re-executes,
air-gapped, through the deterministic oracle. No model, no network; your code
never leaves the machine. Prove your own finding before you report it, or triage
fuzzer/agent output.

```sh
# base64 the candidate, then dispatch:
POV=$(base64 < ./candidate.bin | tr -d '\n')
bin/quarry call verify "{\"target_file\":\"testdata/demo-stack-overflow/quarry.yaml\",\"pov\":\"$POV\"}"
```

```json
{
  "confirmed": true,
  "verdict": {
    "pass": true,
    "conditions": [ { "type": "signal", "matched": true, "detail": "terminated by SIGABRT (6)" } ]
  }
}
```

No model opinion enters the verdict: the finding is re-executed and judged only
by whether the target actually crashes (or hangs). That rejects the most common
failure mode (an LLM asserting a bug); a fabricated report (scary stderr, clean
exit, or `exit 1` after printing a fake report) is **rejected**, because a report
is trusted only when the process aborts by signal or hangs — outcomes the target
can't manufacture. A CI gate reads `.confirmed` from the JSON (`call` exits
non-zero only when the op itself errored, never for an honest UNCONFIRMED).

## 5. Run one investigation

`investigate` is the discovery loop: it plans an objective, fans out hypotheses,
and returns only oracle-confirmed findings.

```sh
make demo-target      # compile the bundled ASan target
bin/quarry call investigate '{
  "target_file": "testdata/demo-stack-overflow/quarry.yaml",
  "objective":   "find and prove a memory-safety bug in parse_header",
  "analyst":     true
}'
```

The result carries a `run_id`, per-finding identity (private specimen id +
signed public abstract id, bug class, behavioral key, novelty), and usage/metrics.
`mode` defaults to `copilot` (objective-guided); set it to `discover` for
autonomous breadth. `analyst: true` turns on the strong-tier source analyst that
directs the frontier; `critic: true` adds the adversarial reviewer.

## 6. Govern long / unattended runs

Budgets and stall limits ride in the params:

```sh
bin/quarry call investigate '{
  "target_file":  "…/quarry.yaml",
  "token_budget": 200000,
  "stall_limit":  5,
  "max_iters":    24
}'
```

`token_budget` halts a scientist at that many tokens; `stall_limit` halts after N
no-progress iterations. Tiered routing comes from the `QUARRY_MODEL_STRONG`
environment (§3).

## 7. Isolate the agent (recommended for untrusted targets)

By default the agent's `exec` runs on the host (not a security boundary). Pin a
locked-down toolbox image (no network, no docker socket, read-only rootfs) and
pass it — digest-pinned; mutable tags are refused:

```sh
export QUARRY_AGENT_IMAGE=sha256:…           # or per-call "agent_image": "sha256:…"
```

The toolbox image recipe and role-scoped tool catalog live with your deployment
infrastructure, not in this core repo (the shipped repo is the pure-Go core). Pin
extra analysis tools through the `tool_catalog` / `tool_store` / `tool_allowlist`
params, backed by `toolctl.populate` over the `toolchain/manifest.yaml` pins.

## 8. The shared commons (git-native)

quarry runs fully offline; the commons is additive and **git-native**: a
content-addressed tree of public crash abstracts, a behavioral-key index, and a
Bloom root digest, published as the `quarry-commons` repo. No service, no shared
secret — clone or pull the tree and query it locally.

```sh
git clone https://github.com/<you>/quarry-commons

# consult prior art mid-run (local, no network):
bin/quarry call investigate '{"target_file":"…","commons_tree":"./quarry-commons"}'

# query the tree directly by behavioral key:
bin/quarry call query '{"tree":"./quarry-commons","keys":["bk:…"]}'

# audit a tree before trusting or merging it (the anti-poisoning gate):
bin/quarry call commons.verify '{"dir":"./quarry-commons"}'
```

A hit is a candidate you re-ground with your own oracle; a Bloom miss is a
definitive "novel". Writes are gated by `commons.verify` in the repo's CI, not a
write key. An untrusted claim is admitted only when quarry's own oracle
independently reproduces it (`commons.ingest`), and reproducer-bearing findings
are re-vetted on an isolated Fly Machine per PoV before admission.

## 9. Seed the commons from ARVO / OSS-Fuzz

`catalog` normalizes the whole corpus into public abstracts (metadata-only, no
Docker, 0 agent calls) and writes the git-native tree deterministically. An
unchanged corpus produces no diff, so refreshes are clean commits:

```sh
bin/quarry call catalog '{"all":true,"tree":"./quarry-commons"}'
(cd ./quarry-commons && git init && git add -A && git commit -m 'catalog snapshot')
```

The reproduce path (`hydrate` with `{"arvo_all":true}`, Docker images →
self-reproducing artifacts) leaves confirmed findings in the local datastore;
those carry a reproducer and stay out of the abstracts-only public tree.

## 10. Bind a frontend (serve mode)

For anything richer than one-shot calls, run the core as a long-lived process and
speak JSON-RPC over stdio:

```sh
bin/quarry serve --principal my-frontend
# stdin  → one request object per line:  {"id":1,"op":"verify","params":{…}}
# stdout → one response per line:         {"id":1,"result":{…}}
#          plus unsolicited {"audit":…}   notifications — the live trail
```

The official web console **quarry-webui** attaches exactly this way. Any language
that can spawn a process and read/write lines can drive the full op surface;
`schema` (§2) gives it typed forms for free.

---

**Next:** [ARCHITECTURE.md](ARCHITECTURE.md) (design), [`docs/`](docs/README.md),
`bin/quarry help`.
