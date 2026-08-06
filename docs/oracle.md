# The oracle

The oracle turns a program run into a pass or fail verdict. It is the source of
truth in quarry: the agent proposes an input, the runner executes the target, and
the oracle decides whether the result is a real finding.

## The run result

Every execution produces a `RunResult`:

- `term_signal`: the signal that killed the process, or 0.
- `exit_code`: the process exit code, meaningful only when there was no signal.
- `stdout`, `stderr`: captured, with a size cap and a truncation marker.
- `sanitizer`: a parsed AddressSanitizer, UBSan, MSan, or TSan report (bug class,
  crash site, call-ordered frames).
- `timed_out`: whether the run hit the wall-clock cap.

## The spec

A `Spec` is an `any` or `all` set of conditions, plus an optional differential
clause.

| Condition | Matches |
|---|---|
| `sanitizer` | a fired sanitizer report, optionally filtered by tool, bug class, or crash site |
| `signal` | the terminating signal is in a set, for example SIGSEGV or SIGABRT |
| `exit` | the exit code matches |
| `output` | a regex over stdout, stderr, or either |
| `timeout` | the run timed out (a hang or DoS) |

The differential clause runs the candidate against both a vulnerable and a fixed
build, and passes only when it triggers on the vulnerable one and not the fixed
one. This is how ARVO-style reproducers are verified.

## Corroboration

A sanitizer report is trusted only when the process also died from a real
memory-safety fault: a crash signal (SIGSEGV, SIGABRT, SIGBUS, SIGFPE, or SIGILL).
A report that fires while the process exits cleanly, exits non-zero, is killed by a
target-controllable signal (SIGALRM, SIGPIPE, or a SIGKILL out-of-memory kill), or
merely times out is dropped. Those are all outcomes the target can manufacture, so a
fabricated `AddressSanitizer` line printed before a clean exit does not confirm a bug.
This is the property that makes the verdict un-forgeable, and it is why quarry can
filter fabricated reports without a model in the loop.

Sanitizers are pinned to abort on error, so a genuine MSan, TSan, or UBSan violation
raises SIGABRT and corroborates instead of exiting quietly and being dropped.

A hang is a separate verdict (the timeout condition), not a corroborated report. A
re-run confirms the hang on any timeout and demotes it only if every re-run completes,
so a nondeterministic deadlock is not lost to a single lucky completion.

## Verdict patterns

A crash is not the only shape a verdict can take. The same conditions compose into
non-crash oracles, each built from the primitives above.

### Differential (crash on vuln, clean on fixed)

The differential clause evaluates the full condition set against both a vulnerable and
a fixed build, and passes only when the conditions hold on the vulnerable build and
fail on the fixed one. A missing fixed run is never a pass. This wraps any condition
set, not just crash signals, so an `output` or `exit` pattern is made vuln-specific by
the same clause.

### Capture the flag (success token)

An `output` condition matches a regex over `stdout`, `stderr`, or either. Point it at a
canary or flag string that only a successful exploit can print:

```yaml
- { type: output, stream: stdout, regex: "FLAG\\{.*\\}" }
```

Add an `exit_code` matcher to require a specific clean termination alongside the token.
If the run is killed by a signal the exit code is treated as meaningless and the
condition fails, so a signal-death cannot forge a clean-exit token match:

```yaml
- { type: output, stream: stdout, regex: "pwned", exit_code: { eq: 0 } }
```

The CLI shortcut form is `output:stdout:REGEX`. The leading token is read as a stream
only when it is `stdout`, `stderr`, or `any`; otherwise the whole clause is the regex
and the stream defaults to either.

### Operator invariant assertions

An invariant checked inside the target with `if (violated) abort()`, or a plain
`assert`, raises SIGABRT, so it reduces to the crash case. Turn the invariant into a
verdict with a signal condition:

```yaml
- { type: signal, signals: ["SIGABRT"] }
```

SIGABRT is a crash signal, so this also carries a sanitizer report through
corroboration and composes with the differential clause. A sanitizer pinned to abort on
error (MSan, TSan, UBSan) reaches the verdict by the same path.

### Sink reached with taint (injection class)

There is no dataflow or taint-tracking condition. The pattern is expressed by
instrumenting the sink itself: when tainted input reaches it, have the target print a
canary and match it with an `output` condition, or call `abort()` and match it with a
`signal` condition on SIGABRT. Both reduce to the patterns above. A first-class taint
condition is not yet supported.

## Writing a target

A target descriptor (`quarry.yaml`) says how to build or run the target, and
carries its oracle. The `{poc}` token is replaced with the candidate input path.

```yaml
target:
  name: my-parser
  ingest: { kind: dockerfile, path: ., dockerfile: Dockerfile }
  run: { argv: ["/harness", "{poc}"], sanitizer: asan, timeout_s: 30 }
  oracle:
    require: any
    conditions:
      - { type: sanitizer, tool: asan }
      - { type: signal, signals: ["SIGSEGV", "SIGABRT", "SIGBUS"] }
```

Ingest kinds: `binary` (a prebuilt executable), `local` (a directory plus a build
command), `dockerfile` (build an image), and `image` (a prebuilt image). A
white-box `source_dir` can be seeded into the agent workspace for reasoning.
