# quarry

Quarry finds and verifies vulnerabilities in native targets. An agent proposes
candidate inputs, and a deterministic oracle confirms a bug by re-executing the
target and requiring a real crash or hang. A sanitizer report only counts when the
process actually aborts, so fabricated reports are rejected.

## Install

Requires Go 1.26 or newer.

```sh
make build   # builds bin/quarry (pure Go, no cgo)
make test
```

## Usage

quarry is an embeddable core, not a per-command CLI: `quarry call OP '<json>'`
dispatches one operation, `quarry serve` runs it over stdio JSON-RPC for a
frontend, and `quarry audit verify` walks the tamper-evident trail. `quarry call ops`
lists every op; `quarry call schema '{"op":"verify"}'` gives its typed params.

Verify a candidate proof-of-vulnerability. Offline, no model or key needed
(a `confirmed` field in the JSON result is the verdict):

```sh
POV=$(base64 < ./candidate.bin | tr -d '\n')
bin/quarry call verify "{\"target_file\":\"quarry.yaml\",\"pov\":\"$POV\"}"
```

Feed that verdict JSON to the `report` op to emit a SARIF bug candidate.

Run the discovery agent (needs model access via `QUARRY_API_KEY` / `QUARRY_MODEL`):

```sh
export QUARRY_API_KEY=...
bin/quarry call investigate '{"target_file":"quarry.yaml","analyst":true}'
```

Query the commons, a content-addressed store of verified crash abstracts:

```sh
bin/quarry call commons.verify '{"dir":"./quarry-commons"}'
bin/quarry call query '{"tree":"./quarry-commons","keys":["bk:..."]}'
```

## Documentation

- [QUICKSTART.md](QUICKSTART.md) for a full walk-through
- [ARCHITECTURE.md](ARCHITECTURE.md) for the design and current status
- [docs/](docs/) for the oracle and how to write a target

## License

[Apache 2.0](LICENSE). Copyright 2026 Justus Johnson.
