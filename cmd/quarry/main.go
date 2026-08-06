package main

import (
	"fmt"
	"os"
)

const version = "0.2.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = cmdServe(os.Args[2:])
	case "call":
		err = cmdCall(os.Args[2:])
	case "audit":
		err = cmdAudit(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Printf("quarry %s\n", version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q (quarry is a core: use `serve`, `call`, or `audit`)\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "quarry: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `quarry — agent-native vulnerability discovery + verification, as an embeddable CORE.

The per-command CLI is gone: quarry is a core with a bindable interface. A Go frontend imports
internal/core; any other frontend speaks JSON-RPC over stdio to 'quarry serve'. Every access,
action, and side-effect is recorded in a hash-chained, tamper-evident audit log.

USAGE:
  quarry serve  [--audit PATH] [--principal ID] [--audit-sink PATH]
        Run the core over stdio JSON-RPC. Write one request object per line to stdin; read one
        response per line from stdout, plus unsolicited {"audit":…} notifications (the live trail).
        Request:  {"id":1,"op":"verify","params":{…}}
        Response: {"id":1,"result":{…}}  or  {"id":1,"error":"…"}
        Send {"op":"ops"} for the list of operations.

  quarry call   OP [JSON-PARAMS] [--audit PATH] [--principal ID]
        One-shot client: dispatch a single op and print the JSON result. e.g.
        quarry call ops
        quarry call verify '{"target_file":"quarry.yaml","pov":"<base64>"}'

  quarry audit  verify PATH
        Walk the hash-chained audit trail; report intact / broken-at-seq.

  quarry version

The agent proposes; only the oracle disposes. Every action is on the record.
`)
}
