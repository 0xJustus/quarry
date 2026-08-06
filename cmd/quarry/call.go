package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/0xjustus/quarry/internal/core"
	"github.com/0xjustus/quarry/internal/core/corerpc"
	"github.com/0xjustus/quarry/internal/platform/audit"
	"github.com/0xjustus/quarry/internal/platform/config"
)

func cmdCall(args []string) error {
	var flagArgs, positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			flagArgs = append(flagArgs, a)
			if !strings.Contains(a, "=") && i+1 < len(args) {
				flagArgs = append(flagArgs, args[i+1])
				i++
			}
			continue
		}
		positional = append(positional, a)
	}
	fs := flag.NewFlagSet("call", flag.ContinueOnError)
	auditPath := fs.String("audit", "quarry-audit.jsonl", "hash-chained audit log path")
	principal := fs.String("principal", "cli", "caller principal recorded in the audit trail")
	if err := fs.Parse(flagArgs); err != nil {
		return err
	}
	if len(positional) == 0 {
		return fmt.Errorf("call: usage: quarry call OP [JSON-PARAMS] [--audit PATH] [--principal ID]")
	}
	op := positional[0]
	params := json.RawMessage("{}")
	if len(positional) > 1 && positional[1] != "" {
		if !json.Valid([]byte(positional[1])) {
			return fmt.Errorf("call: JSON-PARAMS is not valid JSON")
		}
		params = json.RawMessage(positional[1])
	}

	log, err := audit.Open(*auditPath, audit.WithPrincipal(*principal))
	if err != nil {
		return fmt.Errorf("call: open audit log: %w", err)
	}
	defer log.Close()
	eng, err := core.New(config.Defaults(), log)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	resp := corerpc.NewServer(eng).Dispatch(ctx, corerpc.Request{ID: 1, Op: op, Params: params})
	if resp.Error != "" {
		return fmt.Errorf("%s", resp.Error)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(resp.Result)
}
