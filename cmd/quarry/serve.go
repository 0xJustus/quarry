package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/0xjustus/quarry/internal/core"
	"github.com/0xjustus/quarry/internal/core/corerpc"
	"github.com/0xjustus/quarry/internal/platform/audit"
	"github.com/0xjustus/quarry/internal/platform/config"
)

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	auditPath := fs.String("audit", "quarry-audit.jsonl", "hash-chained audit log path (append-only; resumes across restarts)")
	principal := fs.String("principal", "", "default caller principal when a request omits one")
	sinkPath := fs.String("audit-sink", "", "ALSO stream every audit entry to this file/FIFO (an external SIEM/collector fd)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	opts := []audit.Option{}
	if *principal != "" {
		opts = append(opts, audit.WithPrincipal(*principal))
	}
	var sinkFile *os.File
	if *sinkPath != "" {
		f, err := os.OpenFile(*sinkPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return fmt.Errorf("serve: open --audit-sink: %w", err)
		}
		sinkFile = f
		opts = append(opts, audit.WithSink(audit.WriterSink{W: f}))
	}
	log, err := audit.Open(*auditPath, opts...)
	if err != nil {
		return fmt.Errorf("serve: open audit log: %w", err)
	}
	defer log.Close()
	if sinkFile != nil {
		defer sinkFile.Close()
	}

	eng, err := core.New(config.Defaults(), log)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Fprintf(os.Stderr, "quarry core: serving JSON-RPC on stdio (audit → %s)\n", *auditPath)
	return corerpc.NewServer(eng).Serve(ctx, os.Stdin, os.Stdout)
}

func cmdAudit(args []string) error {
	if len(args) < 2 || args[0] != "verify" {
		return fmt.Errorf("audit: usage: quarry audit verify <path>")
	}
	rep, err := audit.VerifyFile(args[1])
	if err != nil {
		return fmt.Errorf("audit verify: %w", err)
	}
	if rep.OK {
		fmt.Printf("audit chain INTACT: %d entries, no breaks\n", rep.Entries)
		return nil
	}
	return fmt.Errorf("audit chain BROKEN at seq %d: %s (%d entries verified before the break)", rep.Broken, rep.Reason, rep.Entries)
}
