// Package autovet re-verifies an allowlist of artifacts on the per-PoV substrate.
package autovet

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
)

type Entry struct {
	ID        string   `yaml:"id" json:"id"`
	Image     string   `yaml:"image" json:"image"`
	Binary    string   `yaml:"binary" json:"binary"`
	Argv      []string `yaml:"argv" json:"argv"`
	NoPoV     bool     `yaml:"nopov" json:"nopov"`
	Sanitizer string   `yaml:"sanitizer" json:"sanitizer"`
}

// Status is three-way, not a bool: only an observed run may admit or reject.
type Status string

const (
	StatusAdmitted Status = "admitted"
	StatusRejected Status = "rejected"
	// StatusInconclusive: nothing was observed — neither an admit nor a reject
	StatusInconclusive Status = "inconclusive"
)

type Verdict struct {
	Status   Status
	ExitCode int
	Detail   string
}

type Dispatcher interface {
	Dispatch(ctx context.Context, e Entry) (Verdict, error)
}

type Result struct {
	ID     string `json:"id"`
	Status Status `json:"status"`
	// pointer: nil means nothing ran, and 0 is the dispatcher's ADMITTED code
	ExitCode *int   `json:"exit_code,omitempty"`
	Err      string `json:"error,omitempty"`
}

func (r Result) Admitted() bool { return r.Status == StatusAdmitted }

func (r Result) Observed() bool {
	return r.Status == StatusAdmitted || r.Status == StatusRejected
}

func Run(ctx context.Context, d Dispatcher, entries []Entry) []Result {
	out := make([]Result, 0, len(entries))
	for _, e := range entries {
		// an entry we never sent is not an observation: stop, do not emit a row
		if ctx.Err() != nil {
			break
		}
		r := Result{ID: e.ID, Status: StatusInconclusive}
		v, err := d.Dispatch(ctx, e)
		switch {
		case err != nil:
			r.Err = err.Error()
		case v.Status == StatusAdmitted || v.Status == StatusRejected:
			code := v.ExitCode
			r.Status, r.ExitCode = v.Status, &code
		default: // no status at all: fail closed
			r.Err = v.Detail
			if r.Err == "" {
				r.Err = "dispatcher returned no verdict status; nothing observed"
			}
		}
		out = append(out, r)
	}
	return out
}

func Summary(rs []Result) (admitted, rejected, inconclusive int) {
	for _, r := range rs {
		switch r.Status {
		case StatusAdmitted:
			admitted++
		case StatusRejected:
			rejected++
		default:
			inconclusive++
		}
	}
	return
}

// WriteLedger appends to <tree>/views/vetd-verdicts.jsonl; `at` is an RFC3339 stamp.
func WriteLedger(treeDir, at string, rs []Result) error {
	dir := filepath.Join(treeDir, "views")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(dir, "vetd-verdicts.jsonl"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, r := range rs {
		status := r.Status
		if status == "" {
			status = StatusInconclusive
		}
		row := map[string]any{"id": r.ID, "status": string(status), "at": at}
		// observed rows only: else an infra failure reads as a rejection
		if r.Observed() {
			row["admitted"] = r.Admitted()
			if r.ExitCode != nil {
				row["exit_code"] = *r.ExitCode
			}
		}
		if r.Err != "" {
			row["error"] = r.Err
		}
		if err := enc.Encode(row); err != nil {
			return err
		}
	}
	return nil
}
