package broker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"
)

type Status string

const (
	StatusPending  Status = "pending"
	StatusRunning  Status = "running"
	StatusDone     Status = "done"
	StatusError    Status = "error"
	StatusCanceled Status = "canceled"
)

func (s Status) Terminal() bool {
	return s == StatusDone || s == StatusError || s == StatusCanceled
}

// Runner MUST honor ctx cancellation, or Cancel cannot stop a job.
type Runner interface {
	Run(ctx context.Context, tool string, args json.RawMessage) (string, error)
}

type RunnerFunc func(ctx context.Context, tool string, args json.RawMessage) (string, error)

func (f RunnerFunc) Run(ctx context.Context, tool string, args json.RawMessage) (string, error) {
	return f(ctx, tool, args)
}

type Result struct {
	ExecutionID string
	Tool        string
	Role        string
	Status      Status
	Output      string // capped; valid only once Status==done
	Error       string // set only when Status==error
	Submitted   time.Time
	Finished    time.Time // zero until terminal
}

type job struct {
	mu     sync.Mutex
	res    Result
	cancel context.CancelFunc
}

// Broker is the in-process, role-filtered async tool endpoint. Safe for concurrent use.
type Broker struct {
	catalog    Catalog
	runner     Runner
	defaultCap int
	jobTTL     time.Duration
	maxJobs    int
	now        func() time.Time

	mu   sync.Mutex
	jobs map[string]*job
}

// Options tunes a Broker. Zero values fall back to defaults.
type Options struct {
	DefaultCap int // per-job output cap when a tool sets none; 0 ⇒ 64 KiB
	// 0 ⇒ 15 min. A reaped id polls as UNKNOWN, never as an empty success.
	JobTTL time.Duration
	// 0 ⇒ 4096. Over the cap the oldest-FINISHED terminal jobs go first.
	MaxJobs int
}

// A nil runner makes Submit fail fast (pure list/describe scaffolding).
func New(catalog Catalog, runner Runner, opts Options) *Broker {
	cap := opts.DefaultCap
	if cap <= 0 {
		cap = 64 << 10
	}
	ttl := opts.JobTTL
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	maxJobs := opts.MaxJobs
	if maxJobs <= 0 {
		maxJobs = 4096
	}
	return &Broker{
		catalog:    catalog,
		runner:     runner,
		defaultCap: cap,
		jobTTL:     ttl,
		maxJobs:    maxJobs,
		now:        time.Now,
		jobs:       map[string]*job{},
	}
}

func (b *Broker) SetClock(now func() time.Time) { b.now = now }

func (b *Broker) clock() time.Time {
	if b.now == nil {
		return time.Now()
	}
	return b.now()
}

// role "" ⇒ every tool
func (b *Broker) ListTools(role string) []Tool { return b.catalog.ForRole(role) }

// must not leak the existence of a role-gated tool
func (b *Broker) DescribeTool(role, name string) (Tool, bool) {
	for _, t := range b.catalog.ForRole(role) {
		if t.Name == name {
			return t, true
		}
	}
	return Tool{}, false
}

// Submit enforces role visibility up front, then runs on a goroutine; poll the id.
func (b *Broker) Submit(ctx context.Context, role, tool string, args json.RawMessage) (string, error) {
	if b.runner == nil {
		return "", fmt.Errorf("broker: no runner configured")
	}
	spec, ok := b.DescribeTool(role, tool)
	if !ok {
		// unknown and role-hidden are indistinguishable by design
		return "", fmt.Errorf("broker: tool %q not available to role %q", tool, role)
	}

	cap := spec.OutputCap
	if cap <= 0 {
		cap = b.defaultCap
	}

	id := newExecID()
	runCtx, cancel := context.WithCancel(ctx)
	j := &job{
		res: Result{
			ExecutionID: id,
			Tool:        tool,
			Role:        role,
			Status:      StatusPending,
			Submitted:   b.clock().UTC(),
		},
		cancel: cancel,
	}

	b.mu.Lock()
	b.jobs[id] = j
	b.mu.Unlock()
	b.reap()

	go func() {
		// release on EVERY exit path: the parent is a long-lived session ctx
		defer cancel()
		b.run(runCtx, j, tool, args, cap)
	}()
	return id, nil
}

// reap drops terminal jobs past jobTTL, then oldest-finished until maxJobs fits; never in-flight.
func (b *Broker) reap() {
	cutoff := b.clock().UTC().Add(-b.jobTTL)
	b.mu.Lock()
	defer b.mu.Unlock()

	// lock order everywhere in this file: b.mu → job.mu
	type aged struct {
		id       string
		finished time.Time
	}
	var terminal []aged
	for id, j := range b.jobs {
		j.mu.Lock()
		done, fin := j.res.Status.Terminal(), j.res.Finished
		j.mu.Unlock()
		if !done {
			continue
		}
		if fin.Before(cutoff) {
			delete(b.jobs, id)
			continue
		}
		terminal = append(terminal, aged{id: id, finished: fin})
	}
	over := len(b.jobs) - b.maxJobs
	if over <= 0 {
		return
	}
	sort.Slice(terminal, func(i, k int) bool { return terminal[i].finished.Before(terminal[k].finished) })
	for i := 0; i < len(terminal) && i < over; i++ {
		delete(b.jobs, terminal[i].id)
	}
}

func (b *Broker) run(ctx context.Context, j *job, tool string, args json.RawMessage, cap int) {
	j.mu.Lock()
	if j.res.Status == StatusCanceled {
		j.mu.Unlock()
		return
	}
	j.res.Status = StatusRunning
	j.mu.Unlock()

	out, err := b.runner.Run(ctx, tool, args)

	j.mu.Lock()
	defer j.mu.Unlock()
	if j.res.Status == StatusCanceled {
		return // Cancel won the race; don't overwrite the terminal state.
	}
	j.res.Finished = b.clock().UTC()
	if err != nil {
		j.res.Status = StatusError
		j.res.Error = err.Error()
		return
	}
	j.res.Status = StatusDone
	j.res.Output = capString(out, cap)
}

// ok is false for an unknown execution_id.
func (b *Broker) Poll(execID string) (Result, bool) {
	b.mu.Lock()
	j, ok := b.jobs[execID]
	b.mu.Unlock()
	if !ok {
		return Result{}, false
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.res, true
}

// Cancel errors on an unknown id; canceling an already-terminal job is a no-op.
func (b *Broker) Cancel(execID string) error {
	b.mu.Lock()
	j, ok := b.jobs[execID]
	b.mu.Unlock()
	if !ok {
		return fmt.Errorf("broker: unknown execution_id %q", execID)
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.res.Status.Terminal() {
		return nil
	}
	j.res.Status = StatusCanceled
	j.res.Finished = b.clock().UTC()
	j.cancel()
	return nil
}

func newExecID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return "exec_" + hex.EncodeToString(b[:])
}

// max<=0 ⇒ uncapped
func capString(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	return s[:max] + "\n…[truncated]…"
}
