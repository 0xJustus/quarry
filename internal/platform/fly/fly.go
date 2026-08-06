// Package fly is a minimal Fly Machines API client for the per-PoV oneshot substrate.
package fly

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const defaultBaseURL = "https://api.machines.dev/v1"

// never 0: 0 is a verdict downstream (vault: Execution Substrate)
const ExitNoVerdict = -1

var destroyRetryDelay = 2 * time.Second

type Client struct {
	App     string
	Token   string
	BaseURL string
	HTTP    *http.Client
}

type Guest struct {
	CPUKind  string `json:"cpu_kind"` // "shared" | "performance"
	CPUs     int    `json:"cpus"`
	MemoryMB int    `json:"memory_mb"`
}

type Restart struct {
	Policy string `json:"policy"`
}

type MachineConfig struct {
	Image       string            `json:"image"`
	Env         map[string]string `json:"env,omitempty"`
	Guest       Guest             `json:"guest"`
	Restart     Restart           `json:"restart"`
	AutoDestroy bool              `json:"auto_destroy"`
	Init        *Init             `json:"init,omitempty"`
}

type Init struct {
	Entrypoint []string `json:"entrypoint,omitempty"`
	Cmd        []string `json:"cmd,omitempty"`
}

type Machine struct {
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	State     string         `json:"state"`
	CreatedAt string         `json:"created_at"` // RFC3339
	Events    []MachineEvent `json:"events"`
}

type MachineEvent struct {
	Type      string `json:"type"`
	Status    string `json:"status"`
	Timestamp int64  `json:"timestamp"`
	Request   struct {
		ExitEvent struct {
			ExitCode    *int `json:"exit_code"`
			Signal      int  `json:"signal"` // Fly reports -1 when NOT signalled
			GuestSignal int  `json:"guest_signal"`
			OOMKilled   bool `json:"oom_killed"`
		} `json:"exit_event"`
	} `json:"request"`
}

type ExitStatus struct {
	Code      int // not a verdict when Killed: Fly reports a kill with exit_code 0
	Signal    int
	OOMKilled bool
	Found     bool // an exit event carrying an exit_code was present at all
}

func (s ExitStatus) Killed() bool { return s.OOMKilled || s.Signal > 0 }

func (m Machine) ExitStatus() ExitStatus {
	var st ExitStatus
	ts := int64(-1)
	for _, e := range m.Events {
		ev := e.Request.ExitEvent
		if e.Type != "exit" || ev.ExitCode == nil || e.Timestamp < ts {
			continue
		}
		sig := ev.Signal
		if ev.GuestSignal > sig { // take the worse of the two reports
			sig = ev.GuestSignal
		}
		st, ts = ExitStatus{Code: *ev.ExitCode, Signal: sig, OOMKilled: ev.OOMKilled, Found: true}, e.Timestamp
	}
	return st
}

func (c Client) base() string {
	if c.BaseURL != "" {
		return c.BaseURL
	}
	return defaultBaseURL
}

func (c Client) httpc() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 60 * time.Second}
}

type APIError struct {
	Method, Path string
	Status       int
	Body         string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("fly: %s %s → %d: %s", e.Method, e.Path, e.Status, e.Body)
}

func (c Client) do(ctx context.Context, method, path string, body, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base()+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.httpc().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode/100 != 2 {
		return &APIError{Method: method, Path: path, Status: resp.StatusCode, Body: truncate(data, 300)}
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}

func (c Client) createMachine(ctx context.Context, name string, cfg MachineConfig) (Machine, error) {
	var m Machine
	err := c.do(ctx, http.MethodPost, "/apps/"+c.App+"/machines", map[string]any{"name": name, "config": cfg}, &m)
	return m, err
}

func (c Client) ListMachines(ctx context.Context) ([]Machine, error) {
	var out []Machine
	err := c.do(ctx, http.MethodGet, "/apps/"+c.App+"/machines", nil, &out)
	return out, err
}

func (c Client) GetMachine(ctx context.Context, id string) (Machine, error) {
	var m Machine
	err := c.do(ctx, http.MethodGet, "/apps/"+c.App+"/machines/"+id, nil, &m)
	return m, err
}

// Fly caps a single server-side wait at 60s, so timeout is clamped to [1s, 60s].
func (c Client) WaitForState(ctx context.Context, id, state string, timeout time.Duration) error {
	secs := int(timeout.Seconds())
	if secs < 1 {
		secs = 1
	}
	if secs > 60 {
		secs = 60
	}
	path := fmt.Sprintf("/apps/%s/machines/%s/wait?state=%s&timeout=%d", c.App, id, state, secs)
	return c.do(ctx, http.MethodGet, path, nil, nil)
}

func (c Client) Destroy(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/apps/"+c.App+"/machines/"+id+"?force=true", nil, nil)
}

// report the outcome: a swallowed DELETE error leaves a billable guest running
func (c Client) destroyRetry(ctx context.Context, id string) error {
	if id == "" {
		return errors.New("fly: destroy: no machine id")
	}
	var last error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return fmt.Errorf("%w (giving up: %v)", last, ctx.Err())
			case <-time.After(time.Duration(attempt) * destroyRetryDelay):
			}
		}
		err := c.Destroy(ctx, id)
		if err == nil {
			return nil
		}
		var ae *APIError
		if errors.As(err, &ae) && ae.Status == http.StatusNotFound {
			return nil // already gone: cleanup satisfied
		}
		last = err
	}
	return last
}

// fresh context: the lost-create path that needs this has no live context left
func (c Client) reapByName(name string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ms, err := c.ListMachines(ctx)
	if err != nil {
		return "", err
	}
	for _, m := range ms {
		if m.Name == name {
			return m.ID, c.destroyRetry(ctx, m.ID)
		}
	}
	return "", nil
}

const oneshotNamePrefix = "quarry-oneshot-"

func oneshotName() string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%s%d", oneshotNamePrefix, time.Now().UnixNano())
	}
	return oneshotNamePrefix + hex.EncodeToString(b[:])
}

// the bound is what keeps the sweep off a concurrent run's unread Machine
const abandonedAfter = 6 * time.Hour

func (c Client) ReapAbandoned(ctx context.Context) ([]string, error) {
	ms, err := c.ListMachines(ctx)
	if err != nil {
		return nil, err
	}
	var reaped []string
	var errs []error
	for _, m := range ms {
		if !strings.HasPrefix(m.Name, oneshotNamePrefix) || !m.olderThan(abandonedAfter) {
			continue
		}
		if derr := c.destroyRetry(ctx, m.ID); derr != nil {
			errs = append(errs, derr)
			continue
		}
		reaped = append(reaped, m.ID)
	}
	return reaped, errors.Join(errs...)
}

func (m Machine) olderThan(d time.Duration) bool {
	t, err := time.Parse(time.RFC3339, m.CreatedAt)
	if err != nil {
		return false // fail closed: an undatable Machine is never old enough
	}
	return time.Since(t) > d
}

// Every error path returns ExitNoVerdict, never a code that reads as a verdict.
func (c Client) RunOneshot(ctx context.Context, cfg MachineConfig, waitTimeout time.Duration) (code int, mach Machine, err error) {
	cfg.Restart.Policy = "no"
	// off: Fly's reaper is free to delete the exit event that carries the verdict
	cfg.AutoDestroy = false
	// best effort: a sweep of somebody else's leftovers must never fail this run
	_, _ = c.ReapAbandoned(ctx)
	name := oneshotName()
	m, err := c.createMachine(ctx, name, cfg)
	if err != nil {
		// POST may have created the Machine before the response was lost; the pre-chosen name makes that stray findable
		id, rerr := c.reapByName(name)
		switch {
		case id != "" && rerr == nil:
			err = fmt.Errorf("fly: create machine: %w (a stray Machine %s from the lost request was destroyed)", err, id)
		case id != "":
			err = fmt.Errorf("fly: create machine: %w (stray Machine %s from the lost request could NOT be destroyed and is still billable: %v)", err, id, rerr)
		case rerr != nil:
			err = fmt.Errorf("fly: create machine: %w (could not check for a stray Machine named %s: %v — verify with `fly machines list`)", err, name, rerr)
		}
		return ExitNoVerdict, m, err
	}
	defer func() {
		rmCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if derr := c.destroyRetry(rmCtx, m.ID); derr != nil {
			// never report clean when the promised cleanup did not happen
			leak := fmt.Errorf("fly: machine %s NOT destroyed (still billable — destroy it manually): %w", m.ID, derr)
			if err == nil {
				err = leak
			} else {
				err = fmt.Errorf("%w; also: %v", err, leak)
			}
		}
	}()
	deadline := time.Now().Add(waitTimeout)
	for {
		got, err := c.GetMachine(ctx, m.ID)
		if err != nil {
			return ExitNoVerdict, m, err
		}
		if got.State == "stopped" || got.State == "destroyed" {
			st := got.ExitStatus()
			switch {
			case !st.Found:
				return ExitNoVerdict, got, fmt.Errorf("fly: machine %s %s with no exit code in events", got.ID, got.State)
			case st.Killed():
				// killed is never a verdict: Fly reports it with exit_code 0
				return ExitNoVerdict, got, fmt.Errorf("fly: machine %s produced NO verdict: killed (signal=%d oom_killed=%v, fly reported exit_code=%d)",
					got.ID, st.Signal, st.OOMKilled, st.Code)
			}
			return st.Code, got, nil
		}
		if time.Now().After(deadline) {
			return ExitNoVerdict, got, fmt.Errorf("fly: machine %s did not stop within %s (state=%s)", m.ID, waitTimeout, got.State)
		}
		per := time.Until(deadline)
		if per > 55*time.Second {
			per = 55 * time.Second
		}
		_ = c.WaitForState(ctx, m.ID, "stopped", per)
	}
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "…"
}

type NetworkPolicy struct {
	ID       string         `json:"id,omitempty"`
	Name     string         `json:"name"`
	Selector map[string]any `json:"selector"`
	Rules    []PolicyRule   `json:"rules"`
}

// any egress rule flips egress to deny-by-default; Fly has no "deny" action
type PolicyRule struct {
	Action    string       `json:"action"`
	Direction string       `json:"direction"`
	Ports     []PolicyPort `json:"ports"`
}

type PolicyPort struct {
	Protocol string `json:"protocol"` // Fly requires protocol and port per entry
	Port     int    `json:"port"`
}

const EgressDenyPolicyName = "quarry-pov-egress-deny"

// Fly requires >=1 allowed port, so true zero-egress is not expressible.
const egressResidualPort = 9999

func (c Client) ListNetworkPolicies(ctx context.Context) ([]NetworkPolicy, error) {
	var out []NetworkPolicy
	err := c.do(ctx, http.MethodGet, "/apps/"+c.App+"/network_policies", nil, &out)
	return out, err
}

// Apply before the first dispatch: policy changes propagate with a few-second delay.
func (c Client) EnsureEgressDenyPolicy(ctx context.Context) error {
	existing, err := c.ListNetworkPolicies(ctx)
	if err != nil {
		return fmt.Errorf("fly: list network policies: %w", err)
	}
	for _, p := range existing {
		if p.Name == EgressDenyPolicyName {
			return nil
		}
	}
	pol := NetworkPolicy{
		Name:     EgressDenyPolicyName,
		Selector: map[string]any{"all": true},
		Rules: []PolicyRule{{
			Action: "allow", Direction: "egress",
			Ports: []PolicyPort{{Protocol: "tcp", Port: egressResidualPort}},
		}},
	}
	if err := c.do(ctx, http.MethodPost, "/apps/"+c.App+"/network_policies", pol, nil); err != nil {
		return fmt.Errorf("fly: apply egress-deny policy: %w", err)
	}
	return nil
}
