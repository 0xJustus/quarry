// Package flywheel turns recorded discovery trajectories into training datasets.
package flywheel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"

	"github.com/0xjustus/quarry/internal/platform/store"
)

// keep in sync with store.TrajectoryEvent
type Event struct {
	Seq     int             `json:"seq"`
	Kind    string          `json:"kind"` // action | observation | verdict | note
	Actor   string          `json:"actor"`
	Payload json.RawMessage `json:"payload"`
}

type Trajectory struct {
	RunID     string  `json:"run_id"`
	Objective string  `json:"objective"`
	TargetRef string  `json:"target_ref"`
	Events    []Event `json:"events"`
	Verdict   string  `json:"verdict,omitempty"`
	// oracle-derived, metadata only: the exporter never invents it
	Reward float64 `json:"reward,omitempty"`
}

type Message struct {
	Role    string `json:"role"` // system | user | assistant | tool
	Content string `json:"content"`
}

type SFTSample struct {
	Messages []Message         `json:"messages"`
	Meta     map[string]string `json:"meta,omitempty"`
}

type TrainMethod string

const (
	MethodSFT    TrainMethod = "sft"
	MethodDistil TrainMethod = "distil"
	MethodRLVR   TrainMethod = "rlvr"
)

type TrainSpec struct {
	Method      TrainMethod
	DatasetPath string
	BaseModel   string
	OutDir      string
}

type TrainResult struct {
	Method   TrainMethod
	ModelRef string
	Samples  int
	Notes    string
}

type TrainingPipeline interface {
	Ingest(ctx context.Context, t Trajectory) error
	Export(ctx context.Context, opts ExportOptions) (Report, error)
}

type Trainer interface {
	Train(ctx context.Context, spec TrainSpec) (*TrainResult, error)
}

var ErrTrainerUnconfigured = errors.New("flywheel: training backend not configured")

// the honest default: never claims a job ran
type UnconfiguredTrainer struct{}

func (UnconfiguredTrainer) Train(context.Context, TrainSpec) (*TrainResult, error) {
	return nil, ErrTrainerUnconfigured
}

type ExportOptions struct {
	Path          string
	MinEvents     int  // 0 keeps everything
	ConfirmedOnly bool // keep only Reward > 0
}

type Report struct {
	Path     string `json:"path"`
	Samples  int    `json:"samples"`
	Skipped  int    `json:"skipped"`
	Ingested int    `json:"ingested"`
	// events of a kind roleFor cannot map: reported, never silently swallowed
	DroppedEvents int `json:"dropped_events,omitempty"`
}

type LocalExporter struct {
	trajectories []Trajectory
}

func NewLocalExporter() *LocalExporter { return &LocalExporter{} }

func (e *LocalExporter) Ingest(_ context.Context, t Trajectory) error {
	if t.RunID == "" {
		return fmt.Errorf("flywheel: ingest: trajectory has no run id")
	}
	e.trajectories = append(e.trajectories, t)
	return nil
}

func (e *LocalExporter) IngestStoreRun(ctx context.Context, runID, objective, targetRef, verdict string, reward float64, events []store.TrajectoryEvent) error {
	t := Trajectory{RunID: runID, Objective: objective, TargetRef: targetRef, Verdict: verdict, Reward: reward}
	for _, ev := range events {
		t.Events = append(t.Events, Event{Seq: ev.Seq, Kind: ev.Kind, Actor: ev.Actor, Payload: ev.Payload})
	}
	return e.Ingest(ctx, t)
}

func (e *LocalExporter) Len() int { return len(e.trajectories) }

func (e *LocalExporter) Export(ctx context.Context, opts ExportOptions) (Report, error) {
	rep := Report{Path: opts.Path, Ingested: len(e.trajectories)}
	if opts.Path == "" {
		return rep, fmt.Errorf("flywheel: export: output path is required")
	}
	f, err := os.Create(opts.Path)
	if err != nil {
		return rep, fmt.Errorf("flywheel: export: %w", err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	for _, t := range e.trajectories {
		if err := ctx.Err(); err != nil {
			return rep, err
		}
		if len(t.Events) < opts.MinEvents {
			rep.Skipped++
			continue
		}
		if opts.ConfirmedOnly && t.Reward <= 0 {
			rep.Skipped++
			continue
		}
		for _, ev := range t.Events {
			if roleFor(ev.Kind) == "" {
				rep.DroppedEvents++
			}
		}
		sample := ToSFTSample(t)
		// count learnable turns: len(Messages)==0 can never fire, the system turn is always prepended
		if contentTurns(sample) == 0 {
			rep.Skipped++
			continue
		}
		if err := enc.Encode(sample); err != nil {
			return rep, fmt.Errorf("flywheel: export: encode %s: %w", t.RunID, err)
		}
		rep.Samples++
	}
	return rep, nil
}

func ToSFTSample(t Trajectory) SFTSample {
	events := append([]Event(nil), t.Events...)
	sort.SliceStable(events, func(i, j int) bool { return events[i].Seq < events[j].Seq })

	msgs := make([]Message, 0, len(events)+1)
	sys := "You are a vulnerability-discovery agent."
	if t.Objective != "" {
		sys += " Objective: " + t.Objective
	}
	if t.TargetRef != "" {
		sys += " Target: " + t.TargetRef
	}
	msgs = append(msgs, Message{Role: "system", Content: sys})

	for _, ev := range events {
		role := roleFor(ev.Kind)
		if role == "" {
			continue
		}
		msgs = append(msgs, Message{Role: role, Content: payloadText(ev.Payload)})
	}

	meta := map[string]string{"run_id": t.RunID}
	if t.Verdict != "" {
		meta["verdict"] = t.Verdict
	}
	if t.Reward != 0 {
		meta["reward"] = fmt.Sprintf("%g", t.Reward)
	}
	return SFTSample{Messages: msgs, Meta: meta}
}

func contentTurns(s SFTSample) int {
	n := 0
	for _, m := range s.Messages {
		if m.Role != "system" {
			n++
		}
	}
	return n
}

func roleFor(kind string) string {
	switch kind {
	case "action", "verdict":
		return "assistant"
	case "observation":
		return "tool"
	case "note":
		return "user"
	default:
		return ""
	}
}

func payloadText(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	return string(raw)
}
