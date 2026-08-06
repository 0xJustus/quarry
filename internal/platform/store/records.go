package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/0xjustus/quarry/internal/publish/artifact"
	"github.com/0xjustus/quarry/internal/verdict/oracle"
)

const (
	HypActive    = "active"
	HypConfirmed = "confirmed"
	HypRefuted   = "refuted"
	HypExhausted = "exhausted"
)

const (
	TagFact        = "fact"
	TagObservation = "observation"
)

type Run struct {
	ID        string
	Objective string
	TargetRef string
	Mode      string
	Status    string
}

type Hypothesis struct {
	ID          string
	RunID       string
	ParentID    string
	Statement   string
	State       string
	BudgetLimit int
	BudgetSpent int
	WhyRefuted  string
}

type Entry struct {
	ID           string
	RunID        string
	HypothesisID string
	Tag          string
	Kind         string
	Value        string
}

type ExperimentInput struct {
	RunID        string
	HypothesisID string
	Kind         string
	Model        string
	ToolHashes   []string
	PoCBlob      string
	Spec         oracle.Spec
	Primary      oracle.RunResult
	Fixed        *oracle.RunResult
	Verdict      oracle.Verdict
}

const hypSelect = `SELECT id,run_id,COALESCE(parent_id,''),statement,state,budget_limit,budget_spent,COALESCE(why_refuted,'')
	 FROM hypotheses`

const entrySelect = `SELECT id,run_id,COALESCE(hypothesis_id,''),tag,kind,value FROM entries`

func (s *Store) CreateRun(ctx context.Context, objective, targetRef, mode string) (*Run, error) {
	r := &Run{ID: newID("run"), Objective: objective, TargetRef: targetRef, Mode: mode, Status: "active"}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO runs(id,objective,target_ref,mode,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?)`,
		r.ID, objective, targetRef, mode, r.Status, s.ts(), s.ts())
	if err != nil {
		return nil, fmt.Errorf("store: create run: %w", err)
	}
	return r, nil
}

func (s *Store) FinishRun(ctx context.Context, runID, status string, verdict any) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE runs SET status=?, verdict=?, updated_at=? WHERE id=?`,
		status, mustJSON(verdict), s.ts(), runID)
	return err
}

func (s *Store) AddHypothesis(ctx context.Context, runID, parentID, statement string, budgetLimit int) (*Hypothesis, error) {
	h := &Hypothesis{ID: newID("hyp"), RunID: runID, ParentID: parentID, Statement: statement, State: HypActive, BudgetLimit: budgetLimit}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO hypotheses(id,run_id,parent_id,statement,state,budget_limit,budget_spent,created_at,updated_at)
		 VALUES(?,?,?,?,?,?,0,?,?)`,
		h.ID, runID, nullable(parentID), statement, HypActive, budgetLimit, s.ts(), s.ts())
	if err != nil {
		return nil, fmt.Errorf("store: add hypothesis: %w", err)
	}
	return h, nil
}

func (s *Store) SetHypothesisState(ctx context.Context, id, state, whyRefuted string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE hypotheses SET state=?, why_refuted=?, updated_at=? WHERE id=?`,
		state, whyRefuted, s.ts(), id)
	return err
}

func (s *Store) AddHypothesisSpend(ctx context.Context, id string, delta int) (int, error) {
	if _, err := s.db.ExecContext(ctx,
		`UPDATE hypotheses SET budget_spent = budget_spent + ?, updated_at=? WHERE id=?`,
		delta, s.ts(), id); err != nil {
		return 0, err
	}
	var spent int
	err := s.db.QueryRowContext(ctx, `SELECT budget_spent FROM hypotheses WHERE id=?`, id).Scan(&spent)
	return spent, err
}

func (s *Store) ActiveHypotheses(ctx context.Context, runID string) ([]Hypothesis, error) {
	rows, err := s.db.QueryContext(ctx, hypSelect+` WHERE run_id=? AND state=? ORDER BY rowid`, runID, HypActive)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanHypotheses(rows)
}

func scanHypotheses(rows *sql.Rows) ([]Hypothesis, error) {
	var out []Hypothesis
	for rows.Next() {
		var h Hypothesis
		if err := rows.Scan(&h.ID, &h.RunID, &h.ParentID, &h.Statement, &h.State, &h.BudgetLimit, &h.BudgetSpent, &h.WhyRefuted); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

func scanEntries(rows *sql.Rows) ([]Entry, error) {
	var out []Entry
	for rows.Next() {
		var e Entry
		if err := rows.Scan(&e.ID, &e.RunID, &e.HypothesisID, &e.Tag, &e.Kind, &e.Value); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) AddEntry(ctx context.Context, runID, hypID, tag, kind, value, provenanceID string) (string, error) {
	id := newID("ent")
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO entries(id,run_id,hypothesis_id,tag,kind,value,provenance_id,created_at) VALUES(?,?,?,?,?,?,?,?)`,
		id, runID, nullable(hypID), tag, kind, value, nullable(provenanceID), s.ts())
	return id, err
}

func (s *Store) Facts(ctx context.Context, runID string) ([]Entry, error) {
	return s.entriesByTag(ctx, runID, TagFact)
}

func (s *Store) Observations(ctx context.Context, runID string) ([]Entry, error) {
	return s.entriesByTag(ctx, runID, TagObservation)
}

func (s *Store) entriesByTag(ctx context.Context, runID, tag string) ([]Entry, error) {
	rows, err := s.db.QueryContext(ctx, entrySelect+` WHERE run_id=? AND tag=? ORDER BY rowid`, runID, tag)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEntries(rows)
}

// excludes confirmed: a success is not a ruled-out line
func (s *Store) ResolvedHypotheses(ctx context.Context, runID string) ([]Hypothesis, error) {
	rows, err := s.db.QueryContext(ctx,
		hypSelect+` WHERE run_id=? AND state<>? AND state<>? ORDER BY rowid`, runID, HypActive, HypConfirmed)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanHypotheses(rows)
}

const hypSubtreeCTE = `WITH RECURSIVE sub(id) AS (
	SELECT id FROM hypotheses WHERE id=?
	UNION ALL
	SELECT h.id FROM hypotheses h JOIN sub ON h.parent_id=sub.id
)
`

func (s *Store) BranchEntries(ctx context.Context, runID, rootHypID, tag string) ([]Entry, error) {
	rows, err := s.db.QueryContext(ctx,
		hypSubtreeCTE+entrySelect+`
		 WHERE run_id=? AND tag=? AND hypothesis_id IN (SELECT id FROM sub) ORDER BY rowid`,
		rootHypID, runID, tag)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEntries(rows)
}

// active=true: the branch's frontier; false: its ruled-out lines
func (s *Store) BranchHypotheses(ctx context.Context, rootHypID string, active bool) ([]Hypothesis, error) {
	var where string
	args := []any{rootHypID}
	if active {
		where = "AND state=?"
		args = append(args, HypActive)
	} else {
		where = "AND state<>? AND state<>?"
		args = append(args, HypActive, HypConfirmed)
	}
	rows, err := s.db.QueryContext(ctx,
		hypSubtreeCTE+hypSelect+` WHERE id IN (SELECT id FROM sub) `+where+` ORDER BY rowid`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanHypotheses(rows)
}

func (s *Store) RecordExperiment(ctx context.Context, in ExperimentInput) (string, error) {
	provID := newID("prov")
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO provenance(id,experiment_id,model,tool_hashes,created_at) VALUES(?,?,?,?,?)`,
		provID, "", in.Model, mustJSON(in.ToolHashes), s.ts()); err != nil {
		return "", fmt.Errorf("store: provenance: %w", err)
	}
	expID := newID("exp")
	var fixed any
	if in.Fixed != nil {
		fixed = mustJSON(in.Fixed)
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO experiments(id,run_id,hypothesis_id,kind,model,poc_blob,spec,runresult,runresult_fix,verdict,provenance_id,created_at)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
		expID, in.RunID, nullable(in.HypothesisID), in.Kind, in.Model, in.PoCBlob,
		mustJSON(in.Spec), mustJSON(in.Primary), fixed, mustJSON(in.Verdict), provID, s.ts()); err != nil {
		return "", fmt.Errorf("store: experiment: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE provenance SET experiment_id=? WHERE id=?`, expID, provID); err != nil {
		return "", err
	}
	return expID, nil
}

func (s *Store) ProvenanceFor(ctx context.Context, experimentID string) (string, error) {
	var id string
	err := s.db.QueryRowContext(ctx, `SELECT id FROM provenance WHERE experiment_id=?`, experimentID).Scan(&id)
	return id, err
}

// seq allocated inside the INSERT: a read-then-write pair loses to BUSY
func (s *Store) AppendEvent(ctx context.Context, runID, kind, actor string, payload any) error {
	return busyRetry(ctx, func() error {
		_, err := s.db.ExecContext(ctx,
			`INSERT INTO events(id,run_id,seq,kind,actor,payload,created_at)
			 SELECT ?,?,COALESCE(MAX(seq),0)+1,?,?,?,? FROM events WHERE run_id=?`,
			newID("evt"), runID, kind, actor, mustJSON(payload), s.ts(), runID)
		return err
	})
}

type TrajectoryEvent struct {
	Seq     int             `json:"seq"`
	Kind    string          `json:"kind"`
	Actor   string          `json:"actor"`
	Payload json.RawMessage `json:"payload"`
}

func (s *Store) Trajectory(ctx context.Context, runID string) ([]TrajectoryEvent, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT seq,kind,COALESCE(actor,''),payload FROM events WHERE run_id=? ORDER BY seq`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TrajectoryEvent
	for rows.Next() {
		var e TrajectoryEvent
		var payload string
		if err := rows.Scan(&e.Seq, &e.Kind, &e.Actor, &payload); err != nil {
			return nil, err
		}
		e.Payload = json.RawMessage(payload)
		out = append(out, e)
	}
	return out, rows.Err()
}

// must not touch dedup_index: an abstract sibling shares the behavioral key
func (s *Store) SaveArtifact(ctx context.Context, runID string, e *artifact.Envelope) error {
	if e.Artifact.ID == "" {
		return fmt.Errorf("store: artifact id not computed")
	}
	wire, err := e.Marshal()
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO patterns(id,run_id,behavioral_key,integrity_tier,placement,bug_class,wire,created_at)
		 VALUES(?,?,?,?,?,?,?,?)`,
		e.Artifact.ID, nullable(runID), e.Artifact.BehavioralKey(), string(e.IntegrityTier()),
		string(e.Placement), e.Artifact.Content.Crash.BugClass, string(wire), s.ts())
	return err
}

// count = distinct runs that produced the behavior; idempotent per (key, runID)
func (s *Store) RegisterFinding(ctx context.Context, behavioralKey, representativeHash, runID string) error {
	return busyRetry(ctx, func() error {
		return s.registerFinding(ctx, behavioralKey, representativeHash, runID)
	})
}

func (s *Store) registerFinding(ctx context.Context, behavioralKey, representativeHash, runID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var provJSON string
	err = tx.QueryRowContext(ctx, `SELECT provenance FROM dedup_index WHERE behavioral_key=?`, behavioralKey).Scan(&provJSON)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO dedup_index(behavioral_key,representative_hash,count,provenance,updated_at) VALUES(?,?,?,?,?)`,
			behavioralKey, representativeHash, 1, mustJSON([]string{runID}), s.ts()); err != nil {
			return err
		}
		return tx.Commit()
	case err != nil:
		return err
	}

	var runs []string
	_ = json.Unmarshal([]byte(provJSON), &runs)
	for _, r := range runs {
		if r == runID {
			return tx.Commit()
		}
	}
	runs = append(runs, runID)
	if _, err := tx.ExecContext(ctx,
		`UPDATE dedup_index SET count=?, provenance=?, updated_at=? WHERE behavioral_key=?`,
		len(runs), mustJSON(runs), s.ts(), behavioralKey); err != nil {
		return err
	}
	return tx.Commit()
}

// never merges or drops keys: prefer false splits
func (s *Store) IndexKeys(ctx context.Context, artifactID string, keys []string) error {
	for _, k := range keys {
		if k == "" {
			continue
		}
		if _, err := s.db.ExecContext(ctx,
			`INSERT OR IGNORE INTO key_index(key, artifact_id, created_at) VALUES(?,?,?)`,
			k, artifactID, s.ts()); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) Candidates(ctx context.Context, keys []string) ([]string, error) {
	if len(keys) == 0 {
		return nil, nil
	}
	ph := make([]string, len(keys))
	args := make([]any, len(keys))
	for i, k := range keys {
		ph[i] = "?"
		args[i] = k
	}
	q := `SELECT DISTINCT artifact_id FROM key_index WHERE key IN (` + strings.Join(ph, ",") + `) ORDER BY artifact_id`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

type DedupEntry struct {
	BehavioralKey      string
	RepresentativeHash string
	Count              int
}

func (s *Store) Dedup(ctx context.Context, behavioralKey string) (DedupEntry, bool, error) {
	var d DedupEntry
	err := s.db.QueryRowContext(ctx,
		`SELECT behavioral_key,representative_hash,count FROM dedup_index WHERE behavioral_key=?`, behavioralKey).
		Scan(&d.BehavioralKey, &d.RepresentativeHash, &d.Count)
	if errors.Is(err, sql.ErrNoRows) {
		return DedupEntry{}, false, nil
	}
	return d, err == nil, err
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}
