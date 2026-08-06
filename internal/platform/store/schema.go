package store

const schemaVersion = 1

const ddl = `
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
PRAGMA synchronous = NORMAL;

CREATE TABLE IF NOT EXISTS meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS runs (
  id         TEXT PRIMARY KEY,
  objective  TEXT NOT NULL,
  target_ref TEXT NOT NULL,
  mode       TEXT NOT NULL,           -- discover | copilot
  status     TEXT NOT NULL,           -- active | done | aborted
  budget     TEXT,                    -- JSON
  verdict    TEXT,                    -- JSON
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS hypotheses (
  id           TEXT PRIMARY KEY,
  run_id       TEXT NOT NULL REFERENCES runs(id),
  parent_id    TEXT REFERENCES hypotheses(id),
  statement    TEXT NOT NULL,
  state        TEXT NOT NULL,         -- active | confirmed | refuted | exhausted
  budget_limit INTEGER NOT NULL DEFAULT 0,
  budget_spent INTEGER NOT NULL DEFAULT 0,
  why_refuted  TEXT,
  created_at   TEXT NOT NULL,
  updated_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_hyp_run ON hypotheses(run_id, state);

CREATE TABLE IF NOT EXISTS provenance (
  id           TEXT PRIMARY KEY,
  experiment_id TEXT,
  model        TEXT,
  tool_hashes  TEXT,                  -- JSON array
  created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS entries (
  id            TEXT PRIMARY KEY,
  run_id        TEXT NOT NULL REFERENCES runs(id),
  hypothesis_id TEXT REFERENCES hypotheses(id),
  tag           TEXT NOT NULL,        -- fact | observation | hypothesis
  kind          TEXT NOT NULL,        -- freeform sub-type, e.g. crash | leak | note
  value         TEXT NOT NULL,
  provenance_id TEXT REFERENCES provenance(id),
  created_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_entries_run ON entries(run_id, tag);

CREATE TABLE IF NOT EXISTS experiments (
  id            TEXT PRIMARY KEY,
  run_id        TEXT NOT NULL REFERENCES runs(id),
  hypothesis_id TEXT REFERENCES hypotheses(id),
  kind          TEXT NOT NULL,        -- oracle | tool
  model         TEXT,
  poc_blob      TEXT,                 -- content hash of the submitted PoV
  spec          TEXT,                 -- oracle Spec JSON
  runresult     TEXT,                 -- RunResult JSON (primary)
  runresult_fix TEXT,                 -- RunResult JSON (fixed image, differential)
  verdict       TEXT,                 -- Verdict JSON
  provenance_id TEXT REFERENCES provenance(id),
  created_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_exp_run ON experiments(run_id);

CREATE TABLE IF NOT EXISTS events (
  id         TEXT PRIMARY KEY,
  run_id     TEXT NOT NULL REFERENCES runs(id),
  seq        INTEGER NOT NULL,
  kind       TEXT NOT NULL,           -- action | observation | verdict | note
  actor      TEXT,                    -- role/agent that produced it
  payload    TEXT NOT NULL,           -- JSON
  created_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_events_seq ON events(run_id, seq);

CREATE TABLE IF NOT EXISTS patterns (
  id             TEXT PRIMARY KEY,    -- artifact id = hash(content)
  run_id         TEXT REFERENCES runs(id),
  behavioral_key TEXT NOT NULL,       -- derived cache, never part of the id
  integrity_tier TEXT NOT NULL,       -- derived cache, never part of the id
  placement      TEXT NOT NULL,       -- exposure tier / which store serves it
  bug_class      TEXT,
  wire           TEXT NOT NULL,       -- full envelope wire JSON
  created_at     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_patterns_bk ON patterns(behavioral_key);

-- candidate set only: many keys per artifact, many artifacts per key
CREATE TABLE IF NOT EXISTS key_index (
  key          TEXT NOT NULL,
  artifact_id  TEXT NOT NULL,
  created_at   TEXT NOT NULL,
  PRIMARY KEY (key, artifact_id)
);
CREATE INDEX IF NOT EXISTS idx_key_index_key ON key_index(key);

CREATE TABLE IF NOT EXISTS dedup_index (
  behavioral_key     TEXT PRIMARY KEY,
  representative_hash TEXT NOT NULL,
  count              INTEGER NOT NULL DEFAULT 1,
  provenance         TEXT,            -- JSON array of run refs
  updated_at         TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS outbox (
  hash           TEXT PRIMARY KEY,    -- artifact id: content-addressed, so idempotent
  behavioral_key TEXT,
  placement      TEXT,
  wire           TEXT NOT NULL,
  status         TEXT NOT NULL DEFAULT 'pending',  -- pending | synced | failed
  attempts       INTEGER NOT NULL DEFAULT 0,
  created_at     TEXT NOT NULL,
  synced_at      TEXT
);
CREATE INDEX IF NOT EXISTS idx_outbox_status ON outbox(status);

CREATE TABLE IF NOT EXISTS blobs (
  hash       TEXT PRIMARY KEY,
  bytes      INTEGER NOT NULL,
  media      TEXT,
  created_at TEXT NOT NULL
);
`
