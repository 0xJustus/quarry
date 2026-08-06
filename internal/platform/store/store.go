package store

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/0xjustus/quarry/internal/publish/artifact"
	"github.com/0xjustus/quarry/internal/publish/channels"

	_ "modernc.org/sqlite" // pure-Go driver: no cgo
)

type Store struct {
	db      *sql.DB
	blobDir string
	now     func() time.Time
}

func Open(dir string) (*Store, error) {
	// 0700: blobs are working-exploit specimens; never world-readable
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("store: mkdir %s: %w", dir, err)
	}
	_ = os.Chmod(dir, 0o700)
	blobDir := filepath.Join(dir, "blobs")
	if err := os.MkdirAll(blobDir, 0o700); err != nil {
		return nil, fmt.Errorf("store: mkdir blobs: %w", err)
	}
	dbPath := filepath.Join(dir, "quarry.db")
	// keep _txlock=immediate: a deferred write upgrade loses to BUSY (vault: Store and Config)
	db, err := sql.Open("sqlite", "file:"+dbPath+"?_pragma=busy_timeout(5000)&_txlock=immediate")
	if err != nil {
		return nil, fmt.Errorf("store: open db: %w", err)
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db, blobDir: blobDir, now: time.Now}
	if _, err := db.Exec(ddl); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: apply schema: %w", err)
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		_ = os.Chmod(dbPath+suffix, 0o600)
	}
	if _, err := db.Exec(`INSERT OR IGNORE INTO meta(key,value) VALUES('schema_version',?)`, strconv.Itoa(schemaVersion)); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: record schema version: %w", err)
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) SetClock(now func() time.Time) { s.now = now }

func (s *Store) ts() string { return s.now().UTC().Format(time.RFC3339Nano) }

func newID(prefix string) string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return prefix + "_" + hex.EncodeToString(b[:])
}

// busy_timeout expiry does not re-enter the handler; a dropped write is lost
func busyRetry(ctx context.Context, fn func() error) error {
	const attempts = 8
	var err error
	for i := 0; i < attempts; i++ {
		if err = fn(); !isBusy(err) {
			return err
		}
		delay := time.Duration(10<<uint(i)) * time.Millisecond
		if delay > 250*time.Millisecond {
			delay = 250 * time.Millisecond
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("store: datastore locked by another process and the context ended (%v): %w", ctx.Err(), err)
		case <-time.After(delay):
		}
	}
	return fmt.Errorf("store: datastore locked by another process after %d attempts: %w", attempts, err)
}

// extended codes carry the base code in the low byte; some paths only text
func isBusy(err error) bool {
	if err == nil {
		return false
	}
	var coded interface{ Code() int }
	if errors.As(err, &coded) {
		switch coded.Code() & 0xff {
		case 5, 6: // SQLITE_BUSY, SQLITE_LOCKED
			return true
		}
	}
	msg := err.Error()
	return strings.Contains(msg, "database is locked") || strings.Contains(msg, "database table is locked")
}

// idempotent; returns the "sha256:..." hash
func (s *Store) PutBlob(ctx context.Context, data []byte, media string) (string, error) {
	sum := sha256.Sum256(data)
	hash := "sha256:" + hex.EncodeToString(sum[:])
	path := s.blobPath(hash)
	have, err := os.ReadFile(path)
	// an ambiguous read error must not be papered over by an overwrite
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return "", fmt.Errorf("store: read blob %s: %w", hash, err)
	}
	// the path existing is not evidence the blob is intact: repair a truncated one
	if err != nil || !bytes.Equal(have, data) {
		if err := writeBlobAtomic(path, data); err != nil {
			return "", err
		}
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO blobs(hash,bytes,media,created_at) VALUES(?,?,?,?)`,
		hash, len(data), media, s.ts()); err != nil {
		return "", err
	}
	return hash, nil
}

// the name must never exist unless the full bytes are behind it
func writeBlobAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".tmp-blob-*")
	if err != nil {
		return fmt.Errorf("store: write blob: %w", err)
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("store: write blob: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("store: sync blob: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("store: write blob: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("store: publish blob: %w", err)
	}
	return nil
}

// fail closed: content that does not match the hash is an error, not a specimen
func (s *Store) GetBlob(hash string) ([]byte, error) {
	data, err := os.ReadFile(s.blobPath(hash))
	if err != nil {
		return nil, err
	}
	if want, ok := sha256Hex(hash); ok {
		sum := sha256.Sum256(data)
		if got := hex.EncodeToString(sum[:]); got != want {
			return nil, fmt.Errorf("store: blob %s corrupt: %d bytes on disk hash to sha256:%s", hash, len(data), got)
		}
	}
	return data, nil
}

// ok=false: the hash carries no digest to verify content against
func sha256Hex(hash string) (string, bool) {
	h, ok := strings.CutPrefix(hash, "sha256:")
	if !ok || len(h) != 64 {
		return "", false
	}
	h = strings.ToLower(h)
	if _, err := hex.DecodeString(h); err != nil {
		return "", false
	}
	return h, true
}

func (s *Store) blobPath(hash string) string {
	h := hash
	if len(h) > 7 && h[:7] == "sha256:" {
		h = h[7:]
	}
	if len(h) < 4 {
		return filepath.Join(s.blobDir, h)
	}
	return filepath.Join(s.blobDir, h[:2], h[2:])
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// implements channels.Outbox
func (s *Store) Enqueue(ctx context.Context, item channels.OutboxItem) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO outbox(hash,behavioral_key,placement,wire,status,created_at)
		 VALUES(?,?,?,?, 'pending', ?)`,
		item.Hash, item.BehavioralKey, item.Placement, string(item.Wire), s.ts())
	return err
}

// cap filtered in-query: local-only items must not head-of-line block syncable ones
func (s *Store) PendingOutbox(ctx context.Context, limit int, maxPlacement artifact.Placement) ([]channels.OutboxItem, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT hash,behavioral_key,placement,wire FROM outbox
		 WHERE status='pending'
		   AND (CASE placement WHEN 'public' THEN 0 WHEN 'trusted' THEN 1 ELSE 2 END) <= ?
		 ORDER BY rowid LIMIT ?`, maxPlacement.Rank(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []channels.OutboxItem
	for rows.Next() {
		var it channels.OutboxItem
		var wire string
		if err := rows.Scan(&it.Hash, &it.BehavioralKey, &it.Placement, &wire); err != nil {
			return nil, err
		}
		it.Wire = []byte(wire)
		out = append(out, it)
	}
	return out, rows.Err()
}

func (s *Store) MarkSynced(ctx context.Context, hash string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE outbox SET status='synced', synced_at=? WHERE hash=?`, s.ts(), hash)
	return err
}
