package broker

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Artifact is a pulled, content-addressed tool artifact (opaque bytes here).
type Artifact struct {
	Hash  string
	Bytes []byte
	Media string
}

// PullRecord is one entry in the evidence trail of provisioned hashes.
type PullRecord struct {
	Hash string
	At   time.Time
	Size int
	OK   bool
	Note string // refusal/failure reason when OK is false
}

// ToolStore is pull-only by design: there is no Put.
type ToolStore interface {
	Get(hash string) (Artifact, error)
	PullLog() []PullRecord
}

// LocalStore never fetches: artifacts are provisioned out-of-band onto disk.
type LocalStore struct {
	dir   string
	allow map[string]bool

	mu    sync.Mutex
	pulls []PullRecord
	now   func() time.Time
}

// Only the listed hashes may EVER be pulled.
func NewLocalStore(dir string, allowlist []string) *LocalStore {
	allow := make(map[string]bool, len(allowlist))
	for _, h := range allowlist {
		allow[normalizeHash(h)] = true
	}
	return &LocalStore{dir: dir, allow: allow, now: time.Now}
}

func (s *LocalStore) SetClock(now func() time.Time) { s.now = now }

func (s *LocalStore) Get(hash string) (Artifact, error) {
	_, data, err := s.verify(hash)
	if err != nil {
		return Artifact{}, err
	}
	return Artifact{Hash: normalizeHash(hash), Bytes: data, Media: sniffMedia(data)}, nil
}

// Resolve returns the host path the Provisioner bind-mounts read-only.
func (s *LocalStore) Resolve(hash string) (string, error) {
	path, _, err := s.verify(hash)
	return path, err
}

// The single trusted gate: no blob or path escapes without passing through here.
func (s *LocalStore) verify(hash string) (string, []byte, error) {
	h := normalizeHash(hash)

	if !s.allow[h] {
		return "", nil, s.record(h, 0, false, "not allowlisted")
	}
	path := s.blobPath(h)
	data, err := os.ReadFile(path)
	if err != nil {
		return "", nil, s.record(h, 0, false, fmt.Sprintf("read: %v", err))
	}
	sum := "sha256:" + hex.EncodeToString(sha256Sum(data))
	if sum != h {
		return "", nil, s.record(h, len(data), false, fmt.Sprintf("content-address mismatch: got %s", sum))
	}

	_ = s.record(h, len(data), true, "")
	return path, data, nil
}

// newest last
func (s *LocalStore) PullLog() []PullRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]PullRecord, len(s.pulls))
	copy(out, s.pulls)
	return out
}

func (s *LocalStore) ProvisionedHashes() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	seen := map[string]bool{}
	for _, r := range s.pulls {
		if r.OK {
			seen[r.Hash] = true
		}
	}
	out := make([]string, 0, len(seen))
	for h := range seen {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// record logs the attempt and, for a failure, returns the error to raise.
func (s *LocalStore) record(hash string, size int, ok bool, note string) error {
	s.mu.Lock()
	s.pulls = append(s.pulls, PullRecord{Hash: hash, At: s.now().UTC(), Size: size, OK: ok, Note: note})
	s.mu.Unlock()
	if ok {
		return nil
	}
	return fmt.Errorf("broker: pull %s refused: %s", hash, note)
}

// 2-char shards, matching the store package layout
func (s *LocalStore) blobPath(hash string) string {
	h := strings.TrimPrefix(hash, "sha256:")
	if len(h) < 4 {
		return filepath.Join(s.dir, h)
	}
	return filepath.Join(s.dir, h[:2], h[2:])
}

// WriteArtifact is out-of-band provisioning, not a Put: it does NOT allowlist.
func (s *LocalStore) WriteArtifact(data []byte) (string, error) {
	hash := "sha256:" + hex.EncodeToString(sha256Sum(data))
	p := s.blobPath(hash)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return "", err
	}
	if err := os.WriteFile(p, data, 0o600); err != nil {
		return "", fmt.Errorf("broker: write artifact: %w", err)
	}
	return hash, nil
}

func normalizeHash(h string) string {
	h = strings.TrimSpace(h)
	if h == "" {
		return h
	}
	if !strings.HasPrefix(h, "sha256:") {
		return "sha256:" + h
	}
	return h
}

func sha256Sum(b []byte) []byte {
	s := sha256.Sum256(b)
	return s[:]
}

func sniffMedia(b []byte) string {
	if len(b) >= 4 && b[0] == 0x7f && b[1] == 'E' && b[2] == 'L' && b[3] == 'F' {
		return "application/x-elf"
	}
	return "application/octet-stream"
}
