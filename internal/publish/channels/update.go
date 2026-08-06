package channels

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Releases run oldest to newest; the tail is the head.
type feedManifest struct {
	Schema   string        `json:"schema"`
	Releases []feedRelease `json:"releases"`
}

type feedRelease struct {
	Version  string `json:"version"`
	Catalog  string `json:"catalog,omitempty"`
	Corpora  string `json:"corpora,omitempty"`
	ModelRef string `json:"model_ref,omitempty"`
}

const feedSchema = "quarry-updates/v1"

type FileUpdateFeed struct {
	dir string
}

func OpenFileUpdateFeed(dir string) (*FileUpdateFeed, error) {
	f := &FileUpdateFeed{dir: dir}
	if _, err := f.load(); err != nil {
		return nil, err
	}
	return f, nil
}

func (f *FileUpdateFeed) load() (feedManifest, error) {
	b, err := os.ReadFile(filepath.Join(f.dir, "feed.json"))
	if err != nil {
		return feedManifest{}, fmt.Errorf("updatefeed: read manifest: %w", err)
	}
	var m feedManifest
	if err := json.Unmarshal(b, &m); err != nil {
		return feedManifest{}, fmt.Errorf("updatefeed: parse manifest: %w", err)
	}
	if m.Schema != feedSchema {
		return feedManifest{}, fmt.Errorf("updatefeed: unknown schema %q (want %q)", m.Schema, feedSchema)
	}
	return m, nil
}

// "cannot tell" is a refusal, never an update: an unlisted caller may be a downgrade.
func (f *FileUpdateFeed) Pull(_ context.Context, sinceVersion string) (Update, bool, error) {
	m, err := f.load()
	if err != nil {
		return Update{}, false, err
	}
	if len(m.Releases) == 0 {
		return Update{}, false, nil
	}
	head := m.Releases[len(m.Releases)-1]
	if head.Version == sinceVersion {
		return Update{}, false, nil
	}
	if sinceVersion != "" && !listsVersion(m.Releases, sinceVersion) {
		return Update{}, false, fmt.Errorf("updatefeed: feed does not list caller version %q (head is %q); refusing to serve an update that cannot be shown to be newer", sinceVersion, head.Version)
	}

	up := Update{Version: head.Version, ModelRef: head.ModelRef}
	if head.Catalog != "" {
		b, err := f.readPayload(head.Catalog)
		if err != nil {
			return Update{}, false, err
		}
		up.Catalog = b
	}
	if head.Corpora != "" {
		b, err := f.readPayload(head.Corpora)
		if err != nil {
			return Update{}, false, err
		}
		up.Corpora = b
	}
	return up, true, nil
}

func listsVersion(rs []feedRelease, version string) bool {
	for _, r := range rs {
		if r.Version == version {
			return true
		}
	}
	return false
}

func (f *FileUpdateFeed) readPayload(rel string) ([]byte, error) {
	clean := filepath.Clean(rel)
	if filepath.IsAbs(clean) || clean == ".." || hasDotDotPrefix(clean) {
		return nil, fmt.Errorf("updatefeed: payload path %q escapes the tree", rel)
	}
	b, err := os.ReadFile(filepath.Join(f.dir, clean))
	if err != nil {
		return nil, fmt.Errorf("updatefeed: read payload %q: %w", rel, err)
	}
	return b, nil
}

func hasDotDotPrefix(p string) bool {
	return len(p) >= 3 && p[0] == '.' && p[1] == '.' && (p[2] == filepath.Separator || p[2] == '/')
}

var _ UpdateFeed = (*FileUpdateFeed)(nil)
