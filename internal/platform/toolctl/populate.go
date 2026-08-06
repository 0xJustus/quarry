package toolctl

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/0xjustus/quarry/internal/platform/broker"
)

// Commander is the only seam that runs docker; tests inject a fake.
type Commander interface {
	Run(ctx context.Context, argv []string) error
}

type PopulateOptions struct {
	Log func(string)     // optional
	Now func() time.Time // defaults to time.Now
}

func (o PopulateOptions) log(format string, a ...any) {
	if o.Log != nil {
		o.Log(fmt.Sprintf(format, a...))
	}
}

func (o PopulateOptions) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

// Populate fails closed on any pin mismatch: pinned bytes must never swap silently.
func Populate(ctx context.Context, m Manifest, baseDir, storeRoot string, cmd Commander, opts PopulateOptions) ([]Provenance, error) {
	plans, err := m.Plans(baseDir)
	if err != nil {
		return nil, err
	}
	if cmd == nil {
		return nil, fmt.Errorf("toolctl: Populate needs a Commander (nil) — use --dry-run to only plan")
	}
	if err := os.MkdirAll(storeRoot, 0o700); err != nil {
		return nil, err
	}
	// nil allowlist: WriteArtifact is out-of-band, only manifest-planned tools reach it
	store := broker.NewLocalStore(storeRoot, nil)

	scratch, err := os.MkdirTemp("", "quarry-toolctl-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(scratch)

	fresh := make([]Provenance, 0, len(plans))
	for _, p := range plans {
		opts.log("build %s: docker %s", p.Name, join(p.BuildArgv))
		if err := cmd.Run(ctx, p.BuildArgv); err != nil {
			return nil, fmt.Errorf("toolctl: build %s: %w", p.Name, err)
		}

		dest := filepath.Join(scratch, p.Name+".artifact")
		if err := extract(ctx, cmd, p.Extract, dest, opts); err != nil {
			return nil, fmt.Errorf("toolctl: extract %s: %w", p.Name, err)
		}
		data, err := os.ReadFile(dest)
		if err != nil {
			return nil, fmt.Errorf("toolctl: read extracted %s artifact: %w", p.Name, err)
		}
		if len(data) == 0 {
			return nil, fmt.Errorf("toolctl: extracted %s artifact is empty", p.Name)
		}

		hash, err := store.WriteArtifact(data)
		if err != nil {
			return nil, fmt.Errorf("toolctl: pin %s: %w", p.Name, err)
		}
		if p.ExpectedPin != "" && p.ExpectedPin != hash {
			return nil, fmt.Errorf("toolctl: %s pin mismatch: manifest expects %s, build produced %s (moved commit or changed recipe?)", p.Name, p.ExpectedPin, hash)
		}

		rec := p.Prov
		rec.Hash = hash
		rec.Size = len(data)
		rec.BuiltAt = opts.now().UTC()
		fresh = append(fresh, rec)
		opts.log("pinned %s → %s (%d bytes) at %s", p.Name, hash, len(data), rec.TargetPath)
	}

	existing, err := LoadProvenance(storeRoot)
	if err != nil {
		return nil, err
	}
	merged := mergeProvenance(existing, fresh)
	if err := SaveProvenance(storeRoot, merged); err != nil {
		return nil, err
	}
	return fresh, nil
}

func extract(ctx context.Context, cmd Commander, e ExtractPlan, dest string, opts PopulateOptions) error {
	if e.Mode == ArtifactImage {
		argv := []string{"save", "-o", dest, e.ImageRef}
		opts.log("extract (image): docker %s", join(argv))
		return cmd.Run(ctx, argv)
	}
	create := []string{"create", "--name", e.Container, e.ImageRef}
	opts.log("extract (file): docker %s", join(create))
	if err := cmd.Run(ctx, create); err != nil {
		return err
	}
	cpArgv := []string{"cp", e.Container + ":" + e.Path, dest}
	opts.log("extract (file): docker %s", join(cpArgv))
	cpErr := cmd.Run(ctx, cpArgv)
	// rm regardless of the cp outcome: a failed cp must not leak the container
	_ = cmd.Run(ctx, []string{"rm", "-f", e.Container})
	return cpErr
}

type VerifyResult struct {
	Name string
	Hash string
	OK   bool
	Note string // failure reason when OK is false
}

// Verify re-checks content addresses through LocalStore.Get, which re-hashes the blob.
func Verify(storeRoot string) ([]VerifyResult, error) {
	recs, err := LoadProvenance(storeRoot)
	if err != nil {
		return nil, err
	}
	hashes := make([]string, 0, len(recs))
	for _, r := range recs {
		hashes = append(hashes, r.Hash)
	}
	store := broker.NewLocalStore(storeRoot, hashes)
	out := make([]VerifyResult, 0, len(recs))
	for _, r := range recs {
		vr := VerifyResult{Name: r.Name, Hash: r.Hash, OK: true}
		if _, gerr := store.Get(r.Hash); gerr != nil {
			vr.OK = false
			vr.Note = gerr.Error()
		}
		out = append(out, vr)
	}
	return out, nil
}

func join(argv []string) string { return strings.Join(argv, " ") }
