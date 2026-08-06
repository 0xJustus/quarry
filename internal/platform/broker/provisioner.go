package broker

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

type ToolPin struct {
	Hash       string // "sha256:…" (bare hex is normalized)
	TargetPath string // absolute path inside the container
}

type Toolset struct {
	Pins []ToolPin
}

func (t Toolset) Empty() bool { return len(t.Pins) == 0 }

type BindMount struct {
	HostPath      string
	ContainerPath string
	ReadOnly      bool // always true: no writeback channel into the trusted store
	Hash          string
}

type BindMountPlan struct {
	Mounts []BindMount
}

func (p BindMountPlan) DockerArgs() []string {
	args := make([]string, 0, len(p.Mounts)*2)
	for _, m := range p.Mounts {
		args = append(args, "-v", m.HostPath+":"+m.ContainerPath+":ro")
	}
	return args
}

// Hashes is the AUTHORITATIVE replay set; the store's pull log can over-report.
func (p BindMountPlan) Hashes() []string {
	seen := map[string]bool{}
	for _, m := range p.Mounts {
		seen[m.Hash] = true
	}
	out := make([]string, 0, len(seen))
	for h := range seen {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

type LocalToolStore interface {
	ToolStore
	// Resolve MUST verify and record before returning a mountable path.
	Resolve(hash string) (hostPath string, err error)
}

// Provisioner turns a Toolset into read-only bind mounts from a local store; opens no network path.
type Provisioner struct {
	store LocalToolStore
}

func NewProvisioner(store LocalToolStore) *Provisioner {
	return &Provisioner{store: store}
}

// Fail closed: validate every pin before any Resolve, because Resolve records.
func (p *Provisioner) Provision(ts Toolset) (BindMountPlan, error) {
	if p == nil || p.store == nil {
		return BindMountPlan{}, fmt.Errorf("broker: provisioner has no store")
	}
	if err := validatePins(ts.Pins); err != nil {
		return BindMountPlan{}, err
	}
	var plan BindMountPlan
	for _, pin := range ts.Pins {
		host, err := p.store.Resolve(pin.Hash)
		if err != nil {
			return BindMountPlan{}, fmt.Errorf("broker: provision %s → %s: %w (plan aborted after %d verified pin(s); NO mounts created — those pins are in the store's pull log but were never provisioned, BindMountPlan.Hashes() is the authoritative replay set)",
				pin.Hash, pin.TargetPath, err, len(plan.Mounts))
		}
		plan.Mounts = append(plan.Mounts, BindMount{
			HostPath:      host,
			ContainerPath: pin.TargetPath,
			ReadOnly:      true,
			Hash:          normalizeHash(pin.Hash),
		})
	}
	return plan, nil
}

func validatePins(pins []ToolPin) error {
	seen := map[string]bool{}
	for _, pin := range pins {
		if strings.TrimSpace(pin.Hash) == "" {
			return fmt.Errorf("broker: toolset pin for %q declares no content hash", pin.TargetPath)
		}
		if !filepath.IsAbs(pin.TargetPath) {
			return fmt.Errorf("broker: toolset target path %q must be absolute", pin.TargetPath)
		}
		if seen[pin.TargetPath] {
			return fmt.Errorf("broker: toolset target path %q declared twice", pin.TargetPath)
		}
		seen[pin.TargetPath] = true
	}
	return nil
}
