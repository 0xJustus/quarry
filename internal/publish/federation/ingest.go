// Package federation grounds untrusted external findings on quarry's own oracle.
package federation

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/0xjustus/quarry/internal/publish/artifact"
	"github.com/0xjustus/quarry/internal/verdict/oracle"
)

const AcquiredBy = "federated-ingest"

// Finding is an untrusted external claim: a PoV plus the oracle spec quarry re-runs.
type Finding struct {
	Source string
	PoV    []byte
	Spec   oracle.Spec
}

func Admit(verdict oracle.Verdict, f Finding, primary oracle.RunResult, pathSig, createdAt string) (*artifact.Envelope, bool) {
	// admit only what re-grounds: an unreproduced claim must never enter the commons
	if !verdict.Pass {
		return nil, false
	}
	sum := sha256.Sum256(f.PoV)
	blob := "sha256:" + hex.EncodeToString(sum[:])
	env := &artifact.Envelope{
		Artifact: artifact.Artifact{
			Content: artifact.Content{
				Specimen: &artifact.SpecimenRef{BlobHash: blob, Media: "application/x-quarry-specimen", Bytes: int64(len(f.PoV))},
				// CrashFromPoV, not CrashFrom: a frame-less divergence has no discriminator
				Crash: artifact.CrashFromPoV(primary, pathSig, f.PoV),
			},
			Reproducer: &artifact.Reproducer{BlobHash: blob, Media: "application/x-quarry-specimen", Bytes: int64(len(f.PoV)), Oracle: f.Spec, Verdict: verdict},
		},
		Placement:  artifact.Private,
		Provenance: artifact.Provenance{AcquiredBy: AcquiredBy, Project: f.Source, Model: "verify"},
		CreatedAt:  createdAt,
	}
	if err := env.Artifact.ComputeID(); err != nil {
		return nil, false
	}
	return env, true
}
