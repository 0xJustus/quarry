package gitcommons

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/0xjustus/quarry/internal/publish/artifact"
)

type VerifyReport struct {
	Artifacts int
	Keys      int
	// 0 = the tree declares no trust root: callers must not report it signature-valid
	Signers int
	// abstracts with no signature at all; in a pinned tree each is also a Failure
	Unsigned int
	Failures []string
}

func (r VerifyReport) OK() bool { return len(r.Failures) == 0 }

// trust root: Generate never writes or clears it, so a PR cannot grant itself a key
type signerPolicy struct {
	Schema  string   `json:"schema"`
	Signers []string `json:"signers"`
}

const signersFile = "signers.json"

// present-but-unusable is an ERROR, never "no policy"; absent is (nil, nil)
func loadSigners(dir string) (map[string]bool, error) {
	b, err := os.ReadFile(filepath.Join(dir, signersFile))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read: %w", err)
	}
	var p signerPolicy
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	if len(p.Signers) == 0 {
		return nil, errors.New("declares no accepted signer (an empty trust root would admit every unsigned abstract)")
	}
	out := make(map[string]bool, len(p.Signers))
	for _, k := range p.Signers {
		h := strings.ToLower(strings.TrimSpace(k))
		raw, dErr := hex.DecodeString(h)
		if dErr != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%q is not a hex ed25519 public key", k)
		}
		out[h] = true
	}
	return out, nil
}

// the pin supplies WHOSE key; an unpinned tree accepts anything here
func checkSigner(accepted map[string]bool, e *artifact.Envelope) string {
	if len(accepted) == 0 {
		return ""
	}
	if e.Signature == nil {
		return fmt.Sprintf("unsigned: %s pins %d accepted signer(s), so an unsigned abstract is not admissible prior art", signersFile, len(accepted))
	}
	if !accepted[strings.ToLower(e.Signature.PublicKey)] {
		return fmt.Sprintf("signed by %s, a key %s does not accept", shortKey(e.Signature.PublicKey), signersFile)
	}
	return ""
}

func shortKey(k string) string {
	if len(k) > 16 {
		return k[:16] + "…"
	}
	return k
}

// anti-poisoning gate: BOTH index directions, since a recomputed tree hides subtraction
func Verify(dir string) (VerifyReport, error) {
	var r VerifyReport
	fail := func(where, why string) { r.Failures = append(r.Failures, where+": "+why) }

	// an unreadable signers.json fails on its own; the remaining checks still run
	accepted, sErr := loadSigners(dir)
	if sErr != nil {
		fail(signersFile, sErr.Error())
	}
	r.Signers = len(accepted)
	battery := publicReIDBattery()

	seen := map[string]bool{}
	artKeys := map[string]map[string]struct{}{}
	var seenEnvs []*artifact.Envelope
	artRoot := filepath.Join(dir, "artifacts")
	if _, err := os.Stat(artRoot); err == nil {
		err = filepath.WalkDir(artRoot, func(path string, d os.DirEntry, werr error) error {
			if werr != nil || d.IsDir() {
				return nil
			}
			rel, _ := filepath.Rel(dir, path)
			if !strings.HasSuffix(path, ".json") {
				fail(rel, "unexpected non-abstract file under artifacts/")
				return nil
			}
			r.Artifacts++
			b, err := os.ReadFile(path)
			if err != nil {
				fail(rel, "read: "+err.Error())
				return nil
			}
			env, err := artifact.Unmarshal(b)
			if err != nil {
				fail(rel, "unmarshal: "+err.Error())
				return nil
			}
			if want := ArtifactPath(env.Artifact.ID); rel != want {
				fail(rel, "wrong path for id "+env.Artifact.ID+" (want "+want+")")
			}
			if err := env.Verify(); err != nil {
				fail(rel, "integrity: "+err.Error())
			}
			// env.Verify() clears an UNSIGNED abstract: the pin is the other half
			if why := checkSigner(accepted, env); why != "" {
				fail(rel, why)
			}
			if env.Signature == nil {
				r.Unsigned++
			}
			if env.Artifact.Content.Specimen != nil {
				fail(rel, "public tier must not carry a specimen")
			}
			if env.Artifact.Reproducer != nil {
				fail(rel, "public tier must not carry a reproducer")
			}
			if env.Placement != artifact.Public {
				fail(rel, "public commons must carry only Public-tier artifacts, got "+string(env.Placement))
			}
			// a hand-edited PR bypasses the write gate, so CI re-applies the same scan
			if why := checkPublicLeaks(battery, env); why != "" {
				fail(rel, "re-id leak scan: "+why)
			}
			seen[env.Artifact.ID] = true
			seenEnvs = append(seenEnvs, env)
			ks := map[string]struct{}{}
			for _, k := range artifact.CrashKeys(env.Artifact.Content.Crash) {
				ks[k] = struct{}{}
			}
			artKeys[env.Artifact.ID] = ks
			return nil
		})
		if err != nil {
			return r, err
		}
	}

	prefix := 0
	var manifest Manifest
	haveManifest := false
	if mb, err := os.ReadFile(filepath.Join(dir, "commons.json")); err == nil {
		if err := json.Unmarshal(mb, &manifest); err != nil {
			fail("commons.json", "unmarshal: "+err.Error())
		} else {
			haveManifest = true
			prefix = manifest.Prefix
		}
	} else {
		fail("commons.json", "missing manifest")
	}

	keySet := map[string]struct{}{}
	indexed := map[string]struct{}{}
	keysRoot := filepath.Join(dir, "keys")
	if _, err := os.Stat(keysRoot); err == nil {
		err = filepath.WalkDir(keysRoot, func(path string, d os.DirEntry, werr error) error {
			if werr != nil || d.IsDir() {
				return nil
			}
			rel, _ := filepath.Rel(dir, path)
			if !strings.HasSuffix(path, ".jsonl") {
				fail(rel, "unexpected non-shard file under keys/")
				return nil
			}
			f, err := os.Open(path)
			if err != nil {
				fail(rel, "open shard: "+err.Error())
				return nil
			}
			defer f.Close()
			sc := jsonlScanner(f)
			ln := 0
			for sc.Scan() {
				ln++
				var e keyEntry
				if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
					fail(fmt.Sprintf("%s:%d", rel, ln), "bad jsonl: "+err.Error())
					continue
				}
				keySet[e.Key] = struct{}{}
				indexed[pairID(e.Key, e.ArtifactID)] = struct{}{}
				if !seen[e.ArtifactID] {
					fail(fmt.Sprintf("%s:%d", rel, ln), "key points at missing artifact "+e.ArtifactID)
					continue
				}
				if _, ok := artKeys[e.ArtifactID][e.Key]; !ok {
					fail(fmt.Sprintf("%s:%d", rel, ln), "key not derivable from artifact "+e.ArtifactID+"'s crash (index poisoning)")
				}
				if haveManifest {
					if want := shardPath(e.Key, prefix); want != rel {
						fail(fmt.Sprintf("%s:%d", rel, ln), "mis-sharded key (manifest prefix routes it to "+want+")")
					}
				}
			}
			if err := sc.Err(); err != nil {
				fail(rel, "scan shard: "+err.Error())
			}
			return nil
		})
		if err != nil {
			return r, err
		}
	}
	r.Keys = len(keySet)

	// the other direction: de-indexing leaves a consistent tree, and the bug reads as novel
	for _, id := range slices.Sorted(maps.Keys(artKeys)) {
		for _, k := range slices.Sorted(maps.Keys(artKeys[id])) {
			if _, ok := indexed[pairID(k, id)]; !ok {
				fail(ArtifactPath(id), "behavioral key "+k+" is not indexed (de-indexed: the bug is unfindable and reads as novel)")
			}
		}
	}

	if haveManifest {
		if want := shardPrefix(len(keySet)); manifest.Prefix != want {
			fail("commons.json", fmt.Sprintf("prefix %d is not the canonical prefix %d for %d keys", manifest.Prefix, want, len(keySet)))
		}
		if manifest.Keys != len(keySet) {
			fail("commons.json", fmt.Sprintf("manifest keys=%d but tree has %d", manifest.Keys, len(keySet)))
		}
		if manifest.Artifacts != r.Artifacts {
			fail("commons.json", fmt.Sprintf("manifest artifacts=%d but tree has %d", manifest.Artifacts, r.Artifacts))
		}
	}

	// byte-identical to the canonical Bloom: rejects a forged superset
	if db, err := os.ReadFile(filepath.Join(dir, "digest", "keys.bloom")); err == nil {
		if !bytes.Equal(canonicalDigest(keySet), db) {
			fail("digest/keys.bloom", "digest is not the canonical Bloom of the indexed keys (stale, forged, or FP-rate mismatch)")
		}
	} else {
		fail("digest/keys.bloom", "missing root digest")
	}

	// recomputed from the audited artifacts, must match byte-for-byte
	expectedViews := viewRows(seenEnvs)
	onDiskView := map[string]bool{}
	viewsRoot := filepath.Join(dir, "views")
	if _, err := os.Stat(viewsRoot); err == nil {
		err = filepath.WalkDir(viewsRoot, func(path string, d os.DirEntry, werr error) error {
			if werr != nil || d.IsDir() {
				return nil
			}
			rel, _ := filepath.Rel(dir, path)
			onDiskView[rel] = true
			if !strings.HasSuffix(path, ".jsonl") {
				fail(rel, "unexpected non-view file under views/")
				return nil
			}
			want, ok := expectedViews[rel]
			if !ok {
				fail(rel, "view file no artifact derives (poisoned or stale)")
				return nil
			}
			got, _ := os.ReadFile(path)
			if !bytes.Equal(got, marshalIDList(want)) {
				fail(rel, "view does not match the artifacts it must be derived from")
			}
			return nil
		})
		if err != nil {
			return r, err
		}
	}
	for rel := range expectedViews {
		if !onDiskView[rel] {
			fail(rel, "missing relevance view (should be derived from the artifacts)")
		}
	}

	return r, nil
}

func pairID(key, id string) string { return key + "\x00" + id }
