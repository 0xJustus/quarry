package artifact

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/0xjustus/quarry/internal/verdict/oracle"
)

const SchemaVersion = "quarry.artifact/v1"

const idDomain = SchemaVersion + "\ncontent\n"

const sigDomain = SchemaVersion + "\nenvelope\n"

// Placement is envelope metadata: never part of identity.
type Placement string

const (
	Public  Placement = "public"
	Trusted Placement = "trusted"
	Private Placement = "private"
)

// least → most sensitive; channel caps compare on this
func (p Placement) Rank() int {
	switch p {
	case Public:
		return 0
	case Trusted:
		return 1
	default:
		return 2
	}
}

func (p Placement) Valid() bool {
	switch p {
	case Public, Trusted, Private:
		return true
	}
	return false
}

// IntegrityTier is derived from structure, never stored.
type IntegrityTier string

const (
	ProvenanceAsserted  IntegrityTier = "provenance-asserted"
	CanonicalConsistent IntegrityTier = "canonical-consistent"
	SelfReproducing     IntegrityTier = "self-reproducing"
)

// Crash lives in Content, so it is id-authenticated.
type Crash struct {
	BugClass   string   `json:"bug_class"`
	Sites      []string `json:"sites"`
	Frames     []string `json:"frames,omitempty"` // call-ordered; keys are order-sensitive
	Signal     int      `json:"signal,omitempty"`
	Sanitizer  string   `json:"sanitizer,omitempty"`
	DedupToken string   `json:"dedup_token,omitempty"`
	PathSig    string   `json:"path_sig,omitempty"`
}

type SpecimenRef struct {
	BlobHash string `json:"blob_hash,omitempty"`
	Media    string `json:"media,omitempty"`
	Bytes    int64  `json:"bytes,omitempty"`
}

// Reproducer presence makes the artifact self-reproducing; excluded from the id.
type Reproducer struct {
	BlobHash string         `json:"blob_hash"`
	Media    string         `json:"media,omitempty"`
	Bytes    int64          `json:"bytes,omitempty"`
	Oracle   oracle.Spec    `json:"oracle"`
	Verdict  oracle.Verdict `json:"verdict"`
}

// Content is identity-bearing: artifact_id = hash(Content).
type Content struct {
	Specimen *SpecimenRef `json:"specimen,omitempty"`
	Crash    Crash        `json:"crash"`
}

type Artifact struct {
	V          string      `json:"v"`
	ID         string      `json:"id"`
	Content    Content     `json:"content"`
	Reproducer *Reproducer `json:"reproducer,omitempty"`
}

func (a *Artifact) SelfReproducing() bool { return a.Reproducer != nil }

// BehavioralKey is derived, never stored.
func (a *Artifact) BehavioralKey() string {
	return ComputeBehavioralKey(a.Content.Crash)
}

func (a *Artifact) contentPreimage() ([]byte, error) {
	c := a.Content
	sites := append([]string(nil), c.Crash.Sites...)
	sort.Strings(sites)
	if len(sites) == 0 {
		sites = []string{} // emit [] not null, else ids diverge cross-language
	}
	c.Crash.Sites = sites
	raw, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var generic any
	if err := dec.Decode(&generic); err != nil {
		return nil, err
	}
	canon, err := canonicalJSON(generic)
	if err != nil {
		return nil, err
	}
	return append([]byte(idDomain), canon...), nil
}

// no HTML escaping: <, >, & must match JS JSON.stringify (cross-language id)
func jsonString(s string) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		return nil, err
	}
	return bytes.TrimRight(b.Bytes(), "\n"), nil // Encode appends a newline
}

// keep byte-identical to the Worker's canonicalize (vault: Artifact Identity)
func canonicalJSON(v any) ([]byte, error) {
	switch t := v.(type) {
	case nil:
		return []byte("null"), nil
	case bool:
		return json.Marshal(t)
	case json.Number:
		return []byte(t.String()), nil
	case string:
		return jsonString(t)
	case []any:
		parts := make([][]byte, 0, len(t))
		for _, e := range t {
			p, err := canonicalJSON(e)
			if err != nil {
				return nil, err
			}
			parts = append(parts, p)
		}
		out := append([]byte{'['}, bytes.Join(parts, []byte{','})...)
		return append(out, ']'), nil
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var buf bytes.Buffer
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			kb, err := jsonString(k)
			if err != nil {
				return nil, err
			}
			buf.Write(kb)
			buf.WriteByte(':')
			vb, err := canonicalJSON(t[k])
			if err != nil {
				return nil, err
			}
			buf.Write(vb)
		}
		buf.WriteByte('}')
		return buf.Bytes(), nil
	default:
		return nil, fmt.Errorf("artifact: cannot canonicalize %T", v)
	}
}

func (a *Artifact) ComputeID() error {
	if a.V == "" {
		a.V = SchemaVersion
	}
	b, err := a.contentPreimage()
	if err != nil {
		return err
	}
	sum := sha256.Sum256(b)
	a.ID = "sha256:" + hex.EncodeToString(sum[:])
	return nil
}

func ComputeBehavioralKey(c Crash) string {
	ks := CrashKeys(c)
	return ks[0]
}

// the ONE keying builder: never hand-assemble a Crash
func CrashFrom(rr oracle.RunResult, pathSig string) Crash {
	san := rr.Sanitizer
	c := Crash{
		BugClass:   san.BugClass,
		Frames:     san.Frames,
		Sanitizer:  san.Tool,
		DedupToken: san.DedupToken,
		PathSig:    pathSig,
	}
	if san.CrashSite != "" {
		c.Sites = []string{san.CrashSite}
	}
	if !san.Fired {
		// no sanitizer: the signal is identity-bearing and names the class
		c.Signal = rr.TermSignal
		if c.BugClass == "" {
			c.BugClass = signalClass(rr.TermSignal)
		}
	}
	return c
}

// CrashFromPoV is CrashFrom for a producer holding the input: a frame-less finding splits on the PoV digest, never merges.
func CrashFromPoV(rr oracle.RunResult, pathSig string, pov []byte) Crash {
	c := CrashFrom(rr, pathSig)
	if !FramesResolved(c) {
		c.PathSig = c.PathSig + "|" + PoVDiscriminator(pov)
	}
	return c
}

// SemanticIdentity keys a SEMANTIC finding (no crash frames): the executed observation is identity; sig must be symbol-shaped.
func SemanticIdentity(class, sig, pathSig string) Crash {
	return Crash{BugClass: class, Frames: []string{sig}, PathSig: pathSig}
}

// one definition so every producer that splits on the PoV splits identically
func PoVDiscriminator(pov []byte) string {
	sum := sha256.Sum256(pov)
	return "pov=" + hex.EncodeToString(sum[:8])
}

// a frame-less crash's ONLY key component: never invent another token
func PathSigFor(stdinPoV bool) string {
	if stdinPoV {
		return "stdin"
	}
	return "argv"
}

func signalClass(sig int) string {
	switch sig {
	case 11, 7: // SIGSEGV, SIGBUS
		return "memory-safety-crash"
	case 6: // SIGABRT
		return "abort"
	case 8: // SIGFPE
		return "arithmetic-fault"
	case 0:
		return "objective-met"
	default:
		return fmt.Sprintf("signal-%d-crash", sig)
	}
}

const crashN = 5

// most-specific first: ComputeBehavioralKey takes [0]
func CrashKeys(c Crash) []string {
	frames := normalizedFrames(c)
	base := crashBase(c)

	var keys []string
	seen := map[string]bool{}
	add := func(scope string) {
		k := "bk:" + hex.EncodeToString(sha256sum(base + "|" + scope))[:32]
		if !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	if len(frames) > 0 {
		n := crashN
		if n > len(frames) {
			n = len(frames)
		}
		add("frames=" + strings.Join(frames[:n], ">"))
		add("site=" + frames[0])
	} else {
		add("path=" + strings.ToLower(strings.TrimSpace(c.PathSig)))
	}
	return keys
}

// keep in lockstep with the Worker's crashKeys
func crashBase(c Crash) string {
	san := strings.ToLower(strings.TrimSpace(c.Sanitizer))
	sig := c.Signal
	if san != "" {
		sig = 0
	}
	return fmt.Sprintf("bug=%s|sig=%d|san=%s", strings.ToLower(strings.TrimSpace(c.BugClass)), sig, san)
}

func sha256sum(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

func normalizedFrames(c Crash) []string {
	src := c.Frames
	if len(src) == 0 {
		src = c.Sites
	}
	out := make([]string, 0, len(src))
	for _, f := range src {
		if nf := normalizeFrame(f); nf != "" {
			out = append(out, nf)
		}
	}
	return out
}

// frame-less ⇒ no discriminator: callers must NOT merge on the coarse key
func FramesResolved(c Crash) bool { return len(normalizedFrames(c)) > 0 }

var reTemplateArgs = regexp.MustCompile(`<[^<>]*>`)

// trailing source location, dropped so keys stay path/line independent
var reFrameLocation = regexp.MustCompile(`\s+\S*:\d+(?::\d+)?$`)

// build variants of one frame must hash alike
func normalizeFrame(s string) string {
	s = strings.TrimSpace(s)
	if m := reFrameLocation.FindStringIndex(s); m != nil {
		s = s[:m[0]]
	}
	s = strings.TrimPrefix(s, "(anonymous namespace)::")
	if i := strings.Index(s, "("); i > 0 { // i>0: a leading (anon…) must not empty the frame
		s = s[:i]
	}
	for {
		r := reTemplateArgs.ReplaceAllString(s, "")
		if r == s {
			break
		}
		s = r
	}
	return strings.ToLower(strings.TrimSpace(stripReturnType(s)))
}

// only a recognizable TYPE prefix drops, else unrelated bugs false-merge (vault: Artifact Identity)
func stripReturnType(s string) string {
	f := strings.Fields(s)
	if len(f) < 2 {
		return s
	}
	for len(f) > 1 && isTypeToken(f[0]) {
		f = f[1:]
	}
	// two space-separated qualified names ⇒ the first is the return type
	if len(f) == 2 && strings.Contains(f[0], "::") && strings.Contains(f[1], "::") {
		f = f[1:]
	}
	return strings.Join(f, " ")
}

// "operator new"/"operator unsigned int" keep their space: those tokens are the symbol
func isTypeToken(t string) bool {
	switch t {
	case "void", "bool", "char", "short", "int", "long", "unsigned", "signed", "float", "double",
		"auto", "const", "volatile", "static", "virtual", "inline", "constexpr", "struct", "class",
		"enum", "union":
		return true
	}
	return strings.HasSuffix(t, "*") || strings.HasSuffix(t, "&")
}

// Provenance is envelope only: not hashed into the id.
type Provenance struct {
	ExperimentID string   `json:"experiment_id,omitempty"`
	RunID        string   `json:"run_id,omitempty"`
	Model        string   `json:"model,omitempty"`
	ToolHashes   []string `json:"tool_hashes,omitempty"`
	AcquiredBy   string   `json:"acquired_by,omitempty"`
	Project      string   `json:"project,omitempty"`
}

// Signature: only a non-self-reproducing artifact may carry one.
type Signature struct {
	Alg       string `json:"alg"`
	PublicKey string `json:"public_key"`
	Sig       string `json:"sig"`
}

// Envelope fields never affect the artifact id.
type Envelope struct {
	Artifact   Artifact   `json:"artifact"`
	Placement  Placement  `json:"placement"`
	Abstract   string     `json:"abstract,omitempty"`
	Provenance Provenance `json:"provenance"`
	Signature  *Signature `json:"signature,omitempty"`
	CreatedAt  string     `json:"created_at,omitempty"`
}

func (e *Envelope) IntegrityTier() IntegrityTier {
	switch {
	case e.Artifact.SelfReproducing():
		return SelfReproducing
	case e.Signature != nil:
		return CanonicalConsistent
	default:
		return ProvenanceAsserted
	}
}

func (e *Envelope) sigPreimage(signerPub string) ([]byte, error) {
	m := struct {
		ArtifactID string     `json:"artifact_id"`
		Placement  Placement  `json:"placement"`
		Abstract   string     `json:"abstract"`
		Provenance Provenance `json:"provenance"`
		SignerKey  string     `json:"signer_key"`
	}{e.Artifact.ID, e.Placement, e.Abstract, e.Provenance, signerPub}
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return append([]byte(sigDomain), b...), nil
}

func (e *Envelope) Sign(priv ed25519.PrivateKey) error {
	if err := e.Artifact.ComputeID(); err != nil {
		return err
	}
	if e.Artifact.SelfReproducing() {
		return fmt.Errorf("artifact: self-reproducing artifacts must stay unsigned")
	}
	pub := hex.EncodeToString(priv.Public().(ed25519.PublicKey))
	msg, err := e.sigPreimage(pub)
	if err != nil {
		return err
	}
	e.Signature = &Signature{Alg: "ed25519", PublicKey: pub, Sig: hex.EncodeToString(ed25519.Sign(priv, msg))}
	return nil
}

// Verify is the anti-poisoning gate (vault: Artifact Identity).
func (e *Envelope) Verify() error {
	if !e.Placement.Valid() {
		return fmt.Errorf("artifact: invalid placement %q", e.Placement)
	}
	want, err := recomputeID(&e.Artifact)
	if err != nil {
		return err
	}
	if e.Artifact.ID != want {
		return fmt.Errorf("artifact: id mismatch: have %s want %s", e.Artifact.ID, want)
	}
	if e.Artifact.SelfReproducing() {
		if e.Signature != nil {
			return fmt.Errorf("artifact: self-reproducing artifact must not carry a signature")
		}
		return nil
	}
	if e.Signature == nil {
		return nil // provenance-asserted, unsigned: weakest but valid
	}
	if e.Signature.Alg != "ed25519" {
		return fmt.Errorf("artifact: unsupported signature alg %q", e.Signature.Alg)
	}
	pub, err := hex.DecodeString(e.Signature.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("artifact: bad public key")
	}
	sig, err := hex.DecodeString(e.Signature.Sig)
	if err != nil {
		return fmt.Errorf("artifact: bad signature encoding")
	}
	msg, err := e.sigPreimage(e.Signature.PublicKey)
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), msg, sig) {
		return fmt.Errorf("artifact: signature verification failed")
	}
	return nil
}

// hash a copy: must not disturb the caller's stored id
func recomputeID(a *Artifact) (string, error) {
	cp := *a
	if err := cp.ComputeID(); err != nil {
		return "", err
	}
	return cp.ID, nil
}

func (e *Envelope) Marshal() ([]byte, error) { return json.MarshalIndent(e, "", "  ") }

func Unmarshal(data []byte) (*Envelope, error) {
	var e Envelope
	if err := json.Unmarshal(data, &e); err != nil {
		return nil, err
	}
	return &e, nil
}
