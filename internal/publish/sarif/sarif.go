// Package sarif renders verification outcomes as SARIF 2.1.0 and reads inbound logs back.
package sarif

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

const (
	version  = "2.1.0"
	schema   = "https://json.schemastore.org/sarif-2.1.0.json"
	toolName = "quarry"
	toolVer  = "0.1.0"
	infoURI  = "https://github.com/0xjustus/quarry"

	// wire identity: downstream dedup keys on this, and Parse reads it back
	behavioralKeyFP = "quarry/behavioralKey/v1"
	framesFP        = "quarry/frames/v1"
)

type Input struct {
	Confirmed     bool
	Verdict       string // real-crash | divergence | hang | unconfirmed
	BugClass      string
	CrashSite     string
	BehavioralKey string
	Frames        []string // call-ordered
	// zero value is NOT isolated: never claim an air gap the caller did not attest
	NetworkIsolated bool
	Detail          string
}

type Opts struct {
	SrcRoot  string
	Repo     string
	Revision string
}

type Report struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []Run  `json:"runs"`
}
type Run struct {
	Tool                     Tool                `json:"tool"`
	OriginalURIBaseIDs       map[string]Artifact `json:"originalUriBaseIds,omitempty"`
	VersionControlProvenance []VCS               `json:"versionControlProvenance,omitempty"`
	Results                  []Result            `json:"results"`
}
type VCS struct {
	RepositoryURI string `json:"repositoryUri"`
	RevisionID    string `json:"revisionId,omitempty"`
	Branch        string `json:"branch,omitempty"`
}
type Tool struct {
	Driver Driver `json:"driver"`
}
type Driver struct {
	Name           string `json:"name"`
	InformationURI string `json:"informationUri,omitempty"`
	Version        string `json:"version,omitempty"`
	Rules          []Rule `json:"rules,omitempty"`
}
type Rule struct {
	ID               string   `json:"id"`
	Name             string   `json:"name,omitempty"`
	ShortDescription *Message `json:"shortDescription,omitempty"`
}
type Result struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             Message           `json:"message"`
	GUID                string            `json:"guid,omitempty"`
	CorrelationGUID     string            `json:"correlationGuid,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	Fingerprints        map[string]string `json:"fingerprints,omitempty"`
	Locations           []Location        `json:"locations,omitempty"`
	Properties          map[string]any    `json:"properties,omitempty"`
}
type Message struct {
	Text string `json:"text"`
}
type Location struct {
	PhysicalLocation *Physical `json:"physicalLocation,omitempty"`
	LogicalLocations []Logical `json:"logicalLocations,omitempty"`
}
type Physical struct {
	ArtifactLocation Artifact `json:"artifactLocation"`
	Region           *Region  `json:"region,omitempty"`
}
type Artifact struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId,omitempty"`
}
type Region struct {
	StartLine int `json:"startLine"`
}
type Logical struct {
	FullyQualifiedName string `json:"fullyQualifiedName"`
	Kind               string `json:"kind,omitempty"`
}

func Build(in Input, opts Opts) Report {
	ruleID, level := ruleAndLevel(in)

	qp := map[string]any{
		"verdict":          in.Verdict,
		"confirmed":        in.Confirmed,
		"method":           methodFor(in),
		"network_isolated": in.NetworkIsolated,
		// claim about THIS result: corroborated AND isolated, else publish false
		"forge_resistant": in.Confirmed && in.NetworkIsolated,
	}
	res := Result{
		RuleID:     ruleID,
		Level:      level,
		Message:    Message{Text: message(in)},
		GUID:       randomGUID(),
		Properties: map[string]any{"quarry": qp, "security-severity": securitySeverity(in)},
	}
	if in.BehavioralKey != "" {
		res.CorrelationGUID = stableGUID(in.BehavioralKey)
		res.PartialFingerprints = map[string]string{behavioralKeyFP: in.BehavioralKey}
		qp["behavioral_key"] = in.BehavioralKey
	}
	if len(in.Frames) > 0 {
		if res.PartialFingerprints == nil {
			res.PartialFingerprints = map[string]string{}
		}
		res.PartialFingerprints[framesFP] = shortHash(strings.Join(in.Frames, "\n"))
		qp["frames"] = in.Frames
	}
	if loc := locationFor(in, opts.SrcRoot); loc != nil {
		res.Locations = []Location{*loc}
	}
	return Report{Schema: schema, Version: version, Runs: []Run{newRun([]Rule{ruleFor(ruleID)}, []Result{res}, opts)}}
}

func newRun(rules []Rule, results []Result, opts Opts) Run {
	run := Run{
		Tool: Tool{Driver: Driver{
			Name:           toolName,
			InformationURI: infoURI,
			Version:        toolVer,
			Rules:          rules,
		}},
		Results: results,
	}
	if opts.SrcRoot != "" {
		run.OriginalURIBaseIDs = map[string]Artifact{"SRCROOT": {URI: toFileURI(opts.SrcRoot)}}
	}
	if opts.Repo != "" || opts.Revision != "" {
		run.VersionControlProvenance = []VCS{{RepositoryURI: opts.Repo, RevisionID: opts.Revision}}
	}
	return run
}

func ruleAndLevel(in Input) (string, string) {
	switch {
	case in.Confirmed && in.Verdict == "hang":
		return "hang", "error"
	case in.Confirmed && in.Verdict == "divergence":
		return "spec-divergence", "error"
	case in.Confirmed:
		if in.BugClass != "" {
			return in.BugClass, "error"
		}
		return "memory-safety-crash", "error"
	default:
		return "unconfirmed", "note"
	}
}

func securitySeverity(in Input) string {
	switch {
	case !in.Confirmed:
		return "0.0"
	case in.Verdict == "hang":
		return "5.3"
	case in.Verdict == "divergence":
		return "6.5"
	default:
		return "8.1"
	}
}

func reexecMethod(in Input) string {
	if in.NetworkIsolated {
		return "air-gapped re-execution"
	}
	return "deterministic re-execution (network not isolated)"
}

func methodFor(in Input) string {
	m := reexecMethod(in)
	if !in.Confirmed {
		return m + " (did not reproduce)"
	}
	return m
}

func detailSuffix(in Input) string {
	d := strings.TrimSpace(in.Detail)
	if d == "" {
		return ""
	}
	return " Observed: " + d
}

func message(in Input) string {
	method := reexecMethod(in)
	switch {
	case !in.Confirmed:
		return "Did not reproduce a real crash, hang or divergence on " + method + "; not a verified finding. " +
			"(Per ossf/oss-crs#310 this is a note, not a shared false-positive status.)" + detailSuffix(in)
	case in.Verdict == "hang":
		return "Oracle-confirmed hang / DoS: the candidate did not terminate within the wall-clock cap under " +
			method + ". A forged report cannot fabricate this." + detailSuffix(in)
	case in.Verdict == "divergence":
		// covers single-run metamorphic: must not assert a reference build ran
		return "Oracle-confirmed spec divergence (non-crash): under " + method + " the target's executed " +
			"output violated a declared reference, baseline or metamorphic relation. quarry EXECUTES the " +
			"target and checks the relation — a forged report cannot fabricate this. This is a logic/spec " +
			"bug, not a memory-safety crash." + detailSuffix(in)
	default:
		bc := in.BugClass
		if bc == "" {
			bc = "memory-safety crash"
		}
		site := ""
		if in.CrashSite != "" {
			site = " at " + strings.TrimSpace(in.CrashSite)
		}
		return fmt.Sprintf("Oracle-confirmed real %s%s, verified by %s under sanitizer with "+
			"abnormal-termination corroboration (a forged sanitizer line on a clean exit is rejected). Behavioral key %s.%s",
			bc, site, method, in.BehavioralKey, detailSuffix(in))
	}
}

func ruleFor(id string) Rule {
	var desc string
	switch id {
	case "hang":
		desc = "Confirmed hang / DoS (non-crash): no termination within the wall-clock cap."
	case "spec-divergence":
		// covers single-run metamorphic: must not assert a reference build ran
		desc = "Oracle-confirmed spec divergence (non-crash): executed output violates a declared reference, baseline or metamorphic relation."
	case "unconfirmed":
		desc = "Candidate did not reproduce under re-execution (not a verified finding)."
	default:
		desc = "Oracle-confirmed memory-safety crash, corroborated by abnormal termination."
	}
	return Rule{ID: id, Name: id, ShortDescription: &Message{Text: desc}}
}

var fileLineRe = regexp.MustCompile(`([\w./+-]+\.[A-Za-z]\w*):(\d+)`)

func locationFor(in Input, srcRoot string) *Location {
	site := strings.TrimSpace(in.CrashSite)
	if site == "" && len(in.Frames) > 0 {
		site = strings.TrimSpace(in.Frames[0])
	}
	if site == "" {
		return nil
	}
	loc := &Location{LogicalLocations: []Logical{{FullyQualifiedName: site, Kind: "function"}}}
	if m := fileLineRe.FindStringSubmatch(site); m != nil {
		phys := &Physical{ArtifactLocation: srcArtifact(m[1], srcRoot)}
		// startLine minimum is 1: emitting :0 makes a validator reject the whole log
		if line, err := strconv.Atoi(m[2]); err == nil && line > 0 {
			phys.Region = &Region{StartLine: line}
		}
		loc.PhysicalLocation = phys
	}
	return loc
}

// uriBaseId requires a RELATIVE uri; a path outside srcRoot must stay unbased
func srcArtifact(file, srcRoot string) Artifact {
	if srcRoot == "" {
		return Artifact{URI: file}
	}
	if !strings.HasPrefix(file, "/") {
		return Artifact{URI: file, URIBaseID: "SRCROOT"}
	}
	if root := rootPath(srcRoot); root != "" && strings.HasPrefix(file, root+"/") {
		if rel := strings.TrimPrefix(file, root+"/"); rel != "" {
			return Artifact{URI: rel, URIBaseID: "SRCROOT"}
		}
	}
	return Artifact{URI: file}
}

// a non-file uri has no local prefix to re-base against
func rootPath(srcRoot string) string {
	if strings.Contains(srcRoot, "://") {
		if !strings.HasPrefix(srcRoot, "file://") {
			return ""
		}
		srcRoot = strings.TrimPrefix(srcRoot, "file://")
	}
	return strings.TrimSuffix(srcRoot, "/")
}

func randomGUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmtGUID(b)
}

func stableGUID(seed string) string {
	h := sha256.Sum256([]byte("quarry/correlation/v1\n" + seed))
	var b [16]byte
	copy(b[:], h[:16])
	b[6] = (b[6] & 0x0f) | 0x50
	b[8] = (b[8] & 0x3f) | 0x80
	return fmtGUID(b)
}

func fmtGUID(b [16]byte) string {
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func shortHash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:8])
}

// a base uri names a directory: without the trailing slash RFC 3986 drops the last segment
func toFileURI(p string) string {
	uri := p
	if !strings.Contains(p, "://") {
		uri = "file://" + p
	}
	if !strings.HasSuffix(uri, "/") {
		uri += "/"
	}
	return uri
}
