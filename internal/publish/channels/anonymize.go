package channels

import (
	"context"
	"os/user"
	"strings"

	"github.com/0xjustus/quarry/internal/publish/artifact"
	"github.com/0xjustus/quarry/internal/publish/redact"
)

type RealAnonymizer struct {
	KeepFrames int // >0 caps frames; changes the content id, so off by default
	userName   string
}

func NewRealAnonymizer() *RealAnonymizer {
	return &RealAnonymizer{userName: currentUserName()}
}

// "" when the name is too short to substitute safely
func currentUserName() string {
	u, err := user.Current()
	if err != nil {
		return ""
	}
	if name := strings.TrimSpace(u.Username); len(name) >= 3 {
		return name
	}
	return ""
}

func (a *RealAnonymizer) Anonymize(_ context.Context, e *artifact.Envelope) (*artifact.Envelope, error) {
	if e == nil {
		return e, nil
	}
	out := *e
	art := e.Artifact
	crash := art.Content.Crash

	crash.Sites = a.redactSlice(crash.Sites)
	crash.Frames = a.redactSlice(crash.Frames)
	crash.DedupToken = a.redact(crash.DedupToken)
	crash.PathSig = a.redact(crash.PathSig)

	if a.KeepFrames > 0 && len(crash.Frames) > a.KeepFrames {
		crash.Frames = crash.Frames[:a.KeepFrames]
	}

	art.Content.Crash = crash
	out.Artifact = art
	out.Abstract = a.redact(e.Abstract)

	// provenance rides to the public sibling verbatim: scrub its free text too
	prov := out.Provenance
	prov.Model = a.redact(prov.Model)
	prov.ExperimentID = a.redact(prov.ExperimentID)
	prov.RunID = a.redact(prov.RunID)
	prov.AcquiredBy = a.redact(prov.AcquiredBy)
	prov.Project = a.redact(prov.Project)
	prov.ToolHashes = a.redactSlice(prov.ToolHashes)
	out.Provenance = prov

	return &out, nil
}

func (a *RealAnonymizer) redactSlice(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = a.redact(s)
	}
	return out
}

func (a *RealAnonymizer) redact(s string) string {
	if s == "" {
		return s
	}
	s = redact.Paths(s, redact.KeepBasename)
	// email/ip/name scrubbing deliberately also runs inside URL spans
	s = redact.Email.ReplaceAllString(s, "<redacted-email>")
	s = redact.IPv4.ReplaceAllString(s, "<redacted-ip>")
	s = redact.IPv6.ReplaceAllString(s, "<redacted-ip>")
	if a.userName != "" {
		s = strings.ReplaceAll(s, a.userName, "<user>")
	}
	return s
}
