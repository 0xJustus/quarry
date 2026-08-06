package hydrate

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/0xjustus/quarry/internal/intake/target"
	"github.com/0xjustus/quarry/internal/verdict/oracle"
)

type ARVOMeta struct {
	LocalID   int             `json:"localId"`
	Project   string          `json:"project"`
	Fix       string          `json:"fix"` // patch commit URL
	Sanitizer string          `json:"sanitizer"`
	CrashType string          `json:"crash_type"`
	FixCommit json.RawMessage `json:"fix_commit"` // string OR array of shas
	Report    json.RawMessage `json:"report"`     // string OR {comments:[…]}
}

type ARVOSource struct {
	MetaBaseURL string // raw base for per-id JSON
	MetaRepo    string // owner/repo for the corpus listing
	ImageRepo   string // Docker repo holding vul/fix images
	TimeoutS    int    // per reproduce-run bound
	HTTP        *http.Client
}

func (s ARVOSource) metaBase() string {
	if s.MetaBaseURL != "" {
		return strings.TrimRight(s.MetaBaseURL, "/")
	}
	return "https://raw.githubusercontent.com/n132/ARVO-Meta/main/archive_data/meta"
}

func (s ARVOSource) imageRepo() string {
	if s.ImageRepo != "" {
		return s.ImageRepo
	}
	return "n132/arvo"
}

func (s ARVOSource) timeoutS() int {
	if s.TimeoutS > 0 {
		return s.TimeoutS
	}
	return 300
}

func (s ARVOSource) httpClient() *http.Client {
	if s.HTTP != nil {
		return s.HTTP
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (s ARVOSource) FetchMeta(ctx context.Context, id int) (ARVOMeta, error) {
	url := fmt.Sprintf("%s/%d.json", s.metaBase(), id)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return ARVOMeta{}, err
	}
	resp, err := s.httpClient().Do(req)
	if err != nil {
		return ARVOMeta{}, fmt.Errorf("arvo: fetch meta %d: %w", id, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ARVOMeta{}, fmt.Errorf("arvo: meta %d: HTTP %d", id, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20)) // reports can be large
	if err != nil {
		return ARVOMeta{}, err
	}
	var m ARVOMeta
	if err := json.Unmarshal(body, &m); err != nil {
		return ARVOMeta{}, fmt.Errorf("arvo: parse meta %d: %w", id, err)
	}
	if m.LocalID == 0 {
		m.LocalID = id
	}
	return m, nil
}

func (s ARVOSource) Entries(ctx context.Context, ids []int) ([]Entry, error) {
	out := make([]Entry, 0, len(ids))
	for _, id := range ids {
		m, err := s.FetchMeta(ctx, id)
		if err != nil {
			return nil, err
		}
		out = append(out, s.entry(m))
	}
	return out, nil
}

func (s ARVOSource) entry(m ARVOMeta) Entry {
	vul := fmt.Sprintf("%s:%d-vul", s.imageRepo(), m.LocalID)
	fix := fmt.Sprintf("%s:%d-fix", s.imageRepo(), m.LocalID)
	san := mapSanitizer(m.Sanitizer)

	// the payload is a tiny ref manifest; the testcase is baked into the image
	manifest, _ := json.Marshal(map[string]any{
		"source": "arvo", "arvo_id": m.LocalID, "project": m.Project,
		"vul_image": vul, "fix_image": fix, "reproduce": []string{"arvo"},
		"sanitizer": san, "crash_type": m.CrashType, "fix_commit": m.Fix,
	})

	return Entry{
		ID:      fmt.Sprintf("arvo-%d", m.LocalID),
		Project: m.Project,
		Vuln:    target.Ingest{Kind: target.KindImage, Image: vul},
		Fix:     target.Ingest{Kind: target.KindImage, Image: fix},
		Run: target.RunConfig{
			Argv:      []string{"arvo"},
			Sanitizer: san,
			NoPoV:     true,
			TimeoutS:  s.timeoutS(),
		},
		Oracle:       arvoOracle(fix, san),
		Testcase:     manifest,
		BugClassHint: normalizeCrashType(m.CrashType),
	}
}

// vul reproduce terminates abnormally, fix run is clean
func arvoOracle(fixImage, san string) oracle.Spec {
	zero := 0
	conds := []oracle.Condition{
		{Type: oracle.CondExit, ExitCode: &oracle.IntMatch{Ne: &zero}},
		{Type: oracle.CondSignal, Signals: []string{"SIGSEGV", "SIGABRT", "SIGBUS", "SIGFPE", "SIGILL"}},
	}
	if san != "" {
		conds = append(conds, oracle.Condition{Type: oracle.CondSanitizer, Tool: san})
	}
	return oracle.Spec{
		Require:      "any",
		Conditions:   conds,
		Differential: &oracle.Differential{FixedImage: fixImage, Rule: oracle.PassOnVulnFailOnFixed},
	}
}

func mapSanitizer(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "asan", "address":
		return "asan"
	case "ubsan", "undefined":
		return "ubsan"
	case "msan", "memory":
		return "msan"
	case "tsan", "thread":
		return "tsan"
	default:
		return ""
	}
}

func normalizeCrashType(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, " ", "-")
	return s
}
