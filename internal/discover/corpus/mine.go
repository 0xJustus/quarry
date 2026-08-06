package corpus

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// Candidate is a mined silent-fix commit: the -fix (ground-truth reference) side plus its -vuln parent.
type Candidate struct {
	Commit Commit
	Parent string // parent SHA = the -vuln build; empty for a root commit
	Class  Classification
}

type MineOptions struct {
	Repo     string
	Rev      string // default HEAD
	Max      int    // 0 → 500
	DiffCap  int    // 0 → 20000
	PathSpec string
}

// Mine returns the commits classified as security fixes — each a -vuln/-fix candidate.
func Mine(ctx context.Context, opts MineOptions) ([]Candidate, error) {
	if opts.Repo == "" {
		return nil, fmt.Errorf("corpus: Repo is required")
	}
	if opts.Max <= 0 {
		opts.Max = 500
	}
	if opts.DiffCap <= 0 {
		opts.DiffCap = 20000
	}
	rev := opts.Rev
	if rev == "" {
		rev = "HEAD"
	}
	// SHA<TAB>parents<TAB>subject; %P (parents) gives the -vuln side
	shaCmd := []string{"-C", opts.Repo, "log", rev, fmt.Sprintf("--max-count=%d", opts.Max), "--format=%H%x09%P%x09%s"}
	if opts.PathSpec != "" {
		shaCmd = append(shaCmd, "--", opts.PathSpec)
	}
	out, err := git(ctx, shaCmd...)
	if err != nil {
		return nil, fmt.Errorf("corpus: git log: %w", err)
	}
	var cands []Candidate
	for _, line := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "\t", 3)
		if len(parts) < 3 {
			continue
		}
		sha, parents, subject := parts[0], parts[1], parts[2]
		parent := ""
		if ps := strings.Fields(parents); len(ps) > 0 {
			parent = ps[0] // first parent (the -vuln side)
		}
		if len(strings.Fields(parents)) > 1 {
			continue // skip merges: the diff is not a single fix
		}
		c, err := commitDetail(ctx, opts.Repo, sha, subject, opts.DiffCap)
		if err != nil {
			continue
		}
		cl := Classify(c)
		if cl.IsSecurityFix() {
			cands = append(cands, Candidate{Commit: c, Parent: parent, Class: cl})
		}
	}
	return cands, nil
}

func commitDetail(ctx context.Context, repo, sha, subject string, diffCap int) (Commit, error) {
	c := Commit{SHA: sha, Subject: subject}
	if body, err := git(ctx, "-C", repo, "log", "-1", "--format=%b", sha); err == nil {
		c.Body = strings.TrimSpace(body)
	}
	// numstat: <added>\t<deleted>\t<path> per file
	if ns, err := git(ctx, "-C", repo, "show", "--numstat", "--format=", sha); err == nil {
		for _, l := range strings.Split(strings.TrimSpace(ns), "\n") {
			f := strings.Split(l, "\t")
			if len(f) < 3 {
				continue
			}
			a, _ := strconv.Atoi(f[0])
			d, _ := strconv.Atoi(f[1])
			c.Added += a
			c.Deleted += d
			c.Files = append(c.Files, f[2])
		}
	}
	if diff, err := git(ctx, "-C", repo, "show", "--format=", "--unified=3", sha); err == nil {
		if len(diff) > diffCap {
			diff = diff[:diffCap]
		}
		c.Diff = diff
	}
	return c, nil
}

func git(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	out, err := cmd.Output()
	return string(out), err
}
