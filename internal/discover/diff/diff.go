// Package diff parses a unified diff into files, hunks and changed symbol names.
package diff

import (
	"regexp"
	"strconv"
	"strings"
)

type Diff struct {
	Files []File
}

type File struct {
	OldPath string
	NewPath string
	Hunks   []Hunk
	Symbols []string
}

type Hunk struct {
	OldStart, OldLines int
	NewStart, NewLines int
	Context            string   // @@ section heading: git's last preceding signature
	Added              []string // added lines, '+' stripped
	Removed            []string // removed lines, '-' stripped
	// markers intact, in file order: contextEncloses needs the interleaving
	Body []string
}

// Path is the file's post-change path (its pre-change path if deleted).
func (f File) Path() string {
	if f.NewPath != "" && f.NewPath != "/dev/null" {
		return f.NewPath
	}
	return f.OldPath
}

func (f File) Stat() (added, removed int) {
	for _, h := range f.Hunks {
		added += len(h.Added)
		removed += len(h.Removed)
	}
	return
}

func (d *Diff) Symbols() []string {
	var out []string
	seen := map[string]bool{}
	for _, f := range d.Files {
		for _, s := range f.Symbols {
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	return out
}

var hunkRe = regexp.MustCompile(`^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(.*)$`)

// Lenient: a git header, a plain `diff -u`, or a bare hunk all parse.
func Parse(data []byte) (*Diff, error) {
	d := &Diff{}
	var cur *File
	var hunk *Hunk
	flushHunk := func() {
		if cur != nil && hunk != nil {
			cur.Hunks = append(cur.Hunks, *hunk)
			hunk = nil
		}
	}
	flushFile := func() {
		flushHunk()
		if cur != nil {
			d.Files = append(d.Files, *cur)
			cur = nil
		}
	}
	lines := splitLines(data)
	oldOwed, newOwed := 0, 0
	sawOldHeader := false
	for i, line := range lines {
		next := ""
		if i+1 < len(lines) {
			next = lines[i+1]
		}
		// the @@ counts decide what is body: content must never rewrite the path
		if hunk != nil && (oldOwed > 0 || newOwed > 0) {
			if addBodyLine(hunk, line, &oldOwed, &newOwed) {
				sawOldHeader = false
				continue
			}
			flushHunk()
		}
		// compute before flushHunk below: it clears hunk, which these two read
		prevOldHeader := sawOldHeader
		isOld := isOldFileHeader(line, next, hunk != nil)
		sawOldHeader = isOld
		switch {
		case strings.HasPrefix(line, "diff --git "):
			flushFile()
			cur = &File{}
			cur.OldPath, cur.NewPath = gitPaths(line)
		case isOld:
			// a plain `diff -uNr` has no `diff --git ` line to flush the previous file on
			if cur != nil && (len(cur.Hunks) > 0 || hunk != nil) {
				flushFile()
			}
			if cur == nil {
				cur = &File{}
			}
			cur.OldPath = trimPath(line[4:])
		case isNewFileHeader(line, prevOldHeader, hunk != nil):
			if cur == nil {
				cur = &File{}
			}
			cur.NewPath = trimPath(line[4:])
		case strings.HasPrefix(line, "@@ "):
			if cur == nil {
				cur = &File{}
			}
			flushHunk()
			if h, ok := parseHunkHeader(line); ok {
				hunk = &h
				oldOwed, newOwed = h.OldLines, h.NewLines
			}
		default:
			// past the declared extent: still collect body lines, but end on a non-body line
			if hunk == nil {
				continue
			}
			if !addBodyLine(hunk, line, &oldOwed, &newOwed) {
				flushHunk()
			}
		}
	}
	flushFile()
	for i := range d.Files {
		d.Files[i].Symbols = extractSymbols(d.Files[i])
	}
	return d, nil
}

// terminators (incl. a CRLF's \r) dropped: the parser needs one-line lookahead
func splitLines(data []byte) []string {
	s := strings.TrimSuffix(string(data), "\n")
	if s == "" {
		return nil
	}
	out := strings.Split(s, "\n")
	for i := range out {
		out[i] = strings.TrimSuffix(out[i], "\r")
	}
	return out
}

// false means the line is not diff-body shaped: the @@ counts over-declared
func addBodyLine(h *Hunk, line string, oldOwed, newOwed *int) bool {
	if line == "" { // an emptied context line
		*oldOwed--
		*newOwed--
		h.Body = append(h.Body, line)
		return true
	}
	switch line[0] {
	case '+':
		h.Added = append(h.Added, line[1:])
		*newOwed--
	case '-':
		h.Removed = append(h.Removed, line[1:])
		*oldOwed--
	case ' ':
		*oldOwed--
		*newOwed--
	case '\\': // "\ No newline at end of file" — counts toward neither side
	default:
		return false
	}
	h.Body = append(h.Body, line)
	return true
}

// past the @@ counts a "--- " is a header only as the first half of the "--- "/"+++ " pair
func isOldFileHeader(line, next string, inHunk bool) bool {
	if !strings.HasPrefix(line, "--- ") {
		return false
	}
	return !inHunk || strings.HasPrefix(next, "+++ ")
}

// the "+++ " half: with a hunk open it needs the "--- " half on the previous line
func isNewFileHeader(line string, sawOldHeader, inHunk bool) bool {
	if !strings.HasPrefix(line, "+++ ") {
		return false
	}
	return !inHunk || sawOldHeader
}

func gitPaths(line string) (old, new string) {
	fields := strings.Fields(strings.TrimPrefix(line, "diff --git "))
	if len(fields) >= 2 {
		return trimPath(fields[0]), trimPath(fields[len(fields)-1])
	}
	return "", ""
}

// strips the a/ or b/ prefix and any trailing tab-separated timestamp
func trimPath(p string) string {
	if i := strings.IndexByte(p, '\t'); i >= 0 {
		p = p[:i]
	}
	p = strings.TrimSpace(p)
	if p == "/dev/null" {
		return p
	}
	if strings.HasPrefix(p, "a/") || strings.HasPrefix(p, "b/") {
		return p[2:]
	}
	return p
}

func parseHunkHeader(line string) (Hunk, bool) {
	m := hunkRe.FindStringSubmatch(line)
	if m == nil {
		return Hunk{}, false
	}
	return Hunk{
		OldStart: atoi(m[1]), OldLines: atoiDef(m[2], 1),
		NewStart: atoi(m[3]), NewLines: atoiDef(m[4], 1),
		Context: strings.TrimSpace(m[5]),
	}, true
}

func atoi(s string) int { n, _ := strconv.Atoi(s); return n }

func atoiDef(s string, def int) int {
	if s == "" {
		return def
	}
	return atoi(s)
}
