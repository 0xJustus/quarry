package diff

import "strings"

// control words that precede a '(' but are not function names
var keywords = map[string]bool{
	"if": true, "for": true, "while": true, "switch": true, "return": true,
	"sizeof": true, "do": true, "else": true, "catch": true, "case": true,
	"func": true, "defer": true, "go": true, "select": true, "with": true,
}

func extractSymbols(f File) []string {
	var out []string
	seen := map[string]bool{}
	add := func(name string) {
		if name == "" || keywords[name] || seen[name] {
			return
		}
		seen[name] = true
		out = append(out, name)
	}
	for _, h := range f.Hunks {
		if contextEncloses(h) {
			add(funcName(h.Context))
		}
		for _, l := range h.Removed {
			if name, ok := defLine(l); ok {
				add(name)
			}
		}
		for _, l := range h.Added {
			if name, ok := defLine(l); ok {
				add(name)
			}
		}
	}
	return out
}

// fail closed: an unattributable change must not implicate the @@ heading
func contextEncloses(h Hunk) bool {
	for _, l := range h.Body {
		if l == "" {
			continue
		}
		switch l[0] {
		case '+', '-':
			return true
		case ' ':
			if strings.HasPrefix(l[1:], "}") { // a '}' at column 0 ends a top-level body
				return false
			}
		}
	}
	return false
}

// reject statements: a harvested name becomes a false "within the diff" claim
func defLine(line string) (string, bool) {
	t := strings.TrimSpace(line)
	if t == "" || !strings.Contains(t, "(") {
		return "", false
	}
	if strings.HasPrefix(t, "func ") || strings.HasPrefix(t, "func(") {
		name := funcName(t)
		if name == "" || keywords[name] {
			return "", false
		}
		return name, true
	}
	if strings.HasSuffix(t, ";") || (!strings.Contains(t, "{") && t[len(t)-1] != ')') {
		return "", false
	}
	open := strings.IndexByte(t, '(')
	// an '=' before that '(': the paren belongs to a call on a right-hand side
	if strings.Contains(t[:open], "=") {
		return "", false
	}
	name := funcName(t)
	if name == "" || keywords[name] {
		return "", false
	}
	if decl := declPrefix(t[:open]); decl != "" {
		if !isDeclarator(decl) {
			return "", false
		}
	} else if line != strings.TrimLeft(line, " \t") {
		// column 0 with no declarator = definition (return type on prev line); indented = bare call
		return "", false
	}
	return name, true
}

func splitTrailingIdent(s string) (before, ident string) {
	end := len(s)
	for end > 0 && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	start := end
	for start > 0 && isIdent(s[start-1]) {
		start--
	}
	return s[:start], s[start:end]
}

// the text before a name in "<decl> name("
func declPrefix(pre string) string {
	before, _ := splitTrailingIdent(pre)
	return strings.TrimRight(before, " \t")
}

// a definition has a return type, storage class, '*'/'&' or "Class::"; a call has none
func isDeclarator(decl string) bool {
	if decl == "" {
		return false
	}
	if strings.HasSuffix(decl, "->") || strings.HasSuffix(decl, ".") {
		return false
	}
	last := decl[len(decl)-1]
	if !isIdent(last) && last != '*' && last != '&' && last != ':' && last != '>' {
		return false
	}
	return !keywords[trailingIdent(decl)]
}

func funcName(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if rest, ok := strings.CutPrefix(s, "func"); ok && (rest == "" || rest[0] == ' ' || rest[0] == '(') {
		rest = strings.TrimSpace(rest)
		if strings.HasPrefix(rest, "(") { // method receiver
			if i := matchParen(rest); i >= 0 {
				rest = strings.TrimSpace(rest[i+1:])
			}
		}
		return leadingIdent(rest)
	}
	i := strings.IndexByte(s, '(')
	if i < 0 {
		return ""
	}
	return trailingIdent(s[:i])
}

// index of the ')' matching the '(' at s[0], or -1
func matchParen(s string) int {
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			if depth--; depth == 0 {
				return i
			}
		}
	}
	return -1
}

func leadingIdent(s string) string {
	s = strings.TrimSpace(s)
	i := 0
	for i < len(s) && isIdent(s[i]) {
		i++
	}
	return validIdent(s[:i])
}

func trailingIdent(s string) string {
	_, ident := splitTrailingIdent(s)
	return validIdent(ident)
}

func validIdent(s string) string {
	if s == "" || (s[0] >= '0' && s[0] <= '9') {
		return ""
	}
	return s
}

func isIdent(b byte) bool {
	return b == '_' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// whole-identifier match, so ns::parse_header resolves to parse_header
func (d *Diff) MatchSymbol(frame string) string {
	frame = strings.TrimSpace(frame)
	if frame == "" {
		return ""
	}
	for _, s := range d.Symbols() {
		if tokenMatch(frame, s) {
			return s
		}
	}
	return ""
}

func tokenMatch(frame, sym string) bool {
	if sym == "" {
		return false
	}
	if frame == sym {
		return true
	}
	for i := 0; i+len(sym) <= len(frame); {
		j := strings.Index(frame[i:], sym)
		if j < 0 {
			return false
		}
		k := i + j
		before := k == 0 || !isIdent(frame[k-1])
		after := k+len(sym) >= len(frame) || !isIdent(frame[k+len(sym)])
		if before && after {
			return true
		}
		i = k + 1
	}
	return false
}
