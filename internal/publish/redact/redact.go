// Package redact is the single identifier battery shared by every redactor and leak scanner.
package redact

import (
	"path/filepath"
	"regexp"
	"strings"
)

var (
	Email = regexp.MustCompile(`\b[\w.+-]+@[\w-]+\.[\w.-]+\b`)
	IPv4  = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	IPv6  = regexp.MustCompile(`(?i)\b[a-f0-9]{1,4}(?::[a-f0-9]{1,4}){2,7}\b|\b[a-f0-9]{1,4}::[a-f0-9]{1,4}(?::[a-f0-9]{1,4}){0,5}\b`)

	// absPath also matches a URL's path component, so it is only ever applied through Paths.
	absPath = regexp.MustCompile(`(?:/[^/\s:")'>\]]+){2,}|[A-Za-z]:\\[^\s:")'>\]]*`)
	// network URLs are upstream reference material; file:// is excluded on purpose
	url = regexp.MustCompile(`(?i)\b(?:https?|ftps?|git|ssh|rsync)://[^\s"'>)\]]+`)
)

// Paths rewrites every absolute-path span OUTSIDE a network URL with repl, leaving URLs verbatim.
func Paths(s string, repl func(string) string) string {
	spans := url.FindAllStringIndex(s, -1)
	if spans == nil {
		return absPath.ReplaceAllStringFunc(s, repl)
	}
	var b strings.Builder
	prev := 0
	for _, sp := range spans {
		b.WriteString(absPath.ReplaceAllStringFunc(s[prev:sp[0]], repl))
		b.WriteString(s[sp[0]:sp[1]])
		prev = sp[1]
	}
	b.WriteString(absPath.ReplaceAllStringFunc(s[prev:], repl))
	return b.String()
}

// HasPath reports whether s carries an absolute path Paths would rewrite (same URL spans as Paths).
func HasPath(s string) bool {
	prev := 0
	for _, sp := range url.FindAllStringIndex(s, -1) {
		if absPath.MatchString(s[prev:sp[0]]) {
			return true
		}
		prev = sp[1]
	}
	return absPath.MatchString(s[prev:])
}

// KeepBasename is the default Paths replacement: drop the directories, keep the file name.
func KeepBasename(p string) string {
	base := filepath.Base(strings.ReplaceAll(p, `\`, `/`))
	if base == "" || base == "." || base == "/" {
		return "<path>"
	}
	return base
}
