//go:build cgo

package loop

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/c"
	"github.com/smacker/go-tree-sitter/cpp"
)

// `(_)` for the callee admits plain, member and C++ qualified/template calls
const sinkQuery = `(call_expression function: (_) @callee arguments: (argument_list) @args)`

// an empty scan must never read as a clean target (vault: Loop Directors)
const StaticScannerAvailable = true

// Language/Query are immutable and shareable; a PARSER is NOT — never hoist one here
var (
	cLang    = c.GetLanguage()
	cppLang  = cpp.GetLanguage()
	cQuery   = mustSinkQuery(cLang)
	cppQuery = mustSinkQuery(cppLang)
)

func mustSinkQuery(lang *sitter.Language) *sitter.Query {
	q, err := sitter.NewQuery([]byte(sinkQuery), lang)
	if err != nil {
		panic("sinkpoint: bad tree-sitter query: " + err.Error())
	}
	return q
}

func languageAndQuery(label string) (*sitter.Language, *sitter.Query) {
	switch strings.ToLower(filepath.Ext(label)) {
	case ".cc", ".cpp", ".cxx", ".c++", ".hpp", ".hh", ".hxx", ".ipp", ".mm":
		return cppLang, cppQuery
	default:
		return cLang, cQuery
	}
}

func scanFileSinks(path, label string, out *[]Sink) {
	fi, err := os.Stat(path)
	if err != nil || fi.IsDir() || fi.Size() > analystMaxReadBytes {
		return
	}
	src, err := os.ReadFile(path)
	if err != nil {
		return
	}
	lang, query := languageAndQuery(label)

	// fresh parser per file: a shared one aborts the process under concurrent scans
	p := sitter.NewParser()
	p.SetLanguage(lang)
	tree, err := p.ParseCtx(context.Background(), nil, src)
	if err != nil || tree == nil {
		return
	}
	defer tree.Close()

	qc := sitter.NewQueryCursor()
	defer qc.Close()
	qc.Exec(query, tree.RootNode())

	lines := strings.Split(string(src), "\n")
	fileCount := 0
	for {
		m, ok := qc.NextMatch()
		if !ok {
			break
		}
		var callee, args *sitter.Node
		for _, cap := range m.Captures {
			switch query.CaptureNameForId(cap.Index) {
			case "callee":
				callee = cap.Node
			case "args":
				args = cap.Node
			}
		}
		if callee == nil {
			continue
		}
		name := calleeName(callee, src)
		info, ok := sinkTable[name]
		if !ok {
			continue
		}
		kind, sev := info.kind, info.sev
		if isAllocToken(name) && name != "calloc" && argsHaveComputedSize(args, src) {
			kind, sev = "alloc-arith", 3
		}
		row := int(callee.StartPoint().Row)
		snip := ""
		if row >= 0 && row < len(lines) {
			snip = snippet(strings.TrimSpace(lines[row]))
		}
		*out = append(*out, Sink{
			File:     label,
			Function: enclosingFunc(callee, src),
			Line:     row + 1,
			Kind:     kind,
			Severity: sev,
			Snippet:  snip,
		})
		fileCount++
		if fileCount >= sinkScanFileCap {
			break
		}
	}
}

func calleeName(n *sitter.Node, src []byte) string {
	switch n.Type() {
	case "identifier", "field_identifier", "type_identifier":
		return n.Content(src)
	case "field_expression":
		if f := n.ChildByFieldName("field"); f != nil {
			return f.Content(src)
		}
	case "qualified_identifier", "template_function":
		if f := n.ChildByFieldName("name"); f != nil {
			return calleeName(f, src)
		}
	}
	s := n.Content(src)
	for _, sep := range []string{"::", "->", "."} {
		if i := strings.LastIndex(s, sep); i >= 0 {
			s = s[i+len(sep):]
		}
	}
	return strings.TrimSpace(s)
}

func argsHaveComputedSize(n *sitter.Node, src []byte) bool {
	if n == nil {
		return false
	}
	if n.Type() == "binary_expression" {
		if op := n.ChildByFieldName("operator"); op != nil {
			switch op.Content(src) {
			case "*", "<<":
				return true
			}
		}
	}
	for i := 0; i < int(n.NamedChildCount()); i++ {
		if argsHaveComputedSize(n.NamedChild(i), src) {
			return true
		}
	}
	return false
}

func enclosingFunc(n *sitter.Node, src []byte) string {
	for p := n.Parent(); p != nil; p = p.Parent() {
		if p.Type() == "function_definition" {
			if d := p.ChildByFieldName("declarator"); d != nil {
				return declName(d, src)
			}
			return ""
		}
	}
	return ""
}

// the `declarator` field must be tried first: else a param name wins over the fn name
func declName(n *sitter.Node, src []byte) string {
	if n == nil {
		return ""
	}
	switch n.Type() {
	case "identifier", "field_identifier":
		return n.Content(src)
	}
	if d := n.ChildByFieldName("declarator"); d != nil {
		if name := declName(d, src); name != "" {
			return name
		}
	}
	for i := 0; i < int(n.NamedChildCount()); i++ {
		if name := declName(n.NamedChild(i), src); name != "" {
			return name
		}
	}
	return ""
}
