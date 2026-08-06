//go:build cgo

package loop

import (
	"context"
	"os"

	sitter "github.com/smacker/go-tree-sitter"
)

// fnDefQuery captures every function definition to record its name, location, body, and enclosed calls.
const fnDefQuery = `(function_definition) @fn`

// scanFileCallGraph adds one file's defs and call edges to g, using a fresh parser so concurrent scans never race.
func scanFileCallGraph(path, label string, g *CallGraph) {
	fi, err := os.Stat(path)
	if err != nil || fi.IsDir() || fi.Size() > analystMaxReadBytes {
		return
	}
	src, err := os.ReadFile(path)
	if err != nil {
		return
	}
	lang, callQuery := languageAndQuery(label)

	p := sitter.NewParser()
	p.SetLanguage(lang)
	tree, err := p.ParseCtx(context.Background(), nil, src)
	if err != nil || tree == nil {
		return
	}
	defer tree.Close()
	root := tree.RootNode()

	// Function definitions: name, 1-based start line, and (bounded) body source.
	fnQuery, err := sitter.NewQuery([]byte(fnDefQuery), lang)
	if err == nil {
		defer fnQuery.Close()
		fc := sitter.NewQueryCursor()
		defer fc.Close()
		fc.Exec(fnQuery, root)
		for {
			m, ok := fc.NextMatch()
			if !ok {
				break
			}
			for _, cap := range m.Captures {
				n := cap.Node
				name := ""
				if d := n.ChildByFieldName("declarator"); d != nil {
					name = declName(d, src)
				}
				if name == "" {
					continue
				}
				g.addDef(FuncDef{
					Name: name,
					File: label,
					Line: int(n.StartPoint().Row) + 1,
					Body: n.Content(src),
				})
				if g.nfuncs >= callGraphTotalFuncCap {
					return
				}
			}
		}
	}

	// Call edges: attribute each call_expression to its enclosing function.
	cc := sitter.NewQueryCursor()
	defer cc.Close()
	cc.Exec(callQuery, root)
	for {
		m, ok := cc.NextMatch()
		if !ok {
			break
		}
		var callee *sitter.Node
		for _, cap := range m.Captures {
			if callQuery.CaptureNameForId(cap.Index) == "callee" {
				callee = cap.Node
			}
		}
		if callee == nil {
			continue
		}
		g.addEdge(enclosingFunc(callee, src), calleeName(callee, src))
	}
}
