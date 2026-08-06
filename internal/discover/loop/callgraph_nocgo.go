//go:build !cgo

package loop

// scanFileCallGraph is a no-op without CGo (tree-sitter needs CGo); pure-Go builds lose nav but the oracle still owns correctness.
func scanFileCallGraph(_, _ string, _ *CallGraph) {}
