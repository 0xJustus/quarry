//go:build !cgo

package loop

// an empty scan must never read as a clean target (vault: Loop Directors)
const StaticScannerAvailable = false

func scanFileSinks(_, _ string, _ *[]Sink) {}
