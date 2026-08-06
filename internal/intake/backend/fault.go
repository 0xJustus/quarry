package backend

import "context"

type FaultClass string

const (
	FaultNone      FaultClass = "none"
	FaultMemory    FaultClass = "memory"
	FaultException FaultClass = "exception"
	FaultTimeout   FaultClass = "timeout"
)

type Fault struct {
	Faulted bool
	Class   FaultClass
	Signal  string
	Site    string
	Output  []byte
}

// only FaultMemory has a crash primitive; never route the others there
func (f Fault) Grader() string {
	switch f.Class {
	case FaultMemory:
		return "crash-primitive"
	case FaultException, FaultTimeout:
		return "semantic-impact"
	default:
		return "none"
	}
}

type Verifier interface {
	Name() string
	Detect(dir string) bool
	BuildImage(ctx context.Context, dir string) (image string, err error)
	RunOnce(ctx context.Context, image string, pov []byte) (Fault, error)
	ClassifyFault(runOutput string) Fault
}

type Fuzzer interface {
	Verifier
	SynthHarness(function, kind string) (string, error)
	Fuzz(ctx context.Context, image, corpusDir string, budgetSecs int) ([][]byte, error)
}
