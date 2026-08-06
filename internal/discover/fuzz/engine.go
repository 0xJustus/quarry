package fuzz

// Engine names the coverage-guided engine a campaign runs.
type Engine string

const (
	EngineAFLPlusPlus Engine = "afl++"
	EngineClassicAFL  Engine = "classic-afl"
	EngineLibFuzzer   Engine = "libfuzzer"
)

type EngineInputs struct {
	// quarry recompiles the harness itself — NOT merely "source exists"
	InstrumentFromSource bool
	AFLPlusPlusAvailable bool
	NativeLibFuzzer      bool
	ClassicAFL           bool
}

// modern flags only when quarry built the harness; a baked afl-fuzz may be classic 2.52b (vault: Fuzzing)
func SelectEngine(in EngineInputs) Engine {
	switch {
	case in.InstrumentFromSource && in.AFLPlusPlusAvailable:
		return EngineAFLPlusPlus
	case in.NativeLibFuzzer:
		return EngineLibFuzzer
	case in.ClassicAFL:
		return EngineClassicAFL
	default:
		return EngineLibFuzzer
	}
}
