package backend

import (
	"cmp"
	"context"
	"fmt"
)

// Rust reaches BOTH graders: unsafe-Rust ASan is memory, safe-Rust panic is not.
type Rust struct {
	DockerBin string
	BaseImage string
	Crate     string
	Function  string
}

func (Rust) Name() string { return "rust" }

func (r Rust) baseImage() string { return cmp.Or(r.BaseImage, "rust:latest") }
func (r Rust) crate() string     { return cmp.Or(r.Crate, "quarrydemo") }
func (r Rust) function() string  { return cmp.Or(r.Function, "process") }

func (r Rust) Detect(dir string) bool {
	return detectSource(dir, []string{"Cargo.toml"}, []string{".rs"})
}

func (r Rust) SynthHarness(function, kind string) (string, error) {
	if function == "" {
		function = r.function()
	}
	return fmt.Sprintf(`#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| { %s::%s(data); });
`, r.crate(), function), nil
}

// toolchain RUNs precede COPY so docker caches them across targets
func (r Rust) dockerfile() string {
	return "FROM " + r.baseImage() + "\n" +
		"RUN rustup toolchain install nightly --profile minimal -c rust-src\n" +
		"RUN cargo install cargo-fuzz\n" +
		"WORKDIR /app\nCOPY . /app\n" +
		"RUN cargo +nightly fuzz init 2>/dev/null || true\n" +
		"RUN cp /app/quarry_fuzz_target.rs fuzz/fuzz_targets/fuzz_target_1.rs\n" +
		"RUN cargo +nightly fuzz build fuzz_target_1\n"
}

func (r Rust) BuildImage(ctx context.Context, dir string) (string, error) {
	harness, err := r.SynthHarness(r.function(), "fuzz")
	if err != nil {
		return "", err
	}
	return buildWithFiles(ctx, r.DockerBin, dir, r.dockerfile(), genFile{"quarry_fuzz_target.rs", harness})
}

func (r Rust) RunOnce(ctx context.Context, image string, pov []byte) (Fault, error) {
	return runPoV(ctx, r.DockerBin, "quarry-rust-pov-*", image, pov, []string{"-w", "/app"},
		[]string{"cargo", "+nightly", "fuzz", "run", "fuzz_target_1", "/pov"}, ClassifyRust)
}

func (r Rust) ClassifyFault(runOutput string) Fault { return ClassifyRust(runOutput) }

func (r Rust) Fuzz(ctx context.Context, image, corpusDir string, budgetSecs int) ([][]byte, error) {
	return fuzzCampaign(ctx, r.DockerBin, "quarry-rust-out-*", budgetSecs, func(out string, budget int) []string {
		return []string{"run", "--rm", "--network", "none", "-v", out + ":/crashes", "-w", "/app", image,
			"cargo", "+nightly", "fuzz", "run", "fuzz_target_1", "--",
			fmt.Sprintf("-max_total_time=%d", budget), "-artifact_prefix=/crashes/"}
	})
}

var _ Fuzzer = Rust{}
