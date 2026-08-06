package backend

import (
	"cmp"
	"context"
	"fmt"
)

type JS struct {
	DockerBin string
	BaseImage string // Jazzer.js's arm64 addon needs GLIBC≥2.38: bookworm node images fail ERR_DLOPEN_FAILED
	Module    string
	Function  string
}

func (JS) Name() string { return "js" }

func (j JS) baseImage() string { return cmp.Or(j.BaseImage, "ubuntu:24.04") }
func (j JS) module() string    { return cmp.Or(j.Module, "target") }
func (j JS) function() string  { return cmp.Or(j.Function, "fuzz") }

func (j JS) Detect(dir string) bool {
	return detectSource(dir, []string{"package.json"}, []string{".js", ".ts", ".mjs", ".cjs"})
}

func (j JS) SynthHarness(function, kind string) (string, error) {
	if function == "" {
		function = j.function()
	}
	return fmt.Sprintf("const t = require('./%s');\nmodule.exports.fuzz = function (data) { t.%s(data); };\n",
		j.module(), function), nil
}

func (j JS) dockerfile() string {
	return "FROM " + j.baseImage() + "\n" +
		"ENV DEBIAN_FRONTEND=noninteractive\n" +
		"RUN apt-get update -qq && apt-get install -y -qq nodejs npm && rm -rf /var/lib/apt/lists/*\n" +
		"WORKDIR /app\nCOPY . /app\n" +
		"RUN npm init -y >/dev/null 2>&1 && npm install --no-audit --no-fund @jazzer.js/core\n"
}

func (j JS) BuildImage(ctx context.Context, dir string) (string, error) {
	harness, err := j.SynthHarness(j.function(), "fuzz")
	if err != nil {
		return "", err
	}
	return buildWithFiles(ctx, j.DockerBin, dir, j.dockerfile(), genFile{"quarry_harness.js", harness})
}

func (j JS) RunOnce(ctx context.Context, image string, pov []byte) (Fault, error) {
	return runPoV(ctx, j.DockerBin, "quarry-js-pov-*", image, pov, []string{"-w", "/app"},
		[]string{"npx", "jazzer", "quarry_harness", "/pov", "--sync"}, ClassifyJS)
}

func (j JS) ClassifyFault(runOutput string) Fault { return ClassifyJS(runOutput) }

func (j JS) Fuzz(ctx context.Context, image, corpusDir string, budgetSecs int) ([][]byte, error) {
	return fuzzCampaign(ctx, j.DockerBin, "quarry-js-out-*", budgetSecs, func(out string, budget int) []string {
		return []string{"run", "--rm", "--network", "none", "-v", out + ":/crashes", "-w", "/app", image,
			"npx", "jazzer", "quarry_harness", "--sync", "--",
			"-artifact_prefix=/crashes/", fmt.Sprintf("-max_total_time=%d", budget)}
	})
}

var _ Fuzzer = JS{}
