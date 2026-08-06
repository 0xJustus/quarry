package backend

import (
	"cmp"
	"context"
	"fmt"
)

type PHP struct {
	DockerBin string
	BaseImage string
	Lib       string
	Function  string
}

func (PHP) Name() string { return "php" }

func (p PHP) baseImage() string { return cmp.Or(p.BaseImage, "php:8.3-cli") }
func (p PHP) lib() string       { return cmp.Or(p.Lib, "lib.php") }
func (p PHP) function() string  { return cmp.Or(p.Function, "process") }

func (p PHP) Detect(dir string) bool {
	return detectSource(dir, []string{"composer.json"}, []string{".php"})
}

// $fuzzer is in scope because php-fuzzer includes this file
func (p PHP) SynthHarness(function, kind string) (string, error) {
	if function == "" {
		function = p.function()
	}
	return fmt.Sprintf("<?php\nrequire_once __DIR__ . '/%s';\n$fuzzer->setTarget(function (string $input) { %s($input); });\n",
		p.lib(), function), nil
}

// php-fuzzer's own replay is version-dependent; a direct shim is robust
func (p PHP) replayShim() string {
	return fmt.Sprintf("<?php\nrequire_once __DIR__ . '/%s';\ntry { %s(file_get_contents($argv[1])); echo \"ok\\n\"; }\ncatch (\\Throwable $e) { fwrite(STDERR, (string)$e); exit(1); }\n",
		p.lib(), p.function())
}

func (p PHP) dockerfile() string {
	return "FROM " + p.baseImage() + "\n" +
		"RUN apt-get update -qq && apt-get install -y -qq git unzip curl && rm -rf /var/lib/apt/lists/*\n" +
		"RUN curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer\n" +
		"WORKDIR /app\nCOPY . /app\n" +
		"RUN composer require --dev nikic/php-fuzzer\n"
}

func (p PHP) BuildImage(ctx context.Context, dir string) (string, error) {
	harness, err := p.SynthHarness(p.function(), "fuzz")
	if err != nil {
		return "", err
	}
	return buildWithFiles(ctx, p.DockerBin, dir, p.dockerfile(),
		genFile{"quarry_harness.php", harness},
		genFile{"quarry_replay.php", p.replayShim()})
}

func (p PHP) RunOnce(ctx context.Context, image string, pov []byte) (Fault, error) {
	return runPoV(ctx, p.DockerBin, "quarry-php-pov-*", image, pov, []string{"-w", "/app"},
		[]string{"php", "/app/quarry_replay.php", "/pov"}, ClassifyPHP)
}

func (p PHP) ClassifyFault(runOutput string) Fault { return ClassifyPHP(runOutput) }

func (p PHP) Fuzz(ctx context.Context, image, corpusDir string, budgetSecs int) ([][]byte, error) {
	return fuzzCampaign(ctx, p.DockerBin, "quarry-php-out-*", budgetSecs, func(out string, budget int) []string {
		// php-fuzzer runs until it crashes or is killed, so bound it with timeout(1)
		sh := fmt.Sprintf("timeout %d /app/vendor/bin/php-fuzzer fuzz /app/quarry_harness.php || true", budget)
		return []string{"run", "--rm", "--network", "none", "-v", out + ":/crashes", "-w", "/crashes",
			image, "bash", "-c", sh}
	})
}

var _ Fuzzer = PHP{}
