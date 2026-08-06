package backend

import (
	"cmp"
	"context"
	"fmt"
)

func detectJava(dir string) bool {
	return detectSource(dir,
		[]string{"pom.xml", "build.gradle", "build.gradle.kts"},
		[]string{".java", ".jar"})
}

// Java is the Jazzer discovery backend.
type Java struct {
	DockerBin     string
	BaseImage     string
	JazzerVersion string
	Lib           string // target class the harness fuzzes
	Function      string // static byte[] method the harness calls
}

func (Java) Name() string { return "java" }

func (j Java) baseImage() string     { return cmp.Or(j.BaseImage, "eclipse-temurin:21-jdk") }
func (j Java) jazzerVersion() string { return cmp.Or(j.JazzerVersion, "v0.30.0") }
func (j Java) lib() string           { return cmp.Or(j.Lib, "Lib") }
func (j Java) function() string      { return cmp.Or(j.Function, "process") }

func (j Java) Detect(dir string) bool { return detectJava(dir) }

func (j Java) SynthHarness(function, kind string) (string, error) {
	if function == "" {
		function = j.function()
	}
	return fmt.Sprintf(`public class FuzzTarget {
  public static void fuzzerTestOneInput(byte[] data) {
    %s.%s(data);
  }
}
`, j.lib(), function), nil
}

// uname picks the arch-matched Jazzer driver: the release ships arm64 and x86-64 separately
func (j Java) dockerfile() string {
	v := j.jazzerVersion()
	return "FROM " + j.baseImage() + "\n" +
		"RUN apt-get update -qq && apt-get install -y -qq curl tar && rm -rf /var/lib/apt/lists/*\n" +
		"RUN A=$(uname -m); case \"$A\" in aarch64|arm64) J=arm64;; *) J=x86-64;; esac; " +
		"curl -sL https://github.com/CodeIntelligenceTesting/jazzer/releases/download/" + v +
		"/jazzer-linux-$J.tar.gz | tar xz -C /opt\n" +
		"WORKDIR /app\nCOPY . /app\nRUN javac *.java\n"
}

func (j Java) BuildImage(ctx context.Context, dir string) (string, error) {
	harness, err := j.SynthHarness(j.function(), "fuzz")
	if err != nil {
		return "", err
	}
	return buildWithFiles(ctx, j.DockerBin, dir, j.dockerfile(), genFile{"FuzzTarget.java", harness})
}

func (j Java) RunOnce(ctx context.Context, image string, pov []byte) (Fault, error) {
	return runPoV(ctx, j.DockerBin, "quarry-jazzer-pov-*", image, pov, nil,
		[]string{"/opt/jazzer", "--cp=/app", "--target_class=FuzzTarget", "/pov"}, ClassifyJVM)
}

func (j Java) ClassifyFault(runOutput string) Fault { return ClassifyJVM(runOutput) }

func (j Java) Fuzz(ctx context.Context, image, corpusDir string, budgetSecs int) ([][]byte, error) {
	return fuzzCampaign(ctx, j.DockerBin, "quarry-jazzer-out-*", budgetSecs, func(out string, budget int) []string {
		args := []string{"run", "--rm", "--network", "none", "-v", out + ":/crashes", "-w", "/crashes"}
		if corpusDir != "" {
			args = append(args, "-v", corpusDir+":/corpus:ro")
		}
		args = append(args, image, "/opt/jazzer", "--cp=/app", "--target_class=FuzzTarget",
			"-artifact_prefix=/crashes/", fmt.Sprintf("-max_total_time=%d", budget))
		if corpusDir != "" {
			args = append(args, "/corpus")
		}
		return args
	})
}

// JavaBackend is the lightweight verifier the grounding path uses: plain javac + `java -cp`.
type JavaBackend struct {
	DockerBin string
	BaseImage string
	MainClass string
}

func (j JavaBackend) Name() string { return "java" }

func (j JavaBackend) baseImage() string { return cmp.Or(j.BaseImage, "eclipse-temurin:21-jdk") }
func (j JavaBackend) mainClass() string { return cmp.Or(j.MainClass, "Target") }

func (j JavaBackend) Detect(dir string) bool { return detectJava(dir) }

func (j JavaBackend) BuildImage(ctx context.Context, dir string) (string, error) {
	df := "FROM " + j.baseImage() + "\nWORKDIR /app\nCOPY . /app\nRUN javac *.java\n"
	return buildDockerfileImage(ctx, j.DockerBin, dir, df)
}

func (j JavaBackend) RunOnce(ctx context.Context, image string, pov []byte) (Fault, error) {
	return runPoV(ctx, j.DockerBin, "quarry-java-pov-*", image, pov, nil,
		[]string{"java", "-cp", "/app", j.mainClass(), "/pov"}, ClassifyJVM)
}

func (j JavaBackend) ClassifyFault(runOutput string) Fault { return ClassifyJVM(runOutput) }

var _ Fuzzer = Java{}

// verify-only by design: the capability split is per-capability, not per-language
var _ Verifier = JavaBackend{}
