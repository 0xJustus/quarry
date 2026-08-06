package fuzz

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// diff driver: DIVERGED (abort), IDENTICAL (0), or COULD-NOT-TELL (diffInconclusiveExit) — never a silent "identical"
const diffDriverSrc = `#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

extern int qtgt_main(int, char **);
extern int qref_main(int, char **);

/* Runs fn with stdout redirected into an unlinked temp file, left open at *outfd, rewound.
   Nothing is buffered in memory, so the comparison below is over the FULL output. */
static int capture(int (*fn)(int, char **), char **argv, int *outfd) {
	char tmpl[] = "/tmp/qcapXXXXXX";
	int fd = mkstemp(tmpl);
	if (fd < 0) return -1000;
	unlink(tmpl);
	fflush(stdout);
	int saved = dup(1);
	dup2(fd, 1);
	int rc = fn(2, argv);
	fflush(stdout);
	dup2(saved, 1);
	close(saved);
	lseek(fd, 0, SEEK_SET);
	*outfd = fd;
	return rc;
}

/* Retries short reads, so a returned count < cap means EOF. */
static ssize_t readfull(int fd, char *buf, size_t cap) {
	size_t got = 0;
	while (got < cap) {
		ssize_t n = read(fd, buf + got, cap - got);
		if (n < 0) return -1;
		if (n == 0) break;
		got += (size_t)n;
	}
	return (ssize_t)got;
}

/* 1 = the captures differ in length OR content, 0 = byte-identical, -1 = compare failed.
   memcmp over real lengths: a divergence after an embedded NUL still counts. */
static int differs(int fa, int fb) {
	static char ca[65536], cb[65536];
	for (;;) {
		ssize_t na = readfull(fa, ca, sizeof ca);
		ssize_t nb = readfull(fb, cb, sizeof cb);
		if (na < 0 || nb < 0) return -1;
		if (na != nb) return 1;
		if (na == 0) return 0;
		if (memcmp(ca, cb, (size_t)na) != 0) return 1;
	}
}

int main(int argc, char **argv) {
	if (argc < 2) return 0;
	char *sub[] = {"x", argv[1], 0};
	int fa = -1, fb = -1;
	int ra = capture(qtgt_main, sub, &fa);
	int rb = capture(qref_main, sub, &fb);
	int d = (fa >= 0 && fb >= 0) ? differs(fa, fb) : -1;
	if (fa >= 0) close(fa);
	if (fb >= 0) close(fb);
	if (d < 0) {
		/* Exit nonzero rather than abort(): an infra failure must never be attributed to
		   the target as a divergence, and never counted as agreement either. */
		fprintf(stderr, "quarry-diff: INCONCLUSIVE - output capture failed, divergence unknown\n");
		return QDIFF_INCONCLUSIVE;
	}
	if (ra != rb || d != 0) {
		abort(); /* the logic divergence, surfaced for the crash oracle */
	}
	return 0;
}
`

// distinct from 0 and from a real divergence's SIGABRT: broken must not read as clean
const diffInconclusiveExit = 42

// bound to the Go constant so the driver's exit status cannot drift from it
var diffDriver = strings.ReplaceAll(diffDriverSrc, "QDIFF_INCONCLUSIVE", strconv.Itoa(diffInconclusiveExit))

// the -Dmain= rename is what makes two standalone programs linkable without a name clash
func diffCompileSteps(cc string) []string {
	return []string{
		cc + " -O1 -Dmain=qtgt_main -c /diff/target.c -o /diff/target.o",
		cc + " -O1 -Dmain=qref_main -c /diff/ref.c -o /diff/ref.o",
		cc + " -O1 /diff/driver.c /diff/target.o /diff/ref.o -o /harness",
	}
}

// compiles both programs into ONE abort-on-divergence image; compileErr ⇒ sources didn't combine, err ⇒ infra failure
func BuildDifferentialImage(ctx context.Context, dockerBin, targetSrc, refSrc string) (image, compileErr string, err error) {
	if dockerBin == "" {
		dockerBin = "docker"
	}
	sum := sha256.Sum256([]byte("difffuzz\x00" + targetSrc + "\x00" + refSrc))
	image = fmt.Sprintf("quarry-difffuzz-%x:latest", sum[:6])

	dir, derr := os.MkdirTemp("", "quarry-difffuzz-*")
	if derr != nil {
		return "", "", derr
	}
	debug := os.Getenv("QUARRY_DIFFFUZZ_DEBUG") != ""
	if !debug {
		defer os.RemoveAll(dir)
	}
	for name, body := range map[string]string{"target.c": targetSrc, "ref.c": refSrc, "driver.c": diffDriver} {
		if werr := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); werr != nil {
			return "", "", werr
		}
	}
	steps := diffCompileSteps("afl-clang-fast")
	dockerfile := "FROM " + QuarryFuzzImage + "\nRUN mkdir -p /diff\nCOPY target.c ref.c driver.c /diff/\n"
	for _, s := range steps {
		dockerfile += "RUN " + s + "\n"
	}
	if werr := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(dockerfile), 0o644); werr != nil {
		return "", "", werr
	}
	build := exec.CommandContext(ctx, dockerBin, "build", "--platform", "linux/amd64", "-t", image, dir)
	if out, berr := build.CombinedOutput(); berr != nil {
		if debug {
			fmt.Fprintf(os.Stderr, "[difffuzz-debug] preserved build dir: %s\n%s\n", dir, tailLines(string(out), 40))
		}
		return "", tailLines(string(out), 30), nil
	}
	return image, "", nil
}

func tailLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
