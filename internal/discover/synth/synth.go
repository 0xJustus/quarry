package synth

import (
	"fmt"
	"strings"
)

// HarnessSpec is the model-authored gap over the fixed skeleton: treat every field as untrusted.
type HarnessSpec struct {
	Entry         string   `json:"entry"`
	Includes      []string `json:"includes"`
	InitStmts     []string `json:"init_stmts"`
	EntryCall     string   `json:"entry_call"`
	TeardownStmts []string `json:"teardown_stmts"`
	LinkLibs      []string `json:"link_libs"`
	ExtraCFlags   []string `json:"extra_cflags"`
	NeedsTempFile bool     `json:"needs_temp_file"`
}

const harnessSkeleton = `/* Synthesized fuzz harness (quarry synth): reads argv[1] into (data,size).
 * A benign/unparseable input returns 0, so only a real ASan/signal abort is a finding. */
%s
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* quarry owns ASan's options: a spec that redefines these is a duplicate symbol and fails the
 * build, never a silenced sanitizer. "" keeps ASan's own defaults. */
#ifdef __cplusplus
extern "C" {
#endif
const char *__asan_default_options(void) { return ""; }
const char *__asan_default_suppressions(void) { return ""; }
#ifdef __cplusplus
}
#endif

int main(int argc, char **argv) {
  if (argc < 2) { fprintf(stderr, "usage: %%s <input-file>\n", argv[0]); return 2; }
  FILE *qf = fopen(argv[1], "rb");
  if (!qf) return 2;
  if (fseek(qf, 0, SEEK_END) != 0) { fclose(qf); return 2; }
  long qn = ftell(qf);
  if (qn < 0) { fclose(qf); return 2; }
  if (fseek(qf, 0, SEEK_SET) != 0) { fclose(qf); return 2; }
  size_t size = (size_t)qn;
  unsigned char *data = (unsigned char *)malloc(size ? size : 1);
  if (!data) { fclose(qf); return 2; }
  size = fread(data, 1, size, qf);
  fclose(qf);
  const char *input_path = argv[1]; /* for path/FILE* entries */
  (void)input_path; (void)data; (void)size;

%s /* init */
%s /* entry */
%s /* teardown */

  free(data);
  return 0;
}
`

func indent(lines []string) string {
	var b strings.Builder
	for _, l := range lines {
		l = strings.TrimRight(l, "\n")
		if strings.TrimSpace(l) == "" {
			continue
		}
		b.WriteString("  ")
		b.WriteString(l)
		b.WriteByte('\n')
	}
	return b.String()
}

// RenderHarness drops what the spec may not write; an inert harness is a rejection, not a risk.
func RenderHarness(s HarnessSpec) string {
	var inc strings.Builder
	for _, h := range s.Includes {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if !safeIncludeEntry(h) {
			inc.WriteString("/* quarry synth: DROPPED an include entry that is not a plain header reference (file-scope C is quarry's, not the spec's) */\n")
			continue
		}
		if strings.HasPrefix(h, "#include") {
			inc.WriteString(h)
		} else if strings.HasPrefix(h, "FT_") || (!strings.Contains(h, ".") && strings.ToUpper(h) == h) {
			inc.WriteString("#include " + h) // macro-style include form, no quotes
		} else {
			inc.WriteString("#include <" + strings.Trim(h, "<>\"") + ">")
		}
		inc.WriteByte('\n')
	}

	init, entry, teardown := s.InitStmts, s.EntryCall, s.TeardownStmts
	escaped := stmtsEscapeMain(init, entry, teardown)
	if escaped {
		// drop the whole block: unbalanced braces continue at file scope
		init, entry, teardown = nil, "", nil
	}
	body := indent([]string{entry})
	switch {
	case escaped:
		body = "  /* quarry synth: DROPPED the spec's statements — unbalanced braces would continue at file scope, outside main — inert harness */\n"
	case strings.TrimSpace(entry) == "":
		body = "  /* no entry call synthesized — inert harness */\n"
	}
	return fmt.Sprintf(harnessSkeleton, strings.TrimRight(inc.String(), "\n"), indent(init), body, indent(teardown))
}

// an include lands at file scope, so a newline in one is arbitrary top-level C
func safeIncludeEntry(h string) bool {
	if len(h) > 200 {
		return false
	}
	for _, r := range h {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return !strings.ContainsAny(h, ";{}()=&|`$\\")
}

// depth < 0 or a left-open block means the spec is writing outside quarry's main
func stmtsEscapeMain(init []string, entry string, teardown []string) bool {
	depth := 0
	scan := func(s string) bool {
		for _, r := range s {
			switch r {
			case '{':
				depth++
			case '}':
				depth--
				if depth < 0 {
					return true
				}
			}
		}
		return false
	}
	for _, group := range [][]string{init, {entry}, teardown} {
		for _, s := range group {
			if scan(s) {
				return true
			}
		}
	}
	return depth != 0
}
