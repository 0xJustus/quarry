package oracle

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type specFile struct {
	Oracle Spec `yaml:"oracle"`
}

type targetFile struct {
	Target specFile `yaml:"target"`
}

func Load(path string) (Spec, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Spec{}, fmt.Errorf("oracle: read %s: %w", path, err)
	}
	return Parse(data)
}

// Parse decodes a Spec from YAML bytes (bare, `oracle:`- or `target:`-wrapped) and validates it.
func Parse(data []byte) (Spec, error) {
	var tf targetFile
	if err := yaml.Unmarshal(data, &tf); err == nil && specPresent(tf.Target.Oracle) {
		if err := tf.Target.Oracle.Validate(); err != nil {
			return Spec{}, err
		}
		return tf.Target.Oracle, nil
	}
	var wrapped specFile
	if err := yaml.Unmarshal(data, &wrapped); err == nil && specPresent(wrapped.Oracle) {
		if err := wrapped.Oracle.Validate(); err != nil {
			return Spec{}, err
		}
		return wrapped.Oracle, nil
	}
	var s Spec
	if err := yaml.Unmarshal(data, &s); err != nil {
		return Spec{}, fmt.Errorf("oracle: parse yaml: %w", err)
	}
	if err := s.Validate(); err != nil {
		return Spec{}, err
	}
	return s, nil
}

// ParseShortcut compiles a ';'-separated CLI clause string into a require=any Spec.
func ParseShortcut(s string) (Spec, error) {
	spec := Spec{Require: "any"}
	for _, clause := range strings.Split(s, ";") {
		clause = strings.TrimSpace(clause)
		if clause == "" {
			continue
		}
		kind, rest, _ := strings.Cut(clause, ":")
		switch ConditionType(strings.ToLower(kind)) {
		case CondSignal:
			sigs := splitNonEmpty(rest, ",")
			if len(sigs) == 0 {
				sigs = []string{"SIGSEGV", "SIGABRT"}
			}
			spec.Conditions = append(spec.Conditions, Condition{Type: CondSignal, Signals: sigs})
		case CondSanitizer:
			parts := strings.SplitN(rest, ":", 3)
			c := Condition{Type: CondSanitizer, Tool: "asan"}
			if len(parts) >= 1 && parts[0] != "" {
				c.Tool = parts[0]
			}
			if len(parts) >= 2 && parts[1] != "" {
				c.BugClass = splitNonEmpty(parts[1], ",")
			}
			if len(parts) >= 3 && parts[2] != "" {
				c.CrashSite = parts[2]
			}
			spec.Conditions = append(spec.Conditions, c)
		case CondOutput:
			// a regex may contain ':': only split off a leading known-stream token
			stream := "any"
			regex := rest
			if head, tail, ok := strings.Cut(rest, ":"); ok && validStream(strings.TrimSpace(head)) && head != "" {
				stream = strings.TrimSpace(head)
				regex = tail
			}
			spec.Conditions = append(spec.Conditions, Condition{Type: CondOutput, Stream: stream, Regex: regex})
		case CondExit:
			n, err := strconv.Atoi(strings.TrimSpace(rest))
			if err != nil {
				return Spec{}, fmt.Errorf("oracle shortcut: exit needs an integer, got %q", rest)
			}
			spec.Conditions = append(spec.Conditions, Condition{Type: CondExit, ExitCode: &IntMatch{Eq: &n}})
		case CondTimeout:
			spec.Conditions = append(spec.Conditions, Condition{Type: CondTimeout})
		case CondResource:
			spec.Conditions = append(spec.Conditions, Condition{Type: CondResource})
		case CondTaint:
			// taint[:sink-label]
			spec.Conditions = append(spec.Conditions, Condition{Type: CondTaint, Sink: strings.TrimSpace(rest)})
		case CondScript:
			name := strings.TrimSpace(rest)
			if name == "" {
				return Spec{}, fmt.Errorf("oracle shortcut: script needs a check name")
			}
			spec.Conditions = append(spec.Conditions, Condition{Type: CondScript, Script: name})
		case CondMetamorphic:
			// metamorphic[:relation][:stream]
			c := Condition{Type: CondMetamorphic, Relation: "equal"}
			if rel, tail, ok := strings.Cut(rest, ":"); ok {
				if rel = strings.TrimSpace(rel); rel != "" {
					c.Relation = rel
				}
				if st := strings.TrimSpace(tail); validStream(st) && st != "" {
					c.Stream = st
				}
			} else if rel := strings.TrimSpace(rest); rel != "" {
				c.Relation = rel
			}
			spec.Conditions = append(spec.Conditions, c)
		default:
			return Spec{}, fmt.Errorf("oracle shortcut: unknown clause kind %q", kind)
		}
	}
	if err := spec.Validate(); err != nil {
		return Spec{}, err
	}
	return spec, nil
}

// a pure reference-diff body carries no conditions and must still count as present
func specPresent(s Spec) bool {
	return len(s.Conditions) > 0 || len(s.Sequence) > 0 || s.Differential != nil
}

func splitNonEmpty(s, sep string) []string {
	var out []string
	for _, p := range strings.Split(s, sep) {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
