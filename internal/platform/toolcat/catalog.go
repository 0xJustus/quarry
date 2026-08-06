// Package toolcat is the declarative tool catalog and its broker.
package toolcat

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type Kind string

const (
	InImage     Kind = "in-image"     // CLI in the pinned agent image
	Sidecar     Kind = "sidecar"      // long-running service, reached via MCP
	ExternalMCP Kind = "external-mcp" // external MCP server launched on demand
)

type Tool struct {
	ID          string   `yaml:"id"`
	Kind        Kind     `yaml:"kind"`
	Description string   `yaml:"description"`
	Schema      string   `yaml:"schema"` // JSON-Schema (raw JSON)
	Cmd         string   `yaml:"cmd"`
	FixedArgs   []string `yaml:"fixed_args"` // prepended before the agent's args
	Command     []string `yaml:"command"`    // external-mcp: stdio server launch argv
	MCPTool     string   `yaml:"mcp_tool"`   // server-side tool name (default = ID)
	Roles       []string `yaml:"roles"`      // empty ⇒ all roles
	Pin         string   `yaml:"pin"`        // REQUIRED pin: …@sha256:… / sha256:… / cas:…
	TimeoutS    int      `yaml:"timeout_s"`  // 0 → broker default
	OutputCap   int      `yaml:"output_cap"` // 0 → broker default
}

type Catalog struct {
	Tools []Tool `yaml:"tools"`
}

func Load(path string) (Catalog, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Catalog{}, err
	}
	var c Catalog
	if err := yaml.Unmarshal(b, &c); err != nil {
		return Catalog{}, fmt.Errorf("toolcat: parse %s: %w", path, err)
	}
	if err := c.Validate(); err != nil {
		return Catalog{}, err
	}
	return c, nil
}

// keep in sync with agent.Belt/cpgTools/binTools/BrokerSource: a colliding catalog id shadows a belt tool (vault: Tool Catalog)
var ReservedIDs = map[string]bool{
	"edit": true, "read_file": true, "ls": true, "exec": true,
	"run_generator": true, "run_pov": true, "spawn_hypothesis": true,
	"get_callers": true, "get_callees": true, "get_function": true,
	"propose_reference": true, "differential_fuzz": true,
	"cpg_reaches": true, "cpg_taint": true, "cpg_bounds": true, "cpg_sinks": true,
	"cpg_slice": true, "cpg_callers": true, "cpg_callees": true, "cpg_missing_authz": true,
	"bin_info": true, "bin_strings": true, "bin_symbols": true, "bin_disasm": true,
	"list_tools": true, "describe_tool": true,
}

func (c Catalog) Validate() error {
	seen := map[string]bool{}
	for i, t := range c.Tools {
		if t.ID == "" {
			return fmt.Errorf("toolcat: tool[%d] has no id", i)
		}
		if seen[t.ID] {
			return fmt.Errorf("toolcat: duplicate tool id %q", t.ID)
		}
		seen[t.ID] = true
		if ReservedIDs[t.ID] {
			return fmt.Errorf("toolcat: tool id %q is reserved for a core belt tool — a catalog entry is appended after the belt and would SHADOW it (a shadowed run_pov never reaches the oracle); rename the catalog entry", t.ID)
		}
		if !pinned(t.Pin) {
			return fmt.Errorf("toolcat: tool %q is not pinned (need pin: repo@sha256:… / sha256:… / cas:…) — unpinned tools break reproducible replay", t.ID)
		}
		// reject at load: an invalid schema fails the marshal of every model request
		var schema map[string]any
		if t.Schema != "" {
			s := strings.TrimSpace(t.Schema)
			if s == "" || !json.Valid([]byte(s)) {
				return fmt.Errorf("toolcat: tool %q has a schema that is not valid JSON", t.ID)
			}
			if err := json.Unmarshal([]byte(s), &schema); err != nil {
				return fmt.Errorf("toolcat: tool %q schema must be a JSON object (JSON-Schema), got %.20s", t.ID, s)
			}
		}
		switch t.Kind {
		case InImage:
			if t.Cmd == "" {
				return fmt.Errorf("toolcat: in-image tool %q needs a cmd", t.ID)
			}
			// in-image tools have one calling convention: positional args (see coerceArgs)
			if props, ok := schema["properties"].(map[string]any); ok && len(props) > 0 {
				if _, ok := props["args"]; !ok {
					return fmt.Errorf("toolcat: in-image tool %q declares a schema with no \"args\" property — in-image tools take a positional list under \"args\"; named parameters cannot be ordered into a command line", t.ID)
				}
			}
		case ExternalMCP:
			if len(t.Command) == 0 {
				return fmt.Errorf("toolcat: external-mcp tool %q needs a command (stdio server argv)", t.ID)
			}
		case Sidecar:
			// a sidecar is routed over stdio MCP too; Tool has no endpoint field
			if len(t.Command) == 0 {
				return fmt.Errorf("toolcat: sidecar tool %q needs a command (the stdio MCP argv that reaches the running sidecar) — sidecars are routed over stdio MCP and there is no endpoint field", t.ID)
			}
		default:
			return fmt.Errorf("toolcat: tool %q has unknown kind %q", t.ID, t.Kind)
		}
	}
	return nil
}

func pinned(p string) bool {
	return strings.Contains(p, "@sha256:") || strings.HasPrefix(p, "sha256:") || strings.HasPrefix(p, "cas:")
}

// ForRole scopes tools to a role; empty Roles or role "" means all.
func (c Catalog) ForRole(role string) []Tool {
	var out []Tool
	for _, t := range c.Tools {
		if role == "" || len(t.Roles) == 0 || slices.Contains(t.Roles, role) {
			out = append(out, t)
		}
	}
	return out
}

// Hashes must name the tool and cover the whole recipe: the pin alone is not a replay key (vault: Tool Catalog).
func Hashes(tools []Tool) []string {
	out := make([]string, 0, len(tools))
	for _, t := range tools {
		out = append(out, t.ID+"@"+t.Pin+"#"+recipeDigest(t))
	}
	slices.Sort(out)
	return out
}

// recipeDigest length-prefixes every field so no two recipes can encode identically.
func recipeDigest(t Tool) string {
	h := sha256.New()
	put := func(s string) { fmt.Fprintf(h, "%d:%s", len(s), s) }
	putList := func(ss []string) {
		put(strconv.Itoa(len(ss)))
		for _, s := range ss {
			put(s)
		}
	}
	put(t.ID)
	put(string(t.Kind))
	put(t.Description)
	put(strings.TrimSpace(t.Schema))
	put(t.Cmd)
	putList(t.FixedArgs)
	putList(t.Command)
	put(t.MCPTool)
	putList(t.Roles)
	put(t.Pin)
	put(strconv.Itoa(t.TimeoutS))
	put(strconv.Itoa(t.OutputCap))
	return "sha256:" + hex.EncodeToString(h.Sum(nil))[:16]
}

func CatalogHash(tools []Tool) string {
	h := sha256.Sum256([]byte(strings.Join(Hashes(tools), "\n")))
	return "toolset:" + hex.EncodeToString(h[:])[:32]
}
