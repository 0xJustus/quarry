package broker

import (
	_ "embed"
	"fmt"
	"slices"
	"sort"

	"gopkg.in/yaml.v3"
)

// Tool is one declarative catalog entry, as list_tools / describe_tool present it.
type Tool struct {
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	Schema      string   `yaml:"schema"`     // JSON-Schema; empty ⇒ default arg schema
	Roles       []string `yaml:"roles"`      // empty ⇒ visible to EVERY role
	OutputCap   int      `yaml:"output_cap"` // 0 ⇒ broker default cap
}

type Catalog struct {
	Tools []Tool `yaml:"tools"`
}

//go:embed catalog.yaml
var defaultCatalogYAML []byte

func DefaultCatalog() Catalog {
	c, err := ParseCatalog(defaultCatalogYAML)
	if err != nil {
		panic(fmt.Sprintf("broker: embedded catalog invalid: %v", err))
	}
	return c
}

func ParseCatalog(b []byte) (Catalog, error) {
	var c Catalog
	if err := yaml.Unmarshal(b, &c); err != nil {
		return Catalog{}, fmt.Errorf("broker: parse catalog: %w", err)
	}
	if err := c.Validate(); err != nil {
		return Catalog{}, err
	}
	return c, nil
}

func (c Catalog) Validate() error {
	seen := map[string]bool{}
	for i, t := range c.Tools {
		if t.Name == "" {
			return fmt.Errorf("broker: tool[%d] has no name", i)
		}
		if seen[t.Name] {
			return fmt.Errorf("broker: duplicate tool name %q", t.Name)
		}
		seen[t.Name] = true
	}
	return nil
}

// ForRole is name-sorted for stable listing; role "" is the unscoped view.
func (c Catalog) ForRole(role string) []Tool {
	var out []Tool
	for _, t := range c.Tools {
		if role == "" || len(t.Roles) == 0 || slices.Contains(t.Roles, role) {
			out = append(out, t)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (c Catalog) Get(name string) (Tool, bool) {
	for _, t := range c.Tools {
		if t.Name == name {
			return t, true
		}
	}
	return Tool{}, false
}
