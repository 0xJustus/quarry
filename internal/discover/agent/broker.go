package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/0xjustus/quarry/internal/platform/broker"
	"github.com/0xjustus/quarry/internal/platform/router"
)

// BrokerSource turns the MCP broker's role-filtered catalog into agent Tools.
type BrokerSource struct {
	Broker *broker.Broker // required; holds the provisioned tools
	Role   router.Role    // scopes broker visibility and submission
	// full image used only to SURFACE layers in list_tools; nil ⇒ flat provisioned set
	Available    []Profile
	PollInterval time.Duration // zero ⇒ defaults
	PollTimeout  time.Duration // zero ⇒ defaults
}

const (
	defaultPollInterval = 25 * time.Millisecond
	defaultPollTimeout  = 10 * time.Minute
)

func (bs *BrokerSource) role() string { return string(bs.Role) }

func (bs *BrokerSource) pollInterval() time.Duration {
	if bs.PollInterval > 0 {
		return bs.PollInterval
	}
	return defaultPollInterval
}

func (bs *BrokerSource) pollTimeout() time.Duration {
	if bs.PollTimeout > 0 {
		return bs.PollTimeout
	}
	return defaultPollTimeout
}

func (bs *BrokerSource) BeltTools() []Tool {
	if bs == nil || bs.Broker == nil {
		return nil
	}
	tools := []Tool{&listToolsTool{bs}, &describeToolTool{bs}}
	for _, ct := range bs.Broker.ListTools(bs.role()) {
		tools = append(tools, &brokerTool{src: bs, spec: ct})
	}
	return tools
}

func AugmentBelt(base []Tool, src *BrokerSource) []Tool {
	if src == nil || src.Broker == nil {
		return base
	}
	have := make(map[string]bool, len(base))
	for _, t := range base {
		have[t.Name()] = true
	}
	out := append([]Tool(nil), base...)
	for _, t := range src.BeltTools() {
		if have[t.Name()] {
			continue // fixed belt wins: the broker must never shadow a core/oracle tool
		}
		have[t.Name()] = true
		out = append(out, t)
	}
	return out
}

type brokerTool struct {
	src  *BrokerSource
	spec broker.Tool
}

func (t *brokerTool) Name() string { return t.spec.Name }

func (t *brokerTool) Description() string {
	d := t.spec.Description
	if d == "" {
		d = "Broker-provisioned tool " + t.spec.Name + "."
	}
	return d + " Provisioned via the MCP broker; its output is a LEAD the oracle must still confirm — it is not a verdict."
}

func (t *brokerTool) Schema() json.RawMessage {
	if s := strings.TrimSpace(t.spec.Schema); s != "" {
		return json.RawMessage(s)
	}
	return json.RawMessage(`{"type":"object","properties":{"args":{"type":"object","description":"tool-specific arguments"}}}`)
}

// Invoke cancels the job on ctx/timeout so a hung backend can't wedge the ReAct loop.
func (t *brokerTool) Invoke(ctx context.Context, args json.RawMessage) (string, error) {
	id, err := t.src.Broker.Submit(ctx, t.src.role(), t.spec.Name, args)
	if err != nil {
		return "", fmt.Errorf("%s: %w", t.spec.Name, err)
	}

	interval := t.src.pollInterval()
	deadline := time.Now().Add(t.src.pollTimeout())
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		res, ok := t.src.Broker.Poll(id)
		if !ok {
			return "", fmt.Errorf("%s: execution %q vanished", t.spec.Name, id)
		}
		if res.Status.Terminal() {
			switch res.Status {
			case broker.StatusDone:
				return res.Output, nil
			case broker.StatusError:
				return "", fmt.Errorf("%s: %s", t.spec.Name, res.Error)
			default: // canceled
				return "", fmt.Errorf("%s: canceled", t.spec.Name)
			}
		}
		if time.Now().After(deadline) {
			_ = t.src.Broker.Cancel(id)
			return "", fmt.Errorf("%s: timed out after %s waiting for the broker", t.spec.Name, t.src.pollTimeout())
		}
		select {
		case <-ctx.Done():
			_ = t.src.Broker.Cancel(id)
			return "", ctx.Err()
		case <-ticker.C:
		}
	}
}

type listToolsTool struct{ src *BrokerSource }

func (listToolsTool) Name() string { return "list_tools" }
func (listToolsTool) Description() string {
	return "Discover the analysis/fuzzing tools the broker exposes to your role, grouped by Analysis Tool Image layer. Layers marked [provisioned] are on your belt now and callable directly; layers marked [available on request] exist but must be provisioned. Use describe_tool(tool) for a tool's arguments. Every broker tool is a lead-producer — the oracle still confirms."
}
func (listToolsTool) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"profile":{"type":"string","description":"optional layer name to filter (e.g. static+, re+, symbolic+, triage+)"}}}`)
}

func (t *listToolsTool) Invoke(_ context.Context, args json.RawMessage) (string, error) {
	var a struct {
		Profile string `json:"profile"`
	}
	_ = json.Unmarshal(args, &a)
	filter := strings.TrimSpace(a.Profile)
	role := t.src.role()

	provisioned := map[string]bool{}
	for _, ct := range t.src.Broker.ListTools(role) {
		provisioned[ct.Name] = true
	}

	profiles := t.src.Available
	if len(profiles) == 0 {
		return renderFlatTools(t.src.Broker.ListTools(role), role), nil
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Broker tool groups for role %q (Analysis Tool Image layers):\n", role)
	shown := 0
	for _, p := range profiles {
		if filter != "" && p.Name != filter {
			continue
		}
		vis := profileVisibleTo(p, role)
		if len(vis) == 0 {
			continue
		}
		shown++
		names := make([]string, 0, len(vis))
		allProvisioned := true
		for _, tl := range vis {
			names = append(names, tl.Name)
			if !provisioned[tl.Name] {
				allProvisioned = false
			}
		}
		sort.Strings(names)
		marker := "available on request"
		if allProvisioned {
			marker = "provisioned"
		}
		fmt.Fprintf(&b, "  [%s] %s — %s\n      %s\n", marker, p.Name, p.Desc, strings.Join(names, ", "))
	}
	if shown == 0 {
		return fmt.Sprintf("no broker tools visible to role %q", role), nil
	}
	b.WriteString("Call a [provisioned] tool directly; use describe_tool(tool) for its schema.")
	return b.String(), nil
}

func renderFlatTools(tools []broker.Tool, role string) string {
	if len(tools) == 0 {
		return fmt.Sprintf("no broker tools visible to role %q", role)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Broker tools for role %q (%d):\n", role, len(tools))
	for _, tl := range tools {
		fmt.Fprintf(&b, "  %s — %s\n", tl.Name, tl.Description)
	}
	b.WriteString("Use describe_tool(tool) for a tool's schema.")
	return b.String()
}

type describeToolTool struct{ src *BrokerSource }

func (describeToolTool) Name() string { return "describe_tool" }
func (describeToolTool) Description() string {
	return "Show a broker tool's description and JSON argument schema, if your role may see it. A role-hidden or unknown tool is reported as unavailable (the broker never leaks a gated tool's existence)."
}
func (describeToolTool) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"tool":{"type":"string","description":"tool name from list_tools"}},"required":["tool"]}`)
}

func (t *describeToolTool) Invoke(_ context.Context, args json.RawMessage) (string, error) {
	var a struct {
		Tool string `json:"tool"`
	}
	_ = json.Unmarshal(args, &a)
	name := strings.TrimSpace(a.Tool)
	if name == "" {
		return "", fmt.Errorf("describe_tool: tool is required")
	}
	role := t.src.role()

	if spec, ok := t.src.Broker.DescribeTool(role, name); ok {
		schema := strings.TrimSpace(spec.Schema)
		if schema == "" {
			schema = "(default free-form argument object)"
		}
		cap := spec.OutputCap
		return fmt.Sprintf("%s [provisioned]\n%s\noutput_cap: %d bytes\nschema: %s", spec.Name, spec.Description, cap, schema), nil
	}

	for _, p := range t.src.Available {
		for _, tl := range profileVisibleTo(p, role) {
			if tl.Name == name {
				return fmt.Sprintf("%s [available on request — layer %s]\n%s\nRequest the %s layer to provision it.", tl.Name, p.Name, tl.Description, p.Name), nil
			}
		}
	}
	// same message as a hidden tool: never leak a gated tool's existence
	return fmt.Sprintf("tool %q is not available to role %q", name, role), nil
}
