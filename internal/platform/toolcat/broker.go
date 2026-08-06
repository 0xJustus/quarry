package toolcat

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"
)

// Execer runs an in-image CLI, inheriting the agent's exec boundary.
type Execer interface {
	Exec(ctx context.Context, cmd string, args []string, stdin string, timeout time.Duration) (stdout, stderr string, exit int, err error)
}

type MCPCaller interface {
	CallTool(ctx context.Context, command []string, tool string, args json.RawMessage, timeout time.Duration) (string, error)
}

type Broker struct {
	Tools          []Tool
	Exec           Execer
	MCP            MCPCaller
	DefaultTimeout time.Duration
	DefaultCap     int
	byID           map[string]Tool
}

func NewBroker(tools []Tool, exec Execer, mcp MCPCaller) *Broker {
	b := &Broker{Tools: tools, Exec: exec, MCP: mcp, DefaultTimeout: 60 * time.Second, DefaultCap: 64 << 10, byID: map[string]Tool{}}
	for _, t := range tools {
		b.byID[t.ID] = t
	}
	return b
}

func (b *Broker) Invoke(ctx context.Context, id string, args json.RawMessage) (string, error) {
	t, ok := b.byID[id]
	if !ok {
		return "", fmt.Errorf("toolcat: unknown tool %q", id)
	}
	timeout := b.DefaultTimeout
	if t.TimeoutS > 0 {
		timeout = time.Duration(t.TimeoutS) * time.Second
	}
	cap := b.DefaultCap
	if t.OutputCap > 0 {
		cap = t.OutputCap
	}

	switch t.Kind {
	case InImage:
		return b.invokeInImage(ctx, t, args, timeout, cap)
	case ExternalMCP, Sidecar:
		if b.MCP == nil {
			return "", fmt.Errorf("toolcat: tool %q needs an MCP backend, none configured", id)
		}
		// guard for a Broker built in code; Catalog.Validate rejects this at load
		if len(t.Command) == 0 {
			return "", fmt.Errorf("toolcat: tool %q (kind %q) declares no command — it is reached over stdio MCP and there is no endpoint field, so it is unreachable", id, t.Kind)
		}
		name := t.MCPTool
		if name == "" {
			name = t.ID
		}
		out, err := b.MCP.CallTool(ctx, t.Command, name, args, timeout)
		return capString(out, cap), err
	default:
		return "", fmt.Errorf("toolcat: tool %q has unroutable kind %q", id, t.Kind)
	}
}

func (b *Broker) invokeInImage(ctx context.Context, t Tool, args json.RawMessage, timeout time.Duration, cap int) (string, error) {
	if b.Exec == nil {
		return "", fmt.Errorf("toolcat: in-image tool %q needs an execer, none configured", t.ID)
	}
	extra, err := coerceArgs(args)
	if err != nil {
		// must not exec bare: the model would read the CLI's usage error as a tool failure
		return "", fmt.Errorf("toolcat: tool %q: %w", t.ID, err)
	}
	argv := slices.Concat(t.FixedArgs, extra)
	stdout, stderr, exit, err := b.Exec.Exec(ctx, t.Cmd, argv, "", timeout)
	if err != nil {
		return "", err
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "exit=%d", exit)
	if stdout != "" {
		fmt.Fprintf(&sb, "\n--- stdout ---\n%s", stdout)
	}
	if stderr != "" {
		fmt.Fprintf(&sb, "\n--- stderr ---\n%s", stderr)
	}
	return capString(sb.String(), cap), nil
}

// coerceArgs never returns a silent empty argv: dropped arguments must be an error.
func coerceArgs(raw json.RawMessage) ([]string, error) {
	body := json.RawMessage(strings.TrimSpace(string(raw)))
	if len(body) == 0 || string(body) == "null" {
		return nil, nil
	}
	// a bare array is the model skipping the wrapper; take it positionally
	if arr, ok := jsonArray(body); ok {
		return scalars(arr), nil
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		return nil, fmt.Errorf("arguments must be an object like {\"args\":[\"-d\",\"/work/vuln\"]} or a bare array of arguments: %w", err)
	}
	inner, ok := obj["args"]
	if !ok {
		if len(obj) == 0 {
			return nil, nil // an explicit no-argument call
		}
		named := slices.Sorted(maps.Keys(obj))
		return nil, fmt.Errorf("this tool takes POSITIONAL arguments under \"args\" (e.g. {\"args\":[\"-d\",\"/work/vuln\"]}); got named argument(s) %s, which cannot be ordered into a command line", strings.Join(named, ", "))
	}
	inner = json.RawMessage(strings.TrimSpace(string(inner)))
	if len(inner) == 0 || string(inner) == "null" {
		return nil, nil
	}
	if arr, ok := jsonArray(inner); ok {
		return scalars(arr), nil
	}
	return []string{scalar(inner)}, nil
}

func jsonArray(raw json.RawMessage) ([]json.RawMessage, bool) {
	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err != nil {
		return nil, false
	}
	return arr, true
}

func scalars(arr []json.RawMessage) []string {
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		out = append(out, scalar(e))
	}
	return out
}

func scalar(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	return strings.TrimSpace(string(raw))
}

func capString(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	return s[:max] + "\n…[truncated]…"
}

// AgentTool satisfies agent.Tool structurally so toolcat never imports agent.
type AgentTool struct {
	b *Broker
	t Tool
}

// AgentTools drops reserved ids: the caller appends after the belt, so one would shadow.
func (b *Broker) AgentTools() []AgentTool {
	out := make([]AgentTool, 0, len(b.Tools))
	for _, t := range b.Tools {
		if ReservedIDs[t.ID] {
			continue
		}
		out = append(out, AgentTool{b: b, t: t})
	}
	return out
}

func (a AgentTool) Name() string { return a.t.ID }
func (a AgentTool) Description() string {
	return a.t.Description + " [catalog:" + string(a.t.Kind) + "]"
}

const defaultInImageSchema = `{"type":"object","properties":{"args":{"type":"array","items":{"type":"string"},"description":"positional arguments, appended after the tool's fixed args"}}}`

// an MCP tool's arguments go verbatim to the server: never advertise the args shape
const defaultMCPSchema = `{"type":"object","description":"arguments are forwarded verbatim to the MCP server's tool; no schema was declared for it, so use the parameter names that server documents","additionalProperties":true}`

func (a AgentTool) Schema() json.RawMessage {
	// must stay valid JSON: this is copied raw into every provider request
	if s := strings.TrimSpace(a.t.Schema); s != "" && json.Valid([]byte(s)) {
		return json.RawMessage(s)
	}
	switch a.t.Kind {
	case ExternalMCP, Sidecar:
		return json.RawMessage(defaultMCPSchema)
	default:
		return json.RawMessage(defaultInImageSchema)
	}
}
func (a AgentTool) Invoke(ctx context.Context, args json.RawMessage) (string, error) {
	return a.b.Invoke(ctx, a.t.ID, args)
}
