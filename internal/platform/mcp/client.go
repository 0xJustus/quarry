package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/0xjustus/quarry/internal/platform/envscrub"
)

type Client struct{}

func New() *Client { return &Client{} }

type rpcReq struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id,omitempty"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

type rpcResp struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int             `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// keep in sync with toolcat.MCPCaller
func (c *Client) CallTool(ctx context.Context, command []string, tool string, args json.RawMessage, timeout time.Duration) (string, error) {
	if len(command) == 0 {
		return "", fmt.Errorf("mcp: empty server command")
	}
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(runCtx, command[0], command[1:]...)
	// never inherit the env: this server runs on the host, outside the sandbox
	cmd.Env = envscrub.Environ()
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return "", err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("mcp: start server: %w", err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()

	enc := json.NewEncoder(stdin)
	scan := bufio.NewScanner(stdout)
	scan.Buffer(make([]byte, 0, 64<<10), 8<<20)

	send := func(v any) error { return enc.Encode(v) }
	readResp := func(id int) (rpcResp, error) {
		for scan.Scan() {
			line := strings.TrimSpace(scan.Text())
			if line == "" {
				continue
			}
			var r rpcResp
			if err := json.Unmarshal([]byte(line), &r); err != nil {
				continue
			}
			if r.ID == id {
				return r, nil
			}
		}
		if err := scan.Err(); err != nil {
			return rpcResp{}, err
		}
		return rpcResp{}, fmt.Errorf("mcp: server closed before responding to id %d", id)
	}

	// required order: initialize, initialized notification, then tools/call
	if err := send(rpcReq{JSONRPC: "2.0", ID: 1, Method: "initialize", Params: map[string]any{
		"protocolVersion": "2024-11-05",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "quarry", "version": "0.1"},
	}}); err != nil {
		return "", err
	}
	if r, err := readResp(1); err != nil {
		return "", err
	} else if r.Error != nil {
		return "", fmt.Errorf("mcp: initialize: %s", r.Error.Message)
	}
	_ = send(rpcReq{JSONRPC: "2.0", Method: "notifications/initialized"})

	if len(args) == 0 {
		args = json.RawMessage("{}")
	}
	if err := send(rpcReq{JSONRPC: "2.0", ID: 2, Method: "tools/call", Params: map[string]any{
		"name":      tool,
		"arguments": args,
	}}); err != nil {
		return "", err
	}
	resp, err := readResp(2)
	if err != nil {
		return "", err
	}
	if resp.Error != nil {
		return "", fmt.Errorf("mcp: tools/call %q: %s", tool, resp.Error.Message)
	}
	return extractText(resp.Result), nil
}

func extractText(result json.RawMessage) string {
	var r struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	}
	if err := json.Unmarshal(result, &r); err != nil {
		return strings.TrimSpace(string(result))
	}
	var b strings.Builder
	for _, c := range r.Content {
		if c.Type == "text" {
			b.WriteString(c.Text)
		}
	}
	out := b.String()
	if r.IsError {
		return "TOOL ERROR: " + out
	}
	return out
}
