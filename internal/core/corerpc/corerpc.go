package corerpc

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sync"

	"github.com/0xjustus/quarry/internal/core"
	"github.com/0xjustus/quarry/internal/platform/audit"
)

type Request struct {
	ID     int             `json:"id"`
	Op     string          `json:"op"`
	Params json.RawMessage `json:"params,omitempty"`
}

type Response struct {
	ID     int    `json:"id"`
	Result any    `json:"result,omitempty"`
	Error  string `json:"error,omitempty"`
}

type Note struct {
	Audit *audit.Entry `json:"audit,omitempty"`
}

type handler func(ctx context.Context, eng *core.Engine, params json.RawMessage) (any, error)

type Server struct {
	eng      *core.Engine
	handlers map[string]handler
}

func NewServer(eng *core.Engine) *Server {
	s := &Server{eng: eng, handlers: map[string]handler{}}
	reg(s, "verify", func(ctx context.Context, e *core.Engine, p json.RawMessage) (any, error) {
		var req core.VerifyRequest
		if err := decode(p, &req); err != nil {
			return nil, err
		}
		return e.Verify(ctx, req)
	})
	reg(s, "impact.grade", func(ctx context.Context, e *core.Engine, p json.RawMessage) (any, error) {
		var req core.ImpactGradeRequest
		if err := decode(p, &req); err != nil {
			return nil, err
		}
		return e.ImpactGrade(ctx, req)
	})
	reg(s, "sarif.ingest", func(ctx context.Context, e *core.Engine, p json.RawMessage) (any, error) {
		var req core.SarifIngestRequest
		if err := decode(p, &req); err != nil {
			return nil, err
		}
		return e.SarifIngest(ctx, req)
	})
	s.registerGenerated()
	s.registerSchema()
	reg(s, "ops", func(_ context.Context, _ *core.Engine, _ json.RawMessage) (any, error) {
		return map[string]any{"ops": s.Ops()}, nil
	})
	return s
}

func reg(s *Server, op string, h handler) { s.handlers[op] = h }

func decode(p json.RawMessage, v any) error {
	if len(p) == 0 {
		return nil
	}
	return json.Unmarshal(p, v)
}

func paramDigest(p json.RawMessage) string {
	if len(p) == 0 {
		return "none"
	}
	sum := sha256.Sum256(p)
	return "sha256:" + hex.EncodeToString(sum[:8])
}

func (s *Server) Ops() []string {
	ops := make([]string, 0, len(s.handlers))
	for k := range s.handlers {
		ops = append(ops, k)
	}
	return ops
}

func (s *Server) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	var wmu sync.Mutex
	enc := json.NewEncoder(out)
	write := func(v any) {
		wmu.Lock()
		defer wmu.Unlock()
		_ = enc.Encode(v)
	}

	stream, cancelStream := s.eng.Audit().Subscribe(256)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for e := range stream {
			ent := e
			write(Note{Audit: &ent})
		}
	}()
	defer func() { cancelStream(); <-done }()

	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 1<<20), 64<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var req Request
		if err := json.Unmarshal(line, &req); err != nil {
			s.eng.Audit().Record("rpc.recv", audit.KindAccess, "malformed", "rejected", err, 0)
			write(Response{Error: "malformed request: " + err.Error()})
			continue
		}
		write(s.Dispatch(ctx, req))
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	return sc.Err()
}

func (s *Server) Dispatch(ctx context.Context, req Request) Response {
	s.eng.Audit().Record("rpc.recv", audit.KindAccess, fmt.Sprintf("op:%s id:%d params:%s", req.Op, req.ID, paramDigest(req.Params)), "", nil, 0)
	h, ok := s.handlers[req.Op]
	if !ok {
		s.eng.Audit().Record("rpc.reject", audit.KindAccess, "op:"+req.Op, "unknown-op", nil, 0)
		return Response{ID: req.ID, Error: fmt.Sprintf("unknown op %q", req.Op)}
	}
	res, err := h(ctx, s.eng, req.Params)
	if err != nil {
		return Response{ID: req.ID, Error: err.Error()}
	}
	return Response{ID: req.ID, Result: res}
}
