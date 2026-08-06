package core

import (
	"context"
	"fmt"

	"github.com/0xjustus/quarry/internal/platform/audit"
	"github.com/0xjustus/quarry/internal/verdict/oracle"
)

type OracleValidateRequest struct {
	Caller Caller `json:"caller,omitempty"`
	Data   []byte `json:"data,omitempty"`
	Spec   string `json:"spec,omitempty"`
}

type OracleValidateResult struct {
	Spec oracle.Spec `json:"spec"`
}

func (e *Engine) OracleValidate(ctx context.Context, req OracleValidateRequest) (OracleValidateResult, error) {
	log := e.logFor(req.Caller.Principal, req.Caller.Session)
	var arg string
	switch {
	case len(req.Data) > 0:
		arg = "data:" + digest(req.Data)
	case req.Spec != "":
		arg = "spec:" + req.Spec
	}
	sp := log.Start("core.OracleValidate", audit.KindAccess, arg)
	res, err := e.oracleValidate(req)
	sp.End(oracleValidateSummary(res, err), err)
	return res, err
}

func (e *Engine) oracleValidate(req OracleValidateRequest) (OracleValidateResult, error) {
	var s oracle.Spec
	var err error
	switch {
	case len(req.Data) > 0:
		s, err = oracle.Parse(req.Data)
	case req.Spec != "":
		s, err = oracle.ParseShortcut(req.Spec)
	default:
		return OracleValidateResult{}, fmt.Errorf("oracle validate: provide data (oracle YAML) or spec (shortcut)")
	}
	if err != nil {
		return OracleValidateResult{}, fmt.Errorf("oracle validate: %w", err)
	}
	return OracleValidateResult{Spec: s}, nil
}

func oracleValidateSummary(res OracleValidateResult, err error) string {
	if err != nil {
		return "invalid"
	}
	return fmt.Sprintf("valid require:%s conditions:%d", res.Spec.Require, len(res.Spec.Conditions))
}
