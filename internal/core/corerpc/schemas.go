package corerpc

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/0xjustus/quarry/internal/core"
)

var schemaTypes = map[string]reflect.Type{
	"verify":           reflect.TypeOf(core.VerifyRequest{}),
	"impact.grade":     reflect.TypeOf(core.ImpactGradeRequest{}),
	"sarif.ingest":     reflect.TypeOf(core.SarifIngestRequest{}),
	"oracle":           reflect.TypeOf(core.OracleValidateRequest{}),
	"minimize":         reflect.TypeOf(core.MinimizeRequest{}),
	"diff":             reflect.TypeOf(core.DiffRequest{}),
	"lang.detect":      reflect.TypeOf(core.LangDetectRequest{}),
	"lang.ground":      reflect.TypeOf(core.LangGroundRequest{}),
	"lang.fuzz":        reflect.TypeOf(core.LangFuzzRequest{}),
	"lang.discover":    reflect.TypeOf(core.LangDiscoverRequest{}),
	"synth":            reflect.TypeOf(core.SynthRequest{}),
	"chains":           reflect.TypeOf(core.ChainsRequest{}),
	"dispatch":         reflect.TypeOf(core.DispatchRequest{}),
	"commons.ingest":   reflect.TypeOf(core.CommonsIngestRequest{}),
	"commons.verify":   reflect.TypeOf(core.CommonsVerifyRequest{}),
	"binfuzz":          reflect.TypeOf(core.BinfuzzRequest{}),
	"binnav":           reflect.TypeOf(core.BinnavRequest{}),
	"bindisco":         reflect.TypeOf(core.BindiscoRequest{}),
	"sinkpoints":       reflect.TypeOf(core.SinkpointsRequest{}),
	"callgraph":        reflect.TypeOf(core.CallgraphRequest{}),
	"cpg.generate":     reflect.TypeOf(core.CPGGenerateRequest{}),
	"cpg.callers":      reflect.TypeOf(core.CPGFuncRequest{}),
	"cpg.callees":      reflect.TypeOf(core.CPGFuncRequest{}),
	"cpg.bounds":       reflect.TypeOf(core.CPGFuncRequest{}),
	"cpg.slice":        reflect.TypeOf(core.CPGFuncRequest{}),
	"cpg.reaches":      reflect.TypeOf(core.CPGReachesRequest{}),
	"cpg.taint":        reflect.TypeOf(core.CPGTaintRequest{}),
	"cpg.sinks":        reflect.TypeOf(core.CPGSinksRequest{}),
	"report":           reflect.TypeOf(core.ReportRequest{}),
	"query":            reflect.TypeOf(core.QueryRequest{}),
	"corpus.mine":      reflect.TypeOf(core.CorpusMineRequest{}),
	"corpus.build":     reflect.TypeOf(core.CorpusBuildRequest{}),
	"hydrate":          reflect.TypeOf(core.HydrateRequest{}),
	"catalog":          reflect.TypeOf(core.CatalogRequest{}),
	"toolctl.populate": reflect.TypeOf(core.ToolPopulateRequest{}),
	"toolctl.list":     reflect.TypeOf(core.ToolListRequest{}),
	"toolctl.verify":   reflect.TypeOf(core.ToolVerifyRequest{}),
	"provision":        reflect.TypeOf(core.ProvisionPlanRequest{}),
	"autovet":          reflect.TypeOf(core.AutovetRequest{}),
	"investigate":      reflect.TypeOf(core.InvestigateRequest{}),
	"fuzz":             reflect.TypeOf(core.FuzzRequest{}),
	"ensemble":         reflect.TypeOf(core.EnsembleRequest{}),
}

func (s *Server) registerSchema() {
	reg(s, "schema", func(ctx context.Context, e *core.Engine, p json.RawMessage) (any, error) {
		var req struct {
			Op string `json:"op"`
		}
		if err := decode(p, &req); err != nil {
			return nil, err
		}
		if req.Op != "" {
			t, ok := schemaTypes[req.Op]
			if !ok {
				return nil, fmt.Errorf("schema: unknown op %q", req.Op)
			}
			return core.SchemaOf(req.Op, t), nil
		}
		out := make([]core.OpSchema, 0, len(schemaTypes))
		for op, t := range schemaTypes {
			out = append(out, core.SchemaOf(op, t))
		}
		return map[string]any{"schemas": out}, nil
	})
}
