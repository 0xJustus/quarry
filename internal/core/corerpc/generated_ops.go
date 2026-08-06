package corerpc

import (
	"context"
	"encoding/json"

	"github.com/0xjustus/quarry/internal/core"
)

func (s *Server) registerGenerated() {
	reg(s, "oracle", func(ctx context.Context, e *core.Engine, p json.RawMessage) (any, error) {
		var r core.OracleValidateRequest
		if err := decode(p, &r); err != nil {
			return nil, err
		}
		return e.OracleValidate(ctx, r)
	})
	reg(s, "minimize", func(ctx context.Context, e *core.Engine, p json.RawMessage) (any, error) {
		var r core.MinimizeRequest
		if err := decode(p, &r); err != nil {
			return nil, err
		}
		return e.Minimize(ctx, r)
	})
	reg(s, "diff", func(ctx context.Context, e *core.Engine, p json.RawMessage) (any, error) {
		var r core.DiffRequest
		if err := decode(p, &r); err != nil {
			return nil, err
		}
		return e.Diff(ctx, r)
	})
	reg(s, "lang.detect", func(ctx context.Context, e *core.Engine, p json.RawMessage) (any, error) {
		var r core.LangDetectRequest
		if err := decode(p, &r); err != nil {
			return nil, err
		}
		return e.LangDetect(ctx, r)
	})
	reg(s, "lang.ground", func(ctx context.Context, e *core.Engine, p json.RawMessage) (any, error) {
		var r core.LangGroundRequest
		if err := decode(p, &r); err != nil {
			return nil, err
		}
		return e.LangGround(ctx, r)
	})
	reg(s, "lang.fuzz", func(ctx context.Context, e *core.Engine, p json.RawMessage) (any, error) {
		var r core.LangFuzzRequest
		if err := decode(p, &r); err != nil {
			return nil, err
		}
		return e.LangFuzz(ctx, r)
	})
	reg(s, "lang.discover", func(ctx context.Context, e *core.Engine, p json.RawMessage) (any, error) {
		var r core.LangDiscoverRequest
		if err := decode(p, &r); err != nil {
			return nil, err
		}
		return e.LangDiscover(ctx, r)
	})
	reg(s, "synth", func(ctx context.Context, e *core.Engine, p json.RawMessage) (any, error) {
		var r core.SynthRequest
		if err := decode(p, &r); err != nil {
			return nil, err
		}
		return e.Synth(ctx, r)
	})
	reg(s, "chains", func(ctx context.Context, e *core.Engine, p json.RawMessage) (any, error) {
		var r core.ChainsRequest
		if err := decode(p, &r); err != nil {
			return nil, err
		}
		return e.Chains(ctx, r)
	})
	reg(s, "dispatch", func(ctx context.Context, e *core.Engine, p json.RawMessage) (any, error) {
		var r core.DispatchRequest
		if err := decode(p, &r); err != nil {
			return nil, err
		}
		return e.Dispatch(ctx, r)
	})
	reg(s, "commons.ingest", func(ctx context.Context, e *core.Engine, p json.RawMessage) (any, error) {
		var r core.CommonsIngestRequest
		if err := decode(p, &r); err != nil {
			return nil, err
		}
		return e.CommonsIngest(ctx, r)
	})
	reg(s, "commons.verify", func(ctx context.Context, e *core.Engine, p json.RawMessage) (any, error) {
		var r core.CommonsVerifyRequest
		if err := decode(p, &r); err != nil {
			return nil, err
		}
		return e.CommonsVerify(ctx, r)
	})
	reg(s, "binfuzz", func(ctx context.Context, e *core.Engine, p json.RawMessage) (any, error) {
		var r core.BinfuzzRequest
		if err := decode(p, &r); err != nil {
			return nil, err
		}
		return e.Binfuzz(ctx, r)
	})
	reg(s, "binnav", func(ctx context.Context, e *core.Engine, p json.RawMessage) (any, error) {
		var r core.BinnavRequest
		if err := decode(p, &r); err != nil {
			return nil, err
		}
		return e.Binnav(ctx, r)
	})
	reg(s, "bindisco", func(ctx context.Context, e *core.Engine, p json.RawMessage) (any, error) {
		var r core.BindiscoRequest
		if err := decode(p, &r); err != nil {
			return nil, err
		}
		return e.Bindisco(ctx, r)
	})
	reg(s, "sinkpoints", func(ctx context.Context, e *core.Engine, p json.RawMessage) (any, error) {
		var r core.SinkpointsRequest
		if err := decode(p, &r); err != nil {
			return nil, err
		}
		return e.Sinkpoints(ctx, r)
	})
	reg(s, "callgraph", func(ctx context.Context, e *core.Engine, p json.RawMessage) (any, error) {
		var r core.CallgraphRequest
		if err := decode(p, &r); err != nil {
			return nil, err
		}
		return e.Callgraph(ctx, r)
	})
	reg(s, "cpg.generate", func(ctx context.Context, e *core.Engine, p json.RawMessage) (any, error) {
		var r core.CPGGenerateRequest
		if err := decode(p, &r); err != nil {
			return nil, err
		}
		return e.CPGGenerate(ctx, r)
	})
	reg(s, "cpg.callers", func(ctx context.Context, e *core.Engine, p json.RawMessage) (any, error) {
		var r core.CPGFuncRequest
		if err := decode(p, &r); err != nil {
			return nil, err
		}
		return e.CPGCallers(ctx, r)
	})
	reg(s, "cpg.callees", func(ctx context.Context, e *core.Engine, p json.RawMessage) (any, error) {
		var r core.CPGFuncRequest
		if err := decode(p, &r); err != nil {
			return nil, err
		}
		return e.CPGCallees(ctx, r)
	})
	reg(s, "cpg.bounds", func(ctx context.Context, e *core.Engine, p json.RawMessage) (any, error) {
		var r core.CPGFuncRequest
		if err := decode(p, &r); err != nil {
			return nil, err
		}
		return e.CPGBounds(ctx, r)
	})
	reg(s, "cpg.slice", func(ctx context.Context, e *core.Engine, p json.RawMessage) (any, error) {
		var r core.CPGFuncRequest
		if err := decode(p, &r); err != nil {
			return nil, err
		}
		return e.CPGSlice(ctx, r)
	})
	reg(s, "cpg.reaches", func(ctx context.Context, e *core.Engine, p json.RawMessage) (any, error) {
		var r core.CPGReachesRequest
		if err := decode(p, &r); err != nil {
			return nil, err
		}
		return e.CPGReaches(ctx, r)
	})
	reg(s, "cpg.taint", func(ctx context.Context, e *core.Engine, p json.RawMessage) (any, error) {
		var r core.CPGTaintRequest
		if err := decode(p, &r); err != nil {
			return nil, err
		}
		return e.CPGTaint(ctx, r)
	})
	reg(s, "cpg.sinks", func(ctx context.Context, e *core.Engine, p json.RawMessage) (any, error) {
		var r core.CPGSinksRequest
		if err := decode(p, &r); err != nil {
			return nil, err
		}
		return e.CPGSinks(ctx, r)
	})
	reg(s, "report", func(ctx context.Context, e *core.Engine, p json.RawMessage) (any, error) {
		var r core.ReportRequest
		if err := decode(p, &r); err != nil {
			return nil, err
		}
		return e.Report(ctx, r)
	})
	reg(s, "query", func(ctx context.Context, e *core.Engine, p json.RawMessage) (any, error) {
		var r core.QueryRequest
		if err := decode(p, &r); err != nil {
			return nil, err
		}
		return e.Query(ctx, r)
	})
	reg(s, "corpus.mine", func(ctx context.Context, e *core.Engine, p json.RawMessage) (any, error) {
		var r core.CorpusMineRequest
		if err := decode(p, &r); err != nil {
			return nil, err
		}
		return e.CorpusMine(ctx, r)
	})
	reg(s, "corpus.build", func(ctx context.Context, e *core.Engine, p json.RawMessage) (any, error) {
		var r core.CorpusBuildRequest
		if err := decode(p, &r); err != nil {
			return nil, err
		}
		return e.CorpusBuild(ctx, r)
	})
	reg(s, "hydrate", func(ctx context.Context, e *core.Engine, p json.RawMessage) (any, error) {
		var r core.HydrateRequest
		if err := decode(p, &r); err != nil {
			return nil, err
		}
		return e.Hydrate(ctx, r)
	})
	reg(s, "catalog", func(ctx context.Context, e *core.Engine, p json.RawMessage) (any, error) {
		var r core.CatalogRequest
		if err := decode(p, &r); err != nil {
			return nil, err
		}
		return e.Catalog(ctx, r)
	})
	reg(s, "toolctl.populate", func(ctx context.Context, e *core.Engine, p json.RawMessage) (any, error) {
		var r core.ToolPopulateRequest
		if err := decode(p, &r); err != nil {
			return nil, err
		}
		return e.ToolPopulate(ctx, r)
	})
	reg(s, "toolctl.list", func(ctx context.Context, e *core.Engine, p json.RawMessage) (any, error) {
		var r core.ToolListRequest
		if err := decode(p, &r); err != nil {
			return nil, err
		}
		return e.ToolList(ctx, r)
	})
	reg(s, "toolctl.verify", func(ctx context.Context, e *core.Engine, p json.RawMessage) (any, error) {
		var r core.ToolVerifyRequest
		if err := decode(p, &r); err != nil {
			return nil, err
		}
		return e.ToolVerify(ctx, r)
	})
	reg(s, "provision", func(ctx context.Context, e *core.Engine, p json.RawMessage) (any, error) {
		var r core.ProvisionPlanRequest
		if err := decode(p, &r); err != nil {
			return nil, err
		}
		return e.ProvisionPlan(ctx, r)
	})
	reg(s, "autovet", func(ctx context.Context, e *core.Engine, p json.RawMessage) (any, error) {
		var r core.AutovetRequest
		if err := decode(p, &r); err != nil {
			return nil, err
		}
		return e.Autovet(ctx, r)
	})
	reg(s, "investigate", func(ctx context.Context, e *core.Engine, p json.RawMessage) (any, error) {
		var r core.InvestigateRequest
		if err := decode(p, &r); err != nil {
			return nil, err
		}
		return e.Investigate(ctx, r)
	})
	reg(s, "fuzz", func(ctx context.Context, e *core.Engine, p json.RawMessage) (any, error) {
		var r core.FuzzRequest
		if err := decode(p, &r); err != nil {
			return nil, err
		}
		return e.Fuzz(ctx, r)
	})
	reg(s, "ensemble", func(ctx context.Context, e *core.Engine, p json.RawMessage) (any, error) {
		var r core.EnsembleRequest
		if err := decode(p, &r); err != nil {
			return nil, err
		}
		return e.Ensemble(ctx, r)
	})
}
