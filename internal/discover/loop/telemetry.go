package loop

import (
	"context"
	"strconv"

	"github.com/0xjustus/quarry/internal/publish/channels"
)

// record emits one de-identified telemetry Event (best-effort, swallowed on failure); no-op without a sink.
func (l *Loop) record(ctx context.Context, runID, kind string, fields map[string]string) {
	if l.Telemetry == nil {
		return
	}
	_ = l.Telemetry.Record(ctx, channels.Event{Kind: kind, RunID: runID, Fields: fields})
}

// RefreshCommons pulls any newer bundle from the UpdateFeed; nil feed reports (Update{}, false, nil).
func (l *Loop) RefreshCommons(ctx context.Context, sinceVersion string) (channels.Update, bool, error) {
	if l.Updates == nil {
		return channels.Update{}, false, nil
	}
	upd, ok, err := l.Updates.Pull(ctx, sinceVersion)
	if err != nil {
		l.log("commons update pull: %v", err)
		return channels.Update{}, false, err
	}
	l.record(ctx, "", "query", map[string]string{"source": "update-feed", "since": sinceVersion, "updated": strconv.FormatBool(ok)})
	if ok {
		l.log("commons refresh: pulled bundle version %s (since %s)", upd.Version, sinceVersion)
	}
	return upd, ok, nil
}
