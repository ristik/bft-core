package configuredadmission

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type traceRecords struct {
	mu   sync.Mutex
	recs []map[string]any
	msgs []string
}

func (h *traceRecords) Enabled(context.Context, slog.Level) bool { return true }
func (h *traceRecords) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	m := map[string]any{}
	r.Attrs(func(a slog.Attr) bool { m[a.Key] = a.Value.Any(); return true })
	h.recs, h.msgs = append(h.recs, m), append(h.msgs, r.Message)
	return nil
}
func (h *traceRecords) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *traceRecords) WithGroup(string) slog.Handler      { return h }

// bft-core#728 trace: a call that waits for the coordinator's lock names the call that held it and for how long.
func TestRecoveryTraceNamesTheHolderOfTheLock(t *testing.T) {
	r := &ExecutionRecovery{}
	first := r.startTrace("Recover")
	require.Empty(t, first.holderOp, "nobody held the lock")
	release := first.enter(r)
	time.Sleep(20 * time.Millisecond)

	second := r.startTrace("AcquireForCertificate")
	require.Equal(t, "Recover", second.holderOp)
	require.GreaterOrEqual(t, second.holderFor, 20*time.Millisecond)
	release()

	third := r.startTrace("Recover")
	require.Empty(t, third.holderOp, "the holder is cleared when its call ends")

	// a later holder is not cleared by an earlier one releasing late
	releaseSecond := second.enter(r)
	release()
	require.Equal(t, "AcquireForCertificate", r.startTrace("Recover").holderOp)
	releaseSecond()
}

func TestRecoveryTraceLogsTimingsAtDebugLevelAndToleratesNoLoggerOrCertificate(t *testing.T) {
	r := &ExecutionRecovery{}
	tr := r.startTrace("Recover")
	defer tr.enter(r)()
	tr.load, tr.chain, tr.acquire, tr.acquired, tr.acquireErr = time.Millisecond, 2*time.Millisecond, 3*time.Millisecond, true, "no provider"

	tr.log(context.Background(), nil, nil) // no logger: nothing happens

	rec := &traceRecords{}
	tr.log(context.Background(), slog.New(rec), nil) // no certificate: still logged
	require.Equal(t, []string{"recovery: call timing"}, rec.msgs)
	got := rec.recs[0]
	require.Equal(t, "Recover", got["op"])
	require.Equal(t, 3*time.Millisecond, got["peerCatchUp"])
	require.Equal(t, "no provider", got["peerCatchUpErr"])
	require.Contains(t, got, "lockWait")
	require.NotContains(t, got, "rootRound")
}
