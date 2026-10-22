package archivewiring

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/configuredprogress"
	"github.com/unicitynetwork/bft-core/frontier"
)

type recordedLog struct {
	mu      sync.Mutex
	records []slog.Record
}

func (r *recordedLog) Enabled(context.Context, slog.Level) bool { return true }
func (r *recordedLog) Handle(_ context.Context, rec slog.Record) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.records = append(r.records, rec)
	return nil
}
func (r *recordedLog) WithAttrs([]slog.Attr) slog.Handler { return r }
func (r *recordedLog) WithGroup(string) slog.Handler      { return r }
func (r *recordedLog) levels() []slog.Level {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []slog.Level
	for _, rec := range r.records {
		out = append(out, rec.Level)
	}
	return out
}

// The promised anchor stays verifiable while any two configured replicas hold it, and not with one.
func TestVerifyFrontierCopiesCountsTwoConfiguredReplicas(t *testing.T) {
	t.Parallel()
	x := newTwoOfThree(t, 8, [3]bool{true, true, true}, [3]bool{})
	require.NoError(t, x.worker.Pass(context.Background()))
	require.NotNil(t, x.anchor(t))
	verify := func() error {
		return x.f.store.VerifyFrontierCopies(context.Background(), x.f.context, x.f.limits)
	}
	require.NoError(t, verify())
	x.stop(t, 1)
	require.NoError(t, verify(), "two of three left")
	x.stop(t, 2)
	require.ErrorIs(t, verify(), frontier.ErrUnavailable, "one copy left")
}

// A replica that has none of the promised history (it was down, or replaced and empty) is filled in by the audit sweep, including
// records the journal has already pruned, from the local archive.
func TestAuditBackfillsAReplicaThatMissedHistory(t *testing.T) {
	t.Parallel()
	x := newTwoOfThree(t, 8, [3]bool{true, true, false}, [3]bool{})
	for i := 0; i < 4; i++ {
		require.NoError(t, x.worker.Pass(context.Background()))
	}
	anchor := x.anchor(t)
	require.NotNil(t, anchor)
	snap, err := x.f.store.LoadFrontier(context.Background(), x.f.context, x.f.limits)
	require.NoError(t, err)
	require.Equal(t, anchor.Height, snap.Floor, "history is pruned from the journal")
	missing := 0
	for i, entry := range x.f.entries {
		if entry.Candidate.Number > anchor.Height {
			continue
		}
		q, _ := x.f.record(t, i)
		if _, err := x.stores[2].Get(q); err != nil {
			require.ErrorIs(t, err, archive.ErrUnavailable)
			missing++
		}
	}
	require.Zero(t, missing, "the returning replica holds every promised record")
}

func TestArchiveHealthReportsFrozenAndCapacity(t *testing.T) {
	cases := map[string]struct {
		replicas []ReplicaReport
		usage    JournalUsage
		tip      uint64
		frontier uint64
		healthy  int
		frozen   bool
		warn     bool
		uncover  uint64
	}{
		"all healthy":    {[]ReplicaReport{{Replica: "a"}, {Replica: "b"}, {Replica: "c"}}, JournalUsage{CandidatesUsed: 7, CandidatesCap: 256}, 10, 9, 3, false, false, 1},
		"one down":       {[]ReplicaReport{{Replica: "a"}, {Replica: "b", Error: "dial"}, {Replica: "c"}}, JournalUsage{CandidatesUsed: 7, CandidatesCap: 256}, 10, 10, 2, false, false, 0},
		"two down":       {[]ReplicaReport{{Replica: "a"}, {Replica: "b", Error: "dial"}, {Replica: "c", Error: "dial"}}, JournalUsage{CandidatesUsed: 7, CandidatesCap: 256}, 300, 20, 1, true, false, 280},
		"pair, one down": {[]ReplicaReport{{Replica: "a"}, {Replica: "b", Error: "dial"}}, JournalUsage{}, 5, 5, 1, true, false, 0},
		"at 75 percent":  {[]ReplicaReport{{Replica: "a"}, {Replica: "b"}}, JournalUsage{CandidatesUsed: 192, CandidatesCap: 256}, 5, 5, 2, false, true, 0},
		"below 75":       {[]ReplicaReport{{Replica: "a"}, {Replica: "b"}}, JournalUsage{ObservationsUsed: 383, ObservationsCap: 512}, 5, 5, 2, false, false, 0},
		"bytes bound":    {[]ReplicaReport{{Replica: "a"}, {Replica: "b"}}, JournalUsage{BytesUsed: 50 << 20, BytesCap: 64 << 20}, 5, 5, 2, false, true, 0},
	}
	for name, tc := range cases {
		s := OperatorStatus{Replicas: tc.replicas, Journal: tc.usage, CertifiedTip: &BlockPin{Height: tc.tip}, PruneFrontier: &BlockPin{Height: tc.frontier}}
		h := archiveHealth(s)
		require.Equal(t, tc.healthy, h.ReplicasHealthy, name)
		require.Equal(t, tc.frozen, h.Frozen, name)
		require.Equal(t, tc.warn, h.CapacityWarning, name)
		require.Equal(t, tc.uncover, h.UncoveredBlocks, name)
		require.Equal(t, replicaCopies, h.CopiesRequired, name)
		if tc.uncover != 0 {
			require.Equal(t, tc.frontier+1, h.OldestUncoveredHeight, name)
		}
	}
}

func TestPublisherWarnsOnceThenQuietlyAndAgainOnANewError(t *testing.T) {
	log := &recordedLog{}
	p := &Publisher{Log: slog.New(log)}
	ctx := context.Background()
	same := errors.New("dial failed")
	for i := 0; i < 5; i++ {
		p.warnThrottled(ctx, "archive replica waiting", same, "replica", "a")
	}
	require.Equal(t, []slog.Level{slog.LevelWarn, slog.LevelDebug, slog.LevelDebug, slog.LevelDebug, slog.LevelDebug}, log.levels())
	p.warnThrottled(ctx, "archive replica waiting", errors.New("different"), "replica", "a")
	p.warnThrottled(ctx, "archive replica waiting", same, "replica", "b")
	require.Equal(t, []slog.Level{slog.LevelWarn, slog.LevelWarn}, log.levels()[5:], "a new error text or replica warns at once")
	// The same failure with a different height or hash is the same message.
	for _, height := range []string{"4", "5", "6"} {
		p.warnThrottled(ctx, "archive publication waiting", errors.New("block "+height+" hash 0x"+height+"abc: replica unavailable"))
	}
	require.Equal(t, []slog.Level{slog.LevelWarn, slog.LevelDebug, slog.LevelDebug}, log.levels()[7:])
}

func TestFrontierWorkerWarnsNearCapacityOncePerMinute(t *testing.T) {
	log := &recordedLog{}
	w := &FrontierWorker{Log: slog.New(log), Limits: configuredprogress.JournalLimits{Candidates: 8, Observations: 100, Bytes: 1 << 20}}
	image := configuredprogress.JournalSnapshot{Candidates: make([]configuredprogress.JournalEntry, 5)}
	w.warnCapacity(context.Background(), image)
	require.Empty(t, log.levels(), "5 of 8 is 62%")
	image.Candidates = make([]configuredprogress.JournalEntry, 6)
	w.warnCapacity(context.Background(), image)
	w.warnCapacity(context.Background(), image)
	require.Equal(t, []slog.Level{slog.LevelWarn}, log.levels(), "6 of 8 is 75%: one warning, not one per pass")
}
