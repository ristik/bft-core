package consensus

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	"github.com/unicitynetwork/bft-core/rootchain/vrschedule"
	"github.com/unicitynetwork/bft-core/vradmit"
	"github.com/unicitynetwork/bft-core/vrhandoff"
	"github.com/unicitynetwork/bft-core/vrschema"
)

type recordingReader struct {
	out map[[32]byte]*vrhandoff.Output
}

// HeaderNumber resolves the certified block's true EVM number: the fixture certifies block hash {b..} at height 100+b, unequal to the shard
// round (b) it also carries, so the test can tell the two apart.
func (r recordingReader) HeaderNumber(_ context.Context, h [32]byte) (uint64, error) {
	return 100 + uint64(h[0]), nil
}

func (r recordingReader) OpenOutput(_ context.Context, _, root [32]byte) (*vrhandoff.Output, error) {
	return r.out[root], nil
}

// fakeObsQueue is the durable observation queue in memory (storage.BoltDB's behaviour: entries oldest first, an acknowledgement deletes up
// to a round and stores the cursor).
type fakeObsQueue struct {
	mu      sync.Mutex
	entries []storage.ObservationInput
	cursor  storage.ObservationCursor
}

func (q *fakeObsQueue) add(es ...storage.ObservationInput) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.entries = append(q.entries, es...)
}

func (q *fakeObsQueue) PendingObservations(max int) ([]storage.ObservationInput, storage.ObservationCursor, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	n := min(max, len(q.entries))
	return append([]storage.ObservationInput(nil), q.entries[:n]...), q.cursor, nil
}

func (q *fakeObsQueue) AckObservation(round uint64, c storage.ObservationCursor) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	for len(q.entries) > 0 && q.entries[0].RootRound <= round {
		q.entries = q.entries[1:]
	}
	q.cursor = c
	return nil
}

func (q *fakeObsQueue) len() int { q.mu.Lock(); defer q.mu.Unlock(); return len(q.entries) }

// obs is the queued observation of a committed block that certifies EVM block hash {evmBlock}: the fixture's reader maps output state root
// {root} to the output and block hash {b} to the EVM height 100+b.
func obs(round, parent, ts uint64, evmBlock, root byte) storage.ObservationInput {
	return storage.ObservationInput{RootRound: round, ParentRound: parent, RootUCTime: ts, BlockHash: [32]byte{evmBlock}, StateRoot: [32]byte{root}, ShardRound: uint64(evmBlock)}
}

func newObsWorker(t *testing.T, reader vrschedule.Reader, sources *vrschedule.Sources, q *fakeObsQueue) *vrHandoff {
	t.Helper()
	return &vrHandoff{cfg: VRHandoffConfig{Log: slog.New(slog.DiscardHandler)}, obsWake: make(chan struct{}, 1), obsq: func() observationQueue { return q },
		update: func() (vrschedule.Committed, error) {
			return vrschedule.Committed{}, errors.New("not derivable in this test")
		},
		observer: &vrschedule.Observer{Reader: reader, Sources: sources, Outputs: vrschedule.NewOutputs()}}
}

func publishedOutput(r vrschema.Word) *vrhandoff.Output {
	return &vrhandoff.Output{State: vradmit.OutputState{ResultID: r, OpenOutput: r, Output: vrschema.OutputRecord{State: vrschema.OutPublished, OutputCommit: vrschema.Word{9}}}}
}

// The commit observer's worker consumes the durable queue: committed blocks reach the observer oldest first with their parent links, so the
// first committed block at which R is published becomes its source, with the verified EVM height; an acknowledged entry leaves the queue and
// the cursor records where the observer stands.
func TestTheCommitWorkerRecordsTheSourceFromTheDurableQueue(t *testing.T) {
	r := vrschema.Word{0x52}
	sources, err := vrschedule.NewSources("")
	require.NoError(t, err)
	q := &fakeObsQueue{}
	v := newObsWorker(t, recordingReader{out: map[[32]byte]*vrhandoff.Output{{2}: publishedOutput(r)}}, sources, q)
	q.add(obs(10, 9, 1000, 1, 1), obs(11, 10, 1011, 2, 2), obs(12, 11, 1012, 2, 2))
	require.True(t, v.drain(context.Background()))
	s, ok := sources.Get(r)
	require.True(t, ok)
	require.EqualValues(t, 11, s.CertRootRound)
	require.EqualValues(t, 1011, s.CertUCTime)
	require.EqualValues(t, 102, s.EVMBlockNumber, "the verified EVM height of block 2, not its shard round")
	require.Zero(t, q.len(), "every acknowledged entry left the queue")
	require.True(t, q.cursor.Set)
	require.EqualValues(t, 12, q.cursor.Round)
	require.Equal(t, [32]byte(r), q.cursor.Prev, "the result open at the last acknowledged block")
}

// outageReader fails the output read of chosen state roots until it is restored (a temporary execution-client outage).
type outageReader struct {
	recordingReader
	failing map[[32]byte]bool
	calls   int
}

func (o *outageReader) OpenOutput(ctx context.Context, b, root [32]byte) (*vrhandoff.Output, error) {
	o.calls++
	if o.failing[root] {
		return nil, errors.New("execution client unavailable")
	}
	return o.recordingReader.OpenOutput(ctx, b, root)
}

// astra r11: four equal roots; on three of them the output read of the PUBLISHING round fails (a temporary outage) and recovers later,
// while later blocks still show the result. The entry stays queued across many failed passes (the worker never gives up), and once the
// client recovers every root ends with the identical source of the original publication boundary.
func TestARootWhoseOutputReadFailsForThePublishingRoundStillRecordsTheSameSource(t *testing.T) {
	r := vrschema.Word{0x52}
	outs := map[[32]byte]*vrhandoff.Output{{2}: publishedOutput(r), {3}: publishedOutput(r), {4}: publishedOutput(r)}
	var want vrschedule.SourceEntry
	for i := 0; i < 4; i++ {
		sources, err := vrschedule.NewSources("")
		require.NoError(t, err)
		reader := &outageReader{recordingReader: recordingReader{out: outs}, failing: map[[32]byte]bool{}}
		q := &fakeObsQueue{}
		v := newObsWorker(t, reader, sources, q)
		if i > 0 { // roots 1..3: the output read of the publishing round (state root {2}) fails
			reader.failing[[32]byte{2}] = true
		}
		q.add(obs(10, 9, 1000, 1, 1), obs(11, 10, 1011, 2, 2), obs(12, 11, 1012, 3, 3), obs(13, 12, 1013, 4, 4))
		for pass := 0; pass < 30; pass++ { // far more than the old 21 attempts
			v.drain(context.Background())
		}
		if i > 0 {
			_, ok := sources.Get(r)
			require.False(t, ok, "root %d: the outage holds the publishing round's entry", i)
			require.Equal(t, 3, q.len(), "the failed entry and its successors stay queued; nothing is skipped")
			delete(reader.failing, [32]byte{2}) // the client recovers
		}
		require.True(t, v.drain(context.Background()))
		got, ok := sources.Get(r)
		require.True(t, ok, "root %d records the source once the client recovers", i)
		require.EqualValues(t, 11, got.CertRootRound, "the ORIGINAL publication boundary, not a later block that still shows the result")
		if i == 0 {
			want = got
		}
		require.Equal(t, want, got, "root %d holds the source of the uninterrupted observer", i)
	}
}

// A worker that starts late, with its wakeup missed, still consumes the queue: nothing is carried by the notification.
func TestALateWorkerWithAMissedWakeupConsumesTheQueue(t *testing.T) {
	r := vrschema.Word{0x52}
	sources, err := vrschedule.NewSources("")
	require.NoError(t, err)
	q := &fakeObsQueue{}
	q.add(obs(10, 9, 1000, 1, 1), obs(11, 10, 1011, 2, 2))
	v := newObsWorker(t, recordingReader{out: map[[32]byte]*vrhandoff.Output{{2}: publishedOutput(r)}}, sources, q)
	for i := 0; i < 5; i++ {
		v.onCommit(nil) // a burst of wakeups, none consumed: the channel is a wakeup only and never blocks
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go v.run(ctx)
	require.Eventually(t, func() bool { _, ok := sources.Get(r); return ok }, 5*time.Second, 10*time.Millisecond)
	// and with no wakeup at all, the poll finds new entries
	q.add(obs(12, 11, 1012, 3, 3))
	require.Eventually(t, func() bool { return q.len() == 0 }, 2*ObservePoll+2*time.Second, 20*time.Millisecond)
}

// A restart with a non-empty durable queue resumes from the acknowledged cursor: the first queued entry continues the run (it is the child of
// the last acknowledged block), so a publication in it is recorded rather than primed over.
func TestARestartWithANonEmptyQueueResumesFromTheAcknowledgedCursor(t *testing.T) {
	r := vrschema.Word{0x52}
	reader := recordingReader{out: map[[32]byte]*vrhandoff.Output{{2}: publishedOutput(r)}}
	q := &fakeObsQueue{}
	first, err := vrschedule.NewSources("")
	require.NoError(t, err)
	v1 := newObsWorker(t, reader, first, q)
	q.add(obs(10, 9, 1000, 1, 1))
	require.True(t, v1.drain(context.Background())) // round 10 acknowledged, nothing published yet
	require.True(t, q.cursor.Set)
	q.add(obs(11, 10, 1011, 2, 2), obs(12, 11, 1012, 2, 2)) // committed while the process was down

	// the restarted process: a new store (it recorded nothing), a new observer, the same durable queue
	second, err := vrschedule.NewSources("")
	require.NoError(t, err)
	v2 := newObsWorker(t, reader, second, q)
	require.True(t, v2.drain(context.Background()))
	s, ok := second.Get(r)
	require.True(t, ok, "the publication at round 11 is recorded after the restart")
	require.EqualValues(t, 11, s.CertRootRound)
	require.Zero(t, q.len())
}
