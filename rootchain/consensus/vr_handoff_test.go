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

// fakeObsQueue is the durable observation queue in memory (storage.BoltDB's behaviour: entries oldest first, an acknowledgement deletes the exact head
// and stores the cursor).
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

func (q *fakeObsQueue) AckObservation(id storage.ObservationID, prev [32]byte) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.entries) == 0 || q.entries[0].ID() != id {
		return errors.New("the acknowledgement does not match the queue head")
	}
	q.entries = q.entries[1:]
	q.cursor = storage.ObservationCursor{Set: true, ID: id, Prev: prev}
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
	return &vrHandoff{cfg: VRHandoffConfig{Log: slog.New(slog.DiscardHandler)}, obsWake: make(chan struct{}, 1), obsq: func() storage.ObservationQueue { return q },
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
	more, err := v.drain(context.Background())
	require.NoError(t, err)
	require.False(t, more)
	s, ok := sources.Get(r)
	require.True(t, ok)
	require.EqualValues(t, 11, s.CertRootRound)
	require.EqualValues(t, 1011, s.CertUCTime)
	require.EqualValues(t, 102, s.EVMBlockNumber, "the verified EVM height of block 2, not its shard round")
	require.Zero(t, q.len(), "every acknowledged entry left the queue")
	require.True(t, q.cursor.Set)
	require.EqualValues(t, 12, q.cursor.ID.Round)
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
		more, err := v.drain(context.Background())
		require.NoError(t, err)
		require.False(t, more)
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
	more, err := v1.drain(context.Background())
	require.NoError(t, err)
	require.False(t, more) // round 10 acknowledged, nothing published yet
	require.True(t, q.cursor.Set)
	q.add(obs(11, 10, 1011, 2, 2), obs(12, 11, 1012, 2, 2)) // committed while the process was down

	// the restarted process: a new store (it recorded nothing), a new observer, the same durable queue
	second, err := vrschedule.NewSources("")
	require.NoError(t, err)
	v2 := newObsWorker(t, reader, second, q)
	more, err = v2.drain(context.Background())
	require.NoError(t, err)
	require.False(t, more)
	s, ok := second.Get(r)
	require.True(t, ok, "the publication at round 11 is recorded after the restart")
	require.EqualValues(t, 11, s.CertRootRound)
	require.Zero(t, q.len())
}

func TestObservationContinuityBreaksAcrossEpochs(t *testing.T) {
	first, second := vrschema.Word{1}, vrschema.Word{2}
	sources, err := vrschedule.NewSources("")
	require.NoError(t, err)
	q := &fakeObsQueue{}
	v := newObsWorker(t, recordingReader{out: map[[32]byte]*vrhandoff.Output{
		{2}: publishedOutput(first), {3}: publishedOutput(second),
	}}, sources, q)
	old, successor, child := obs(12, 11, 1000, 1, 1), obs(13, 12, 1011, 2, 2), obs(14, 13, 1012, 3, 3)
	old.RootEpoch, successor.RootEpoch, child.RootEpoch = 1, 2, 2
	q.add(old, successor, child)
	more, err := v.drain(context.Background())
	require.NoError(t, err)
	require.False(t, more)
	_, ok := sources.Get(first)
	require.False(t, ok, "round 12 of the old epoch is not the successor's anchor")
	s, ok := sources.Get(second)
	require.True(t, ok)
	require.EqualValues(t, 14, s.CertRootRound)
}

type proofWindowReader struct {
	recordingReader
	window uint64
	tip    uint64
}

func (r *proofWindowReader) OpenOutput(ctx context.Context, hash, root [32]byte) (*vrhandoff.Output, error) {
	height, _ := r.HeaderNumber(ctx, hash)
	if r.tip-height > r.window {
		return nil, errors.New("historical state proof exceeds the configured window")
	}
	return r.recordingReader.OpenOutput(ctx, hash, root)
}

func TestArchivedProofsResumeAtTheOriginalPublicationBoundary(t *testing.T) {
	result := vrschema.Word{1}
	sources, err := vrschedule.NewSources("")
	require.NoError(t, err)
	reader := &proofWindowReader{recordingReader: recordingReader{out: map[[32]byte]*vrhandoff.Output{
		{2}: publishedOutput(result), {70}: publishedOutput(result),
	}}, tip: 101, window: 64}
	q := &fakeObsQueue{}
	v := newObsWorker(t, reader, sources, q)
	q.add(obs(10, 9, 1000, 1, 1))
	_, err = v.drain(context.Background())
	require.NoError(t, err)

	reader.tip = 170
	q.add(obs(11, 10, 1011, 2, 2), obs(12, 11, 1012, 70, 70))
	_, err = v.drain(context.Background())
	require.ErrorContains(t, err, "historical state proof")
	require.Equal(t, 2, q.len(), "the readable successor cannot replace the expired publication boundary")

	// The private archive serves the verified historical proof at the same hash.
	reader.window = ^uint64(0)
	_, err = v.drain(context.Background())
	require.NoError(t, err)
	source, ok := sources.Get(result)
	require.True(t, ok)
	require.EqualValues(t, 11, source.CertRootRound)
	require.EqualValues(t, 102, source.EVMBlockNumber)
	require.Zero(t, q.len())
}

func TestObservationWorkerRefreshesBetweenBatches(t *testing.T) {
	sources, err := vrschedule.NewSources("")
	require.NoError(t, err)
	q := &fakeObsQueue{}
	for i := uint64(1); i <= observationBatch*2+1; i++ {
		q.add(obs(i, i-1, i, 1, 1))
	}
	v := newObsWorker(t, recordingReader{}, sources, q)
	remaining := make(chan int, 3)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	v.update = func() (vrschedule.Committed, error) {
		select {
		case remaining <- q.len():
		case <-ctx.Done():
		}
		return vrschedule.Committed{}, errors.New("not derivable in this test")
	}
	go v.run(ctx)
	for _, want := range []int{observationBatch + 1, 1, 0} {
		select {
		case got := <-remaining:
			require.Equal(t, want, got)
		case <-time.After(5 * time.Second):
			t.Fatal("worker did not refresh")
		}
	}
}

func TestObservationRetryWaitsDespiteCommitWakeups(t *testing.T) {
	sources, err := vrschedule.NewSources("")
	require.NoError(t, err)
	q := &fakeObsQueue{}
	q.add(obs(11, 10, 1011, 2, 2))
	reader := &outageReader{failing: map[[32]byte]bool{{2}: true}}
	v := newObsWorker(t, reader, sources, q)
	refreshes := make(chan time.Time, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	v.update = func() (vrschedule.Committed, error) {
		select {
		case refreshes <- time.Now():
		case <-ctx.Done():
		}
		return vrschedule.Committed{}, errors.New("not derivable in this test")
	}
	go v.run(ctx)
	first := <-refreshes
	for i := 0; i < 10; i++ {
		v.obsWakeup()
	}
	select {
	case retry := <-refreshes:
		require.GreaterOrEqual(t, retry.Sub(first), observeBackoffMin)
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not retry")
	}
}
