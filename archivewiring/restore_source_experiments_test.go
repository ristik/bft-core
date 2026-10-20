package archivewiring

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	libp2pnetwork "github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/shardnode"
)

// The H4 (#21) experiments "unavailable sources" and "rejected false readiness claims" for the archive restore, in process.
//
// A restore reads from two configured replicas (archivewiring.ArchiveRestore.Replicas). Its first phase walks the certified chain from
// the pinned tip to genesis, authenticating each record and retaining it in the local archive; only then does the second phase replay the
// local copies into the execution client. So a source can fail in three places, and each has a test below:
//
//   - during the fetch walk (one replica, then both);
//   - after the walk, during the replay (the replay must not need a source);
//   - by answering without serving: it accepts the stream and never answers, or it answers a request for one block with the record of
//     another. That is the replica "advertising" a record it cannot serve; the restore must bypass it and never accept the answer.
//
// What these tests do not show is a process-level lane (a replica process killed or lied through during a live restore). The fixtures use the
// real archive server, the real client framing and the real retry policy over libp2p, with the stream layer replaced for the faulty source.

// sourceHost is the restore's evidence host with a per-source fault hook. route sees every stream the restore opens (id, the 1-based
// number of streams opened to that peer so far) and may answer it itself; handled=false delegates to the real host.
type sourceHost struct {
	shardnode.EvidenceHost
	route func(ctx context.Context, id peer.ID, n int64) (stream libp2pnetwork.Stream, err error, handled bool)

	mu    sync.Mutex
	calls map[peer.ID]int64
}

func (h *sourceHost) opened(id peer.ID) int64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.calls[id]
}

func (h *sourceHost) total() int64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	var sum int64
	for _, n := range h.calls {
		sum += n
	}
	return sum
}

func (h *sourceHost) CreateStream(ctx context.Context, id peer.ID, protocol string) (libp2pnetwork.Stream, error) {
	h.mu.Lock()
	if h.calls == nil {
		h.calls = map[peer.ID]int64{}
	}
	h.calls[id]++
	n := h.calls[id]
	h.mu.Unlock()
	if h.route != nil {
		if s, err, ok := h.route(ctx, id, n); ok {
			return s, err
		}
	}
	return h.EvidenceHost.CreateStream(ctx, id, protocol)
}

// pipeStream is the client's end of a stream whose other end the test controls.
type pipeStream struct {
	libp2pnetwork.Stream
	c net.Conn
}

func (s *pipeStream) Read(p []byte) (int, error)        { return s.c.Read(p) }
func (s *pipeStream) Write(p []byte) (int, error)       { return s.c.Write(p) }
func (s *pipeStream) Close() error                      { return s.c.Close() }
func (s *pipeStream) Reset() error                      { return s.c.Close() }
func (s *pipeStream) SetDeadline(t time.Time) error     { return s.c.SetDeadline(t) }
func (s *pipeStream) SetReadDeadline(t time.Time) error { return s.c.SetReadDeadline(t) }

// silentSourceStream accepts the request and never answers.
func silentSourceStream() libp2pnetwork.Stream {
	client, far := net.Pipe()
	go func() { _, _ = io.Copy(io.Discard, far) }()
	return &pipeStream{c: client}
}

// substitutingStream serves each request through the real server, but for a different block than the one asked for: the replica
// claims to hold the record and answers with a genuine, correctly framed record that is not the requested one.
func substitutingStream(t *testing.T, server *Server, subject archive.Context, instead [32]byte) libp2pnetwork.Stream {
	client, far := net.Pipe()
	go func() {
		defer far.Close()
		frame, err := readFrame(far, maxArchiveFrameBytes)
		if err != nil || len(frame) < 2 || frame[0] != 2 {
			return
		}
		raw, err := archive.EncodeRequest(archive.Request{Context: subject, BlockHash: instead})
		if err != nil {
			return
		}
		var swapped bytes.Buffer
		if err := writeFrame(&swapped, append([]byte{2}, raw...)); err != nil {
			return
		}
		_ = server.Serve(context.Background(), struct {
			io.Reader
			io.Writer
		}{&swapped, far})
	}()
	return &pipeStream{c: client}
}

func blockHashes(t *testing.T, fx *retryRestoreFixture) (byNumber map[uint64][32]byte) {
	t.Helper()
	byNumber = map[uint64][32]byte{}
	for _, entry := range fx.wf.entries {
		q, _, err := FromJournal(context.Background(), fx.wf.context, fx.wf.subject, nil, entry)
		require.NoError(t, err)
		byNumber[entry.Candidate.Number] = q.BlockHash
	}
	return byNumber
}

func fastRetry(total time.Duration) FetchRetry {
	return FetchRetry{Initial: time.Millisecond, Max: 5 * time.Millisecond, Busy: time.Millisecond, Total: total}
}

func requireNothingRetained(t *testing.T, fx *retryRestoreFixture) {
	t.Helper()
	image, err := fx.journal.LoadJournal(context.Background(), fx.wf.context, fx.limits)
	require.NoError(t, err)
	require.Nil(t, image.Restored, "a failed restore must not leave a restore pin")
	require.Empty(t, image.Observations)
	require.Empty(t, image.Candidates)
	require.EqualValues(t, 0, fx.executor.head.Number, "the EL head must stay at the checked genesis")
	require.EqualValues(t, 0, fx.executor.finalized.Number)
}

// One replica is lost partway through the fetch walk (it served two records, then every stream to it fails). The restore completes from
// the other replica, and everything it replays is the authenticated chain.
func TestArchiveRestoreSurvivesLosingOneReplicaDuringTheFetchWalk(t *testing.T) {
	t.Parallel()
	fx := newRetryRestoreFixture(t, 0, fastRetry(20*time.Second))
	lost := fx.restore.Replicas[0]
	host := &sourceHost{EvidenceHost: fx.host}
	host.route = func(_ context.Context, id peer.ID, n int64) (libp2pnetwork.Stream, error, bool) {
		if id == lost && n > 2 {
			return nil, &StreamResetError{Peer: id, Operation: "fetch", Reason: errors.New("replica process is gone")}, true
		}
		return nil, nil, false
	}
	fx.restore.Host = host
	require.NoError(t, fx.restore.Restore(context.Background()))
	require.Greater(t, host.opened(lost), int64(2), "the loss must have happened during the walk, not after it")
	require.Positive(t, host.opened(fx.restore.Replicas[1]), "the other replica carried the rest")
	require.EqualValues(t, 5, fx.executor.head.Number)
	require.True(t, sameBlockRef(fx.executor.head, fx.executor.finalized))
	image, err := fx.journal.LoadJournal(context.Background(), fx.wf.context, fx.limits)
	require.NoError(t, err)
	require.NotNil(t, image.Restored)
}

// Both replicas are lost partway through the walk. The restore ends after its bounded wait, naming the restore refusal and the unavailable
// record. The failure is in the fetch phase, so nothing reached the journal or the execution client: no pin, no observation, EL at genesis.
// Once the sources are back, the same restore runs to completion on the same disks.
func TestArchiveRestoreLosingBothReplicasDuringTheFetchWalkEndsCleanlyAndResumes(t *testing.T) {
	t.Parallel()
	const total = 300 * time.Millisecond
	fx := newRetryRestoreFixture(t, 0, fastRetry(total))
	var cut atomic.Bool
	var served atomic.Int64
	host := &sourceHost{EvidenceHost: fx.host}
	host.route = func(_ context.Context, id peer.ID, _ int64) (libp2pnetwork.Stream, error, bool) {
		if cut.Load() {
			return nil, &StreamResetError{Peer: id, Operation: "fetch", Reason: errors.New("replica process is gone")}, true
		}
		if served.Add(1) > 2 {
			cut.Store(true)
			return nil, &StreamResetError{Peer: id, Operation: "fetch", Reason: errors.New("replica process is gone")}, true
		}
		return nil, nil, false
	}
	fx.restore.Host = host
	started := time.Now()
	err := fx.restore.Restore(context.Background())
	require.Error(t, err)
	require.ErrorIs(t, err, ErrRestore)
	require.ErrorIs(t, err, archive.ErrUnavailable)
	require.False(t, errors.Is(err, context.DeadlineExceeded))
	require.GreaterOrEqual(t, time.Since(started), total, "the restore waits out the bounded total before giving up")
	require.Less(t, time.Since(started), 10*time.Second)
	requireNothingRetained(t, fx)

	cut.Store(false)
	served.Store(-1 << 40)
	require.NoError(t, fx.restore.Restore(context.Background()), "the sources are back: the same restore completes on the same disks")
	require.EqualValues(t, 5, fx.executor.head.Number)
	image, err := fx.journal.LoadJournal(context.Background(), fx.wf.context, fx.limits)
	require.NoError(t, err)
	require.NotNil(t, image.Restored)
}

// The replay phase reads the local copies the walk retained and needs no source: with both replicas gone from the moment the first record is
// replayed, the restore still completes and opens no further stream.
func TestArchiveRestoreReplayDoesNotNeedTheSources(t *testing.T) {
	t.Parallel()
	fx := newRetryRestoreFixture(t, 0, fastRetry(300*time.Millisecond))
	var replaying atomic.Bool
	host := &sourceHost{EvidenceHost: fx.host}
	var atCut atomic.Int64
	host.route = func(_ context.Context, id peer.ID, _ int64) (libp2pnetwork.Stream, error, bool) {
		if replaying.Load() {
			return nil, &StreamResetError{Peer: id, Operation: "fetch", Reason: errors.New("replica process is gone")}, true
		}
		return nil, nil, false
	}
	fx.restore.Host = host
	fx.restore.Adapter = &replayProbe{RestoreExecutor: fx.executor, onFirstVerify: func() { atCut.Store(host.total()); replaying.Store(true) }}
	require.NoError(t, fx.restore.Restore(context.Background()))
	require.Positive(t, atCut.Load())
	require.Equal(t, atCut.Load(), host.total(), "no stream was opened once the replay began")
	require.EqualValues(t, 5, fx.executor.head.Number)
}

type replayProbe struct {
	RestoreExecutor
	once          sync.Once
	onFirstVerify func()
}

func (p *replayProbe) Verify(ctx context.Context, b shardnode.Block, params shardnode.RoundParams) (shardnode.Status, error) {
	p.once.Do(p.onFirstVerify)
	return p.RestoreExecutor.Verify(ctx, b, params)
}

// A replay that fails partway (here the execution client refuses the third block) leaves the execution client past genesis. The failure
// is not rolled back and a second restore on the same disks is refused before any fetch, as docs/single-epoch-archive-restore.md says:
// restart from new empty disks.
func TestArchiveRestoreFailedReplayIsNotResumedOnTheSameDisks(t *testing.T) {
	t.Parallel()
	fx := newRetryRestoreFixture(t, 0, fastRetry(time.Second))
	fx.restore.Adapter = &failingVerify{RestoreExecutor: fx.executor, failAt: 3}
	err := fx.restore.Restore(context.Background())
	require.ErrorIs(t, err, ErrRestore)
	require.EqualValues(t, 2, fx.executor.head.Number, "the first two blocks were imported")
	image, loadErr := fx.journal.LoadJournal(context.Background(), fx.wf.context, fx.limits)
	require.NoError(t, loadErr)
	require.Nil(t, image.Restored, "no restore pin is recorded for a failed replay")

	fx.restore.Adapter = fx.executor
	before := fx.host.calls.Load()
	err = fx.restore.Restore(context.Background())
	require.ErrorIs(t, err, ErrRestore)
	require.ErrorContains(t, err, "EL head must be the checked genesis")
	require.Equal(t, before, fx.host.calls.Load(), "the refusal comes before any fetch")
}

type failingVerify struct {
	RestoreExecutor
	failAt uint64
}

func (f *failingVerify) Verify(ctx context.Context, b shardnode.Block, params shardnode.RoundParams) (shardnode.Status, error) {
	if b.Number == f.failAt {
		return shardnode.StatusInvalid, nil
	}
	return f.RestoreExecutor.Verify(ctx, b, params)
}

// A source that accepts every stream and never answers (it advertises itself as a replica and cannot serve) costs the restore one bounded
// exchange per record, not the restore: the other replica serves it.
func TestArchiveRestoreBypassesAReplicaThatAcceptsAndNeverAnswers(t *testing.T) {
	t.Parallel()
	fx := newRetryRestoreFixture(t, 0, fastRetry(20*time.Second))
	fx.restore.Limits = Limits{Deadline: 100 * time.Millisecond, Pending: 4, PerPeer: 4}
	stalled := fx.restore.Replicas[0]
	host := &sourceHost{EvidenceHost: fx.host}
	host.route = func(_ context.Context, id peer.ID, _ int64) (libp2pnetwork.Stream, error, bool) {
		if id == stalled {
			return silentSourceStream(), nil, true
		}
		return nil, nil, false
	}
	fx.restore.Host = host
	started := time.Now()
	require.NoError(t, fx.restore.Restore(context.Background()))
	require.Positive(t, host.opened(stalled), "the stalled replica was asked")
	require.Less(t, time.Since(started), 15*time.Second)
	require.EqualValues(t, 5, fx.executor.head.Number)
}

// Two stalled replicas end the restore after the bounded wait; the restore does not hang on a source that holds the stream open.
func TestArchiveRestoreEndsWhenBothReplicasAcceptAndNeverAnswer(t *testing.T) {
	t.Parallel()
	const total = 400 * time.Millisecond
	fx := newRetryRestoreFixture(t, 0, fastRetry(total))
	fx.restore.Limits = Limits{Deadline: 100 * time.Millisecond, Pending: 4, PerPeer: 4}
	host := &sourceHost{EvidenceHost: fx.host}
	host.route = func(context.Context, peer.ID, int64) (libp2pnetwork.Stream, error, bool) {
		return silentSourceStream(), nil, true
	}
	fx.restore.Host = host
	started := time.Now()
	err := fx.restore.Restore(context.Background())
	require.ErrorIs(t, err, ErrRestore)
	require.ErrorIs(t, err, archive.ErrUnavailable)
	require.Less(t, time.Since(started), 10*time.Second, "the wait stays bounded")
	requireNothingRetained(t, fx)
}

// A replica that is asked for one block and answers with another block's genuine record (correctly framed, correctly certified) is not
// trusted: the answer does not echo the request, so it is bypassed, and the other replica serves the block.
func TestArchiveRestoreBypassesAReplicaThatAnswersWithAnotherBlocksRecord(t *testing.T) {
	t.Parallel()
	fx := newRetryRestoreFixture(t, 0, fastRetry(20*time.Second))
	hashes := blockHashes(t, fx)
	liar := fx.restore.Replicas[0]
	server, err := NewServer(fx.stores[0], fx.wf.subject, func(context.Context, archive.Request, *archive.Record) error { return nil }, []peer.ID{fx.senderID}, DefaultLimits())
	require.NoError(t, err)
	host := &sourceHost{EvidenceHost: fx.host}
	host.route = func(_ context.Context, id peer.ID, _ int64) (libp2pnetwork.Stream, error, bool) {
		if id == liar {
			return substitutingStream(t, server, fx.wf.subject, hashes[1]), nil, true
		}
		return nil, nil, false
	}
	fx.restore.Host = host
	require.NoError(t, fx.restore.Restore(context.Background()))
	require.Positive(t, host.opened(liar))
	require.EqualValues(t, 5, fx.executor.head.Number)
	// what was replayed is the real chain: the block-5 record came from the honest replica
	rec, err := fx.local.Get(archive.Request{Context: fx.wf.subject, BlockHash: hashes[5]})
	require.NoError(t, err)
	want, err := fx.stores[1].Get(archive.Request{Context: fx.wf.subject, BlockHash: hashes[5]})
	require.NoError(t, err)
	require.Equal(t, want.Header, rec.Header)
}

// Both replicas answer with another block's record: the restore never accepts it, ends with the restore refusal and keeps nothing.
func TestArchiveRestoreRefusesWhenEveryReplicaAnswersWithAnotherBlocksRecord(t *testing.T) {
	t.Parallel()
	fx := newRetryRestoreFixture(t, 0, fastRetry(300*time.Millisecond))
	hashes := blockHashes(t, fx)
	servers := make(map[peer.ID]*Server)
	for i, id := range fx.restore.Replicas {
		server, err := NewServer(fx.stores[i], fx.wf.subject, func(context.Context, archive.Request, *archive.Record) error { return nil }, []peer.ID{fx.senderID}, DefaultLimits())
		require.NoError(t, err)
		servers[id] = server
	}
	host := &sourceHost{EvidenceHost: fx.host}
	host.route = func(_ context.Context, id peer.ID, _ int64) (libp2pnetwork.Stream, error, bool) {
		return substitutingStream(t, servers[id], fx.wf.subject, hashes[1]), nil, true
	}
	fx.restore.Host = host
	err := fx.restore.Restore(context.Background())
	require.ErrorIs(t, err, ErrRestore)
	require.ErrorIs(t, err, ErrReplica, "the final error says the replicas answered something else")
	requireNothingRetained(t, fx)
}
