package shardnode

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-go-base/types"
)

/*
Fixtures for the requester coordinator (docs/design/f6b-quiet-tail-anchor-recovery.md §6.3).

Every certificate is genuinely signed and genuinely verified — the coordinator's decisions are only
worth testing against real authentication, because "the predicate is the authority" is the property
under test. What IS stubbed is the network: the fetcher is an injected function, so who was asked, in
what order, and what happened while a fetch was in flight are all decided by the test rather than by
timing.
*/

// --- harness -----------------------------------------------------------------------------------

type stubProviders []peer.ID

func (s stubProviders) EvidenceProviders() []peer.ID { return []peer.ID(s) }

type fetchFunc func(ctx context.Context, p peer.ID, req EvidenceRequest) (AnchorEvidence, error)

type recordingFetcher struct {
	mu    sync.Mutex
	fn    fetchFunc
	asked []peer.ID
	reqs  []EvidenceRequest
}

func (f *recordingFetcher) Fetch(ctx context.Context, p peer.ID, req EvidenceRequest) (AnchorEvidence, error) {
	f.mu.Lock()
	f.asked = append(f.asked, p)
	f.reqs = append(f.reqs, req)
	f.mu.Unlock()
	return f.fn(ctx, p, req)
}

func (f *recordingFetcher) calls() ([]peer.ID, []EvidenceRequest) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]peer.ID(nil), f.asked...), append([]EvidenceRequest(nil), f.reqs...)
}

// testClock is read from the run goroutine and moved from the test goroutine, so it is guarded.
type testClock struct {
	mu sync.Mutex
	at time.Time
}

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = c.at.Add(d)
}

type recoveryFixture struct {
	*evidenceFixture
	req     *EvidenceRequester
	fetcher *recordingFetcher
	clock   *testClock
}

func newRecoveryFixture(t *testing.T, providers []peer.ID, budget RecoveryBudget, fn fetchFunc, opts ...func(*RecoveryConfig)) *recoveryFixture {
	t.Helper()
	f := newEvidenceFixture(t)
	fetcher := &recordingFetcher{fn: fn}
	clock := &testClock{at: time.Unix(1_700_000_000, 0)}
	cfg := RecoveryConfig{
		PartitionID:   evidencePartitionID,
		ShardConfHash: f.conf,
		TrustBases:    f.trust,
		Fetcher:       fetcher,
		Providers:     stubProviders(providers),
		Limits:        DefaultAnchorEvidenceLimits,
		Budget:        budget,
		Now:           clock.now,
	}
	for _, o := range opts {
		o(&cfg)
	}
	r, err := NewEvidenceRequester(cfg)
	require.NoError(t, err)
	t.Cleanup(r.Close)
	return &recoveryFixture{evidenceFixture: f, req: r, fetcher: fetcher, clock: clock}
}

// testBudget is deliberately generous in time and tight in attempts: the fixtures are about which
// decisions are made, and a wall-clock deadline that could fire would make them about scheduling.
func testBudget() RecoveryBudget {
	return RecoveryBudget{
		MaxProviders: 4, Overall: 20 * time.Second, PerAttempt: 0,
		Backoff: 10 * time.Second, MaxRestarts: 2, MaxWitness: 8,
	}
}

func (rf *recoveryFixture) observe(t *testing.T, links ...EvidenceLink) {
	t.Helper()
	for _, l := range links {
		require.NoError(t, rf.req.Observe(l.UC, l.Technical))
	}
}

// settled waits for the recovery to stop running. The ceiling is a test failure rather than a hang:
// a coordinator that never finishes is a defect, and a suite that hangs does not say which one.
func (rf *recoveryFixture) settled(t *testing.T) RecoveryStatus {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		st := rf.req.Status()
		if st.State != RecoveryFetching {
			return st
		}
		if time.Now().After(deadline) {
			t.Fatal("recovery never finished")
		}
		time.Sleep(time.Millisecond)
	}
}

// The measured situation (§1): a block was certified in round 10 and every certified round since has
// been quiet at the state it produced. Rounds are non-consecutive so any `+1` arithmetic fails.
func quietTailChain(f *evidenceFixture) (source, mid, head EvidenceLink) {
	stateA, stateB, blockB := h32(0x0a), h32(0x0b), h32(0xbb)
	return f.cert(10, 100, stateA, stateB, blockB, 12),
		f.cert(12, 110, stateB, stateB, nil, 16),
		f.cert(16, 120, stateB, stateB, nil, 19)
}

func bundleOf(source EvidenceLink, tail ...EvidenceLink) AnchorEvidence {
	return AnchorEvidence{Source: source.UC, SourceTechnical: source.Technical, Tail: tail}
}

func always(ev AnchorEvidence, err error) fetchFunc {
	return func(context.Context, peer.ID, EvidenceRequest) (AnchorEvidence, error) { return ev, err }
}

// --- the ordinary case -------------------------------------------------------------------------

/*
The whole point, end to end: a node holding only quiet certificates ends up with the block hash its
executor is missing, having asked peers and believed none of them.

The first provider fails at the wire, the second serves a complete and correctly signed chain that
stops one round short, and only the third serves evidence the predicate accepts. All three are
consulted, because neither of the first two said anything about the shard's history that another
provider could not contradict.
*/
func TestEvidenceRequester_RecoversFromTheFirstProviderThatCanVerify(t *testing.T) {
	var f *evidenceFixture
	var short, full AnchorEvidence

	rf := newRecoveryFixture(t, []peer.ID{"bad", "stale", "good"}, testBudget(),
		func(_ context.Context, p peer.ID, _ EvidenceRequest) (AnchorEvidence, error) {
			switch p {
			case "bad":
				// A frame the transport refused: nothing arrived, so nothing is known.
				return AnchorEvidence{}, fmt.Errorf("%w: response frame exceeds the bound", ErrEvidenceTransport)
			case "stale":
				return short, nil
			default:
				return full, nil
			}
		})
	f = rf.evidenceFixture
	source, mid, head := quietTailChain(f)
	short = bundleOf(source, mid)      // authentic, and one round short of what this node holds
	full = bundleOf(source, mid, head) // the chain that reaches it

	rf.observe(t, source, mid, head)
	require.NoError(t, rf.req.Need())
	st := rf.settled(t)

	require.Equal(t, RecoveryReady, st.State, "err: %v", st.LastErr)
	asked, reqs := rf.fetcher.calls()
	require.Equal(t, []peer.ID{"bad", "stale", "good"}, asked)
	for _, req := range reqs {
		require.EqualValues(t, 16, req.HeldRound, "every request is pinned to the certificate held")
		require.NotEmpty(t, req.HeldIdentity, "a request naming only a round would be refused (§2.2)")
	}

	anchor, ok := rf.req.Target()
	require.True(t, ok)
	require.Equal(t, Hash(h32(0xbb)), anchor.Anchor.BlockHash)
	require.Equal(t, Hash(h32(0x0b)), anchor.Anchor.StateRoot)
	require.EqualValues(t, 10, anchor.Anchor.Round)
}

// Transport success is not evidence, and the requester must not be steered by a peer that behaves
// perfectly at the wire while serving a chain about something else.
func TestEvidenceRequester_TransportSuccessIsNotEvidence(t *testing.T) {
	var elsewhere AnchorEvidence
	rf := newRecoveryFixture(t, []peer.ID{"p1"}, testBudget(),
		func(context.Context, peer.ID, EvidenceRequest) (AnchorEvidence, error) { return elsewhere, nil })
	_, _, head := quietTailChain(rf.evidenceFixture)

	// A structurally perfect chain, of exactly the shape this node is asking for, signed by a root
	// chain this node does not trust — and delivered without a single wire error.
	other := newEvidenceFixture(t)
	osrc, omid, ohead := quietTailChain(other)
	elsewhere = bundleOf(osrc, omid, ohead)

	rf.observe(t, head)
	require.NoError(t, rf.req.Need())
	st := rf.settled(t)

	require.Equal(t, RecoveryFailed, st.State)
	require.ErrorIs(t, st.LastErr, ErrRecoveryUnavailable)
	require.ErrorIs(t, st.LastErr, ErrEvidenceUnauthenticated)
	_, ok := rf.req.Target()
	require.False(t, ok, "a bundle that verified against nothing installs nothing")
}

// --- availability ------------------------------------------------------------------------------

func TestEvidenceRequester_NothingToAskOrNothingObtained(t *testing.T) {
	t.Run("no provider is a failure to start a recovery, not a failed recovery", func(t *testing.T) {
		rf := newRecoveryFixture(t, nil, testBudget(), always(AnchorEvidence{}, errors.New("never called")))
		_, _, head := quietTailChain(rf.evidenceFixture)
		rf.observe(t, head)
		require.NoError(t, rf.req.Need())
		st := rf.settled(t)
		require.ErrorIs(t, st.LastErr, ErrRecoveryNoProvider)
		asked, _ := rf.fetcher.calls()
		require.Empty(t, asked)
	})

	t.Run("every provider unavailable spends the attempt budget and no more", func(t *testing.T) {
		budget := testBudget()
		budget.MaxProviders = 2
		rf := newRecoveryFixture(t, []peer.ID{"a", "b", "c", "d"}, budget,
			always(AnchorEvidence{}, fmt.Errorf("%w: stream reset", ErrEvidenceTransport)))
		_, _, head := quietTailChain(rf.evidenceFixture)
		rf.observe(t, head)
		require.NoError(t, rf.req.Need())
		st := rf.settled(t)

		require.Equal(t, RecoveryFailed, st.State)
		require.ErrorIs(t, st.LastErr, ErrRecoveryUnavailable)
		asked, _ := rf.fetcher.calls()
		require.Equal(t, []peer.ID{"a", "b"}, asked, "the budget is across providers, not per provider")
	})

	t.Run("nothing observed yet is refused before a request is invented", func(t *testing.T) {
		rf := newRecoveryFixture(t, []peer.ID{"a"}, testBudget(), always(AnchorEvidence{}, nil))
		require.ErrorIs(t, rf.req.Need(), ErrRecoveryNoObservation)
		asked, _ := rf.fetcher.calls()
		require.Empty(t, asked)
	})
}

// A failed recovery must not be retried on the next certificate delivery. A shard certifies a round
// every few seconds; refetching on each one would turn one node's recovery into a load pattern on
// every other node.
func TestEvidenceRequester_BackoffRatherThanRefetchOnEveryDelivery(t *testing.T) {
	rf := newRecoveryFixture(t, []peer.ID{"a"}, testBudget(),
		always(AnchorEvidence{}, fmt.Errorf("%w: stream reset", ErrEvidenceTransport)))
	_, _, head := quietTailChain(rf.evidenceFixture)
	rf.observe(t, head)

	require.NoError(t, rf.req.Need())
	require.Equal(t, RecoveryFailed, rf.settled(t).State)

	for i := 0; i < 5; i++ {
		err := rf.req.Need()
		require.ErrorIs(t, err, ErrRecoveryBackoff, "delivery %d", i)
	}
	asked, _ := rf.fetcher.calls()
	require.Len(t, asked, 1, "the backoff is a refusal to ask, not a quieter way of asking")

	rf.clock.advance(11 * time.Second)
	require.NoError(t, rf.req.Need())
	rf.settled(t)
	asked, _ = rf.fetcher.calls()
	require.Len(t, asked, 2, "and it expires")
}

// --- coalescing and cancellation ---------------------------------------------------------------

func TestEvidenceRequester_DuplicateTriggersDoNotSpawnParallelFetches(t *testing.T) {
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	var full AnchorEvidence

	rf := newRecoveryFixture(t, []peer.ID{"a"}, testBudget(),
		func(ctx context.Context, _ peer.ID, _ EvidenceRequest) (AnchorEvidence, error) {
			select {
			case entered <- struct{}{}:
			default:
			}
			select {
			case <-release:
			case <-ctx.Done():
				return AnchorEvidence{}, ctx.Err()
			case <-time.After(5 * time.Second):
				return AnchorEvidence{}, errors.New("fetch was never released")
			}
			return full, nil
		})
	source, mid, head := quietTailChain(rf.evidenceFixture)
	full = bundleOf(source, mid, head)
	rf.observe(t, source, mid, head)

	require.NoError(t, rf.req.Need())
	<-entered
	// The same certificate delivered again, and again, from as many call sites as a node has.
	for i := 0; i < 10; i++ {
		require.NoError(t, rf.req.Need(), "a duplicate trigger is a no-op, not an error")
	}
	require.Equal(t, RecoveryFetching, rf.req.Status().State)
	close(release)

	st := rf.settled(t)
	require.Equal(t, RecoveryReady, st.State, "err: %v", st.LastErr)
	asked, _ := rf.fetcher.calls()
	require.Len(t, asked, 1, "eleven triggers, one fetch")

	// And once a target is ready for the certificate held, a further trigger asks nobody.
	require.NoError(t, rf.req.Need())
	asked, _ = rf.fetcher.calls()
	require.Len(t, asked, 1)
}

func TestEvidenceRequester_CloseStopsTheFetchAndReleasesIt(t *testing.T) {
	entered := make(chan struct{})
	returned := make(chan struct{})

	rf := newRecoveryFixture(t, []peer.ID{"a"}, testBudget(),
		func(ctx context.Context, _ peer.ID, _ EvidenceRequest) (AnchorEvidence, error) {
			close(entered)
			<-ctx.Done() // cancellation must reach the I/O, not merely be checked around it
			close(returned)
			return AnchorEvidence{}, ctx.Err()
		})
	_, _, head := quietTailChain(rf.evidenceFixture)
	rf.observe(t, head)

	require.NoError(t, rf.req.Need())
	<-entered

	done := make(chan struct{})
	go func() { defer close(done); rf.req.Close() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not return: the fetch was neither cancelled nor waited for")
	}
	<-returned

	require.ErrorIs(t, rf.req.Status().LastErr, context.Canceled)
	require.ErrorIs(t, rf.req.Need(), ErrRecoveryClosed)
}

// --- the held certificate moving under a fetch --------------------------------------------------

// gatedFetch releases one fetch at a time, so a test can decide exactly what this node observes
// while a request is outstanding.
func gatedFetch(entered chan<- struct{}, release <-chan struct{}, reply func() (AnchorEvidence, error)) fetchFunc {
	return func(ctx context.Context, _ peer.ID, _ EvidenceRequest) (AnchorEvidence, error) {
		select {
		case entered <- struct{}{}:
		default:
		}
		select {
		case <-release:
		case <-ctx.Done():
			return AnchorEvidence{}, ctx.Err()
		case <-time.After(5 * time.Second):
			return AnchorEvidence{}, errors.New("fetch was never released")
		}
		return reply()
	}
}

/*
A result verified against the certificate held when the request went out does not authorise the one
held when it came back. The distinction is decided by re-verification over the observed interval, and
never by the state roots matching.
*/
func TestEvidenceRequester_HeldCertificateMovesUnderTheFetch(t *testing.T) {
	stateB, stateC := h32(0x0b), h32(0x0c)
	blockB, blockC, blockE := h32(0xbb), h32(0xcc), h32(0xee)

	t.Run("a quiet round observed meanwhile extends the result", func(t *testing.T) {
		entered, release := make(chan struct{}, 1), make(chan struct{})
		var full AnchorEvidence
		rf := newRecoveryFixture(t, []peer.ID{"a"}, testBudget(),
			gatedFetch(entered, release, func() (AnchorEvidence, error) { return full, nil }))
		f := rf.evidenceFixture
		source, mid, head := quietTailChain(f)
		next := f.cert(19, 130, stateB, stateB, nil, 23) // the round 16 assigned, still quiet
		full = bundleOf(source, mid, head)

		rf.observe(t, source, mid, head)
		require.NoError(t, rf.req.Need())
		<-entered
		rf.observe(t, next)
		close(release)

		st := rf.settled(t)
		require.Equal(t, RecoveryReady, st.State, "err: %v", st.LastErr)
		require.EqualValues(t, 19, st.TargetFor, "the target is verified against the certificate now held")
		anchor, ok := rf.req.Target()
		require.True(t, ok)
		require.Equal(t, Hash(blockB), anchor.Anchor.BlockHash)
		asked, _ := rf.fetcher.calls()
		require.Len(t, asked, 1, "extending what was already obtained needs no second request")
	})

	/*
	   The counterexample the whole design exists for (§3.3.1), reached from the other side: the state
	   root this node holds is the SAME as when it asked, and the last certified block is a different
	   one. Two certified rounds moved the state away and back again while the fetch was outstanding.

	   Accepting the first result because the hashes match would install block bb as the anchor for a
	   state that block ee produced, and P-id gates signing on exactly that hash.
	*/
	t.Run("the same state root reached by a different block does not carry the result", func(t *testing.T) {
		entered, release := make(chan struct{}, 1), make(chan struct{})
		var stale, fresh AnchorEvidence
		var served int
		var mu sync.Mutex
		rf := newRecoveryFixture(t, []peer.ID{"a"}, testBudget(),
			gatedFetch(entered, release, func() (AnchorEvidence, error) {
				mu.Lock()
				defer mu.Unlock()
				served++
				if served == 1 {
					return stale, nil
				}
				return fresh, nil
			}))
		f := rf.evidenceFixture
		source, mid, head := quietTailChain(f)
		away := f.cert(19, 130, stateB, stateC, blockC, 21) // state leaves B
		back := f.cert(21, 140, stateC, stateB, blockE, 23) // and returns to B by ANOTHER block
		quiet := f.cert(23, 150, stateB, stateB, nil, 27)
		stale = bundleOf(source, mid, head)
		fresh = bundleOf(back, quiet)

		rf.observe(t, source, mid, head)
		require.NoError(t, rf.req.Need())
		<-entered
		rf.observe(t, away, back, quiet)
		close(release)

		st := rf.settled(t)
		require.Equal(t, RecoveryReady, st.State, "err: %v", st.LastErr)
		anchor, ok := rf.req.Target()
		require.True(t, ok)
		require.Equal(t, Hash(blockE), anchor.Anchor.BlockHash,
			"the anchor is the block that actually produced the state now held")
		require.NotEqual(t, Hash(blockB), anchor.Anchor.BlockHash)
		require.EqualValues(t, 21, anchor.Anchor.Round)
		require.EqualValues(t, 1, st.Restarts, "the stale result was discarded and the request re-pinned")
		asked, reqs := rf.fetcher.calls()
		require.Len(t, asked, 2)
		require.EqualValues(t, 16, reqs[0].HeldRound)
		require.EqualValues(t, 23, reqs[1].HeldRound, "the second request names the certificate now held")
	})

	t.Run("a repeat observed meanwhile is carried, not read as a gap", func(t *testing.T) {
		entered, release := make(chan struct{}, 1), make(chan struct{})
		var full AnchorEvidence
		rf := newRecoveryFixture(t, []peer.ID{"a"}, testBudget(),
			gatedFetch(entered, release, func() (AnchorEvidence, error) { return full, nil }))
		f := rf.evidenceFixture
		source, mid, head := quietTailChain(f)
		// Round 16 again: same input record, a later root round, and a NEW assignment — the ordinary
		// product of a root-chain timeout. The round it assigns is what the next certificate must be.
		repeat := f.cert(16, 125, stateB, stateB, nil, 21)
		after := f.cert(21, 135, stateB, stateB, nil, 25)
		full = bundleOf(source, mid, head)

		rf.observe(t, source, mid, head)
		require.NoError(t, rf.req.Need())
		<-entered
		rf.observe(t, repeat, after)
		close(release)

		st := rf.settled(t)
		require.Equal(t, RecoveryReady, st.State, "err: %v", st.LastErr)
		require.EqualValues(t, 21, st.TargetFor)
		require.Zero(t, st.Restarts, "the repeat supplied the assignment round 21 follows")
		anchor, ok := rf.req.Target()
		require.True(t, ok)
		require.Equal(t, Hash(blockB), anchor.Anchor.BlockHash)
	})

	t.Run("an interval no longer witnessed is refetched rather than assumed", func(t *testing.T) {
		entered, release := make(chan struct{}, 1), make(chan struct{})
		var stale, fresh AnchorEvidence
		var mu sync.Mutex
		served := 0
		budget := testBudget()
		budget.MaxWitness = 3 // small enough that the snapshot is evicted while the fetch is out
		rf := newRecoveryFixture(t, []peer.ID{"a"}, budget,
			gatedFetch(entered, release, func() (AnchorEvidence, error) {
				mu.Lock()
				defer mu.Unlock()
				served++
				if served == 1 {
					return stale, nil
				}
				return fresh, nil
			}))
		f := rf.evidenceFixture
		source, mid, head := quietTailChain(f)
		r19 := f.cert(19, 130, stateB, stateB, nil, 23)
		r23 := f.cert(23, 140, stateB, stateB, nil, 27)
		r27 := f.cert(27, 150, stateB, stateB, nil, 31)
		stale = bundleOf(source, mid, head)
		fresh = bundleOf(source, mid, head, r19, r23, r27)

		rf.observe(t, source, mid, head)
		require.NoError(t, rf.req.Need())
		<-entered
		rf.observe(t, r19, r23, r27)
		close(release)

		st := rf.settled(t)
		require.Equal(t, RecoveryReady, st.State, "err: %v", st.LastErr)
		require.EqualValues(t, 1, st.Restarts)
		asked, reqs := rf.fetcher.calls()
		require.Len(t, asked, 2, "the interval could not be witnessed, so it was asked for again")
		require.EqualValues(t, 27, reqs[1].HeldRound)
		anchor, ok := rf.req.Target()
		require.True(t, ok)
		require.Equal(t, Hash(blockB), anchor.Anchor.BlockHash)
	})

	/*
	   A shard that certifies blocks faster than a fetch completes would otherwise restart the same
	   recovery forever — a livelock that looks like progress, because every individual step is
	   making a correct decision. The restart budget is what ends it, and the node then waits out
	   the backoff instead.
	*/
	t.Run("a certificate that keeps moving ends the recovery rather than looping", func(t *testing.T) {
		budget := testBudget()
		budget.MaxRestarts = 2
		var f *evidenceFixture
		var rf *recoveryFixture
		var mu sync.Mutex
		certs := map[uint64]EvidenceLink{}
		var prev []byte
		round, tag := uint64(0), byte(0x20)

		rf = newRecoveryFixture(t, []peer.ID{"a"}, budget,
			func(_ context.Context, _ peer.ID, req EvidenceRequest) (AnchorEvidence, error) {
				mu.Lock()
				defer mu.Unlock()
				// Exactly what was asked for: the certificate that named the block, served as its
				// own source. It is a correct answer to a question that is about to go out of date.
				answer := bundleOf(certs[req.HeldRound])
				// ...because the shard certified another block while this one was in flight.
				next := f.cert(round, 200+round, prev, h32(tag), h32(tag+0x40), round+4)
				certs[round] = next
				prev, tag, round = h32(tag), tag+1, round+4
				require.NoError(t, rf.req.Observe(next.UC, next.Technical))
				return answer, nil
			})
		f = rf.evidenceFixture
		source, mid, head := quietTailChain(f)
		rf.observe(t, source, mid, head)
		first := f.cert(19, 130, stateB, h32(tag), h32(tag+0x40), 23)
		certs[19] = first
		prev, tag, round = h32(tag), tag+1, 23
		rf.observe(t, first)

		require.NoError(t, rf.req.Need())
		st := rf.settled(t)
		require.Equal(t, RecoveryFailed, st.State)
		require.ErrorIs(t, st.LastErr, ErrRecoveryStale)
		require.EqualValues(t, budget.MaxRestarts, st.Restarts)
		asked, _ := rf.fetcher.calls()
		require.Len(t, asked, budget.MaxRestarts+1, "one fetch per pass, and the budget ends the passes")
		_, ok := rf.req.Target()
		require.False(t, ok)
	})
}

// One silent provider must not be able to spend the whole recovery's time, and a per-attempt share
// must not be able to extend it either: whichever deadline is sooner is the one that applies.
func TestEvidenceRequester_OneProviderDoesNotSpendTheWholeBudget(t *testing.T) {
	budget := testBudget()
	budget.PerAttempt = 50 * time.Millisecond
	budget.Overall = 20 * time.Second

	var full AnchorEvidence
	rf := newRecoveryFixture(t, []peer.ID{"silent", "good"}, budget,
		func(ctx context.Context, p peer.ID, _ EvidenceRequest) (AnchorEvidence, error) {
			if p == "silent" {
				<-ctx.Done() // never answers, and is not interrupted by anything else
				return AnchorEvidence{}, ctx.Err()
			}
			return full, nil
		})
	source, mid, head := quietTailChain(rf.evidenceFixture)
	full = bundleOf(source, mid, head)
	rf.observe(t, source, mid, head)

	started := time.Now()
	require.NoError(t, rf.req.Need())
	st := rf.settled(t)
	require.Equal(t, RecoveryReady, st.State, "err: %v", st.LastErr)
	require.Less(t, time.Since(started), 10*time.Second, "the silent peer held only its own share")
	asked, _ := rf.fetcher.calls()
	require.Equal(t, []peer.ID{"silent", "good"}, asked)
}

// A target is answered against the certificate actually held, and is retained rather than discarded
// when that certificate moves — the caller applying it may not have finished, and the next trigger
// can usually carry it forward without asking anyone.
func TestEvidenceRequester_TargetIsPinnedToTheCertificateHeld(t *testing.T) {
	stateB := h32(0x0b)
	var full AnchorEvidence
	rf := newRecoveryFixture(t, []peer.ID{"a"}, testBudget(),
		func(context.Context, peer.ID, EvidenceRequest) (AnchorEvidence, error) { return full, nil })
	f := rf.evidenceFixture
	source, mid, head := quietTailChain(f)
	full = bundleOf(source, mid, head)

	rf.observe(t, source, mid, head)
	require.NoError(t, rf.req.Need())
	require.Equal(t, RecoveryReady, rf.settled(t).State)
	_, ok := rf.req.Target()
	require.True(t, ok)

	// A newer certificate arrives and nothing has re-verified against it yet.
	rf.observe(t, f.cert(19, 130, stateB, stateB, nil, 23))
	_, ok = rf.req.Target()
	require.False(t, ok, "an anchor verified for round 16 is not an anchor for round 19")

	// The retained bundle answers it without a second request.
	require.NoError(t, rf.req.Need())
	require.Equal(t, RecoveryReady, rf.settled(t).State)
	anchor, ok := rf.req.Target()
	require.True(t, ok)
	require.Equal(t, Hash(h32(0xbb)), anchor.Anchor.BlockHash)
	asked, _ := rf.fetcher.calls()
	require.Len(t, asked, 1, "carrying a retained result forward is local work")
}

/*
A repeat this node ALREADY holds must not be appended to evidence that already ends at it.

The provider's buffer retains repeats, so a correct answer to a request pinned to a repeated round
ends at the repeat. Extending it with "the repeat, again" produces a tail whose second copy is at the
SAME root round as the first, and repeat normalisation requires a strictly later one (§2.3) — so a
correct answer is refused as a gap, and the retry budget is spent obtaining it again and again.

The cause is that a snapshot cannot be keyed on content: a repeat has the same round and the same
input record as the certificate it repeats. It is keyed on the observation's own version instead, and
the fixture in HeldCertificateMovesUnderTheFetch pins the opposite direction — a repeat observed
AFTER the snapshot, which must be appended, because it carries the assignment the rest follows.
*/
func TestEvidenceRequester_EvidenceThatAlreadyEndsAtTheHeldRepeat(t *testing.T) {
	stateB := h32(0x0b)
	var full AnchorEvidence
	rf := newRecoveryFixture(t, []peer.ID{"a"}, testBudget(),
		func(context.Context, peer.ID, EvidenceRequest) (AnchorEvidence, error) { return full, nil })
	f := rf.evidenceFixture
	source, mid, head := quietTailChain(f)
	// Round 16 again: same input record, a later root round, a new assignment. Both this node and
	// the provider retained it, so the chain the provider serves ends at it.
	repeat := f.cert(16, 125, stateB, stateB, nil, 21)
	full = bundleOf(source, mid, head, repeat)

	rf.observe(t, source, mid, head, repeat)
	require.NoError(t, rf.req.Need())
	st := rf.settled(t)

	require.Equal(t, RecoveryReady, st.State, "err: %v", st.LastErr)
	require.Zero(t, st.Restarts, "the answer was correct; nothing needed re-obtaining")
	asked, _ := rf.fetcher.calls()
	require.Len(t, asked, 1)
	anchor, ok := rf.req.Target()
	require.True(t, ok)
	require.Equal(t, Hash(h32(0xbb)), anchor.Anchor.BlockHash)
}

/*
What a caller is handed is its own. ExecutionAnchor's hashes are byte slices and Contradiction holds
certificate pointers, so returning a struct copy hands out the retained values themselves: a caller
that overwrites a returned hash would be editing this node's verified target, and the next reader
would be told the edited value had been verified.
*/
func TestEvidenceRequester_ReturnedValuesDoNotAliasWhatIsRetained(t *testing.T) {
	t.Run("a returned target", func(t *testing.T) {
		var full AnchorEvidence
		rf := newRecoveryFixture(t, []peer.ID{"a"}, testBudget(),
			func(context.Context, peer.ID, EvidenceRequest) (AnchorEvidence, error) { return full, nil })
		source, mid, head := quietTailChain(rf.evidenceFixture)
		full = bundleOf(source, mid, head)
		rf.observe(t, source, mid, head)
		require.NoError(t, rf.req.Need())
		require.Equal(t, RecoveryReady, rf.settled(t).State)

		anchor, ok := rf.req.Target()
		require.True(t, ok)
		anchor.Anchor.BlockHash[0] ^= 0xff
		anchor.Anchor.StateRoot[0] ^= 0xff
		anchor.Anchor.Round = 999

		again, ok := rf.req.Target()
		require.True(t, ok)
		require.Equal(t, Hash(h32(0xbb)), again.Anchor.BlockHash, "the retained target is what was verified")
		require.Equal(t, Hash(h32(0x0b)), again.Anchor.StateRoot)
		require.EqualValues(t, 10, again.Anchor.Round)
	})

	t.Run("a returned contradiction", func(t *testing.T) {
		stateA, stateC := h32(0x0a), h32(0x0c)
		var conflicting AnchorEvidence
		rf := newRecoveryFixture(t, []peer.ID{"a"}, testBudget(),
			func(context.Context, peer.ID, EvidenceRequest) (AnchorEvidence, error) { return conflicting, nil })
		f := rf.evidenceFixture
		_, _, head := quietTailChain(f)
		other := f.cert(10, 100, stateA, stateC, h32(0xcc), 12)
		conflicting = bundleOf(other, f.cert(12, 110, stateC, stateC, nil, 16), f.cert(16, 120, stateC, stateC, nil, 19))

		rf.observe(t, head)
		require.NoError(t, rf.req.Need())
		require.Equal(t, RecoveryRefused, rf.settled(t).State)

		c, ok := rf.req.Contradiction()
		require.True(t, ok)
		c.Count = 99
		c.HeldRound = 999
		c.Evidence.Source.InputRecord.Hash[0] ^= 0xff
		c.Evidence.Tail = nil

		again, ok := rf.req.Contradiction()
		require.True(t, ok)
		require.Equal(t, 1, again.Count)
		require.EqualValues(t, 16, again.HeldRound)
		require.Equal(t, stateC, []byte(again.Evidence.Source.InputRecord.Hash), "the record of a disagreement cannot be rewritten")
		require.Len(t, again.Evidence.Tail, 2)
	})

	/*
	   The bundle a provider hands over is not this node's memory, and a SUCCESSFUL one was the case
	   left aliasing it: ExecutionAnchor's hashes are slices INTO the certificate the anchor came
	   from, so retaining what arrived left the verified target — and the bundle future extensions
	   are built on — pointing at bytes the provider could still be writing to. Cloning on the way
	   out of Target does not help, because what it clones is already the provider's.
	*/
	t.Run("a successful bundle is owned before it is retained", func(t *testing.T) {
		stateB := h32(0x0b)
		var full AnchorEvidence
		rf := newRecoveryFixture(t, []peer.ID{"a"}, testBudget(),
			func(context.Context, peer.ID, EvidenceRequest) (AnchorEvidence, error) { return full, nil })
		f := rf.evidenceFixture
		source, mid, head := quietTailChain(f)
		full = bundleOf(source, mid, head)
		rf.observe(t, source, mid, head)
		require.NoError(t, rf.req.Need())
		require.Equal(t, RecoveryReady, rf.settled(t).State)

		// The provider's copy changes after it was handed over — a decoder's buffer reused, or a
		// peer that simply keeps writing.
		full.Source.InputRecord.BlockHash[0] ^= 0xff
		full.Source.InputRecord.Hash[0] ^= 0xff
		full.Tail[1].UC.InputRecord.Hash[0] ^= 0xff

		anchor, ok := rf.req.Target()
		require.True(t, ok)
		require.Equal(t, Hash(h32(0xbb)), anchor.Anchor.BlockHash, "the target was verified from memory this node owns")
		require.Equal(t, Hash(h32(0x0b)), anchor.Anchor.StateRoot)

		// And the retained bundle is intact too: a further quiet round is carried forward from it
		// with no second request, which it could not be if its certificates had been rewritten.
		rf.observe(t, f.cert(19, 130, stateB, stateB, nil, 23))
		require.NoError(t, rf.req.Need())
		st := rf.settled(t)
		require.Equal(t, RecoveryReady, st.State, "err: %v", st.LastErr)
		require.EqualValues(t, 19, st.TargetFor)
		again, ok := rf.req.Target()
		require.True(t, ok)
		require.Equal(t, Hash(h32(0xbb)), again.Anchor.BlockHash)
		asked, _ := rf.fetcher.calls()
		require.Len(t, asked, 1)
	})

	t.Run("the recorded bundle does not alias what the provider handed over", func(t *testing.T) {
		stateA, stateC := h32(0x0a), h32(0x0c)
		var conflicting AnchorEvidence
		rf := newRecoveryFixture(t, []peer.ID{"a"}, testBudget(),
			func(context.Context, peer.ID, EvidenceRequest) (AnchorEvidence, error) { return conflicting, nil })
		f := rf.evidenceFixture
		_, _, head := quietTailChain(f)
		other := f.cert(10, 100, stateA, stateC, h32(0xcc), 12)
		conflicting = bundleOf(other, f.cert(12, 110, stateC, stateC, nil, 16), f.cert(16, 120, stateC, stateC, nil, 19))

		rf.observe(t, head)
		require.NoError(t, rf.req.Need())
		require.Equal(t, RecoveryRefused, rf.settled(t).State)

		// The decoder's buffers are not this node's to rely on staying still.
		conflicting.Source.InputRecord.BlockHash[0] ^= 0xff
		c, ok := rf.req.Contradiction()
		require.True(t, ok)
		require.Equal(t, h32(0xcc), []byte(c.Evidence.Source.InputRecord.BlockHash))
	})
}

// --- authenticated disagreement ------------------------------------------------------------------

/*
The one refusal no other provider can repair: an authenticated chain and this node's OWN
authenticated certificate make different statements about round 16. Half the contradiction is ours,
so the attempt ends, the remaining providers are not asked, and the evidence is kept rather than
reduced to a log line.
*/
func TestEvidenceRequester_TerminalConflictEndsTheAttemptAndIsKept(t *testing.T) {
	stateA, stateB, stateC := h32(0x0a), h32(0x0b), h32(0x0c)
	var conflicting AnchorEvidence
	rf := newRecoveryFixture(t, []peer.ID{"a", "b", "c"}, testBudget(),
		func(context.Context, peer.ID, EvidenceRequest) (AnchorEvidence, error) { return conflicting, nil })
	f := rf.evidenceFixture
	_, _, head := quietTailChain(f) // this node holds round 16, quiet at B

	// A different, genuinely signed history: round 10 certified block cc into state C, and round 16
	// is quiet at C. Every certificate authenticates; the two statements about round 16 do not agree.
	other := f.cert(10, 100, stateA, stateC, h32(0xcc), 12)
	omid := f.cert(12, 110, stateC, stateC, nil, 16)
	ohead := f.cert(16, 120, stateC, stateC, nil, 19)
	conflicting = bundleOf(other, omid, ohead)

	rf.observe(t, head)
	require.NoError(t, rf.req.Need())
	st := rf.settled(t)

	require.Equal(t, RecoveryRefused, st.State)
	require.ErrorIs(t, st.LastErr, ErrRecoveryConflict)
	require.ErrorIs(t, st.LastErr, ErrEvidenceConflict)
	asked, _ := rf.fetcher.calls()
	require.Equal(t, []peer.ID{"a"}, asked, "no third party can adjudicate it, so nobody else is asked")

	require.Equal(t, 1, st.Contradictions)
	c, ok := rf.req.Contradiction()
	require.True(t, ok)
	require.Equal(t, peer.ID("a"), c.Provider)
	require.EqualValues(t, 16, c.HeldRound)
	require.NotNil(t, c.Evidence.Source, "the bundle is kept as it arrived")
	require.Len(t, c.Evidence.Tail, 2)

	// Terminal for THAT certificate, and only it.
	require.ErrorIs(t, rf.req.Need(), ErrRecoveryConflict)
	asked, _ = rf.fetcher.calls()
	require.Len(t, asked, 1)

	// A different certificate is a different question and gets its own attempt.
	rf.observe(t, f.cert(19, 130, stateB, stateB, nil, 23))
	require.NoError(t, rf.req.Need())
	rf.settled(t)
	asked, _ = rf.fetcher.calls()
	require.Greater(t, len(asked), 1, "a later certificate does not inherit an earlier refusal")
}

// Equivocation INSIDE a bundle is worth keeping and is not terminal: both halves came from the same
// provider, and neither is a statement this node made.
func TestEvidenceRequester_ASplitInsideOneBundleIsKeptButNotTerminal(t *testing.T) {
	stateB, stateC := h32(0x0b), h32(0x0c)
	var split, full AnchorEvidence
	rf := newRecoveryFixture(t, []peer.ID{"a", "b"}, testBudget(),
		func(_ context.Context, p peer.ID, _ EvidenceRequest) (AnchorEvidence, error) {
			if p == "a" {
				return split, nil
			}
			return full, nil
		})
	f := rf.evidenceFixture
	source, mid, head := quietTailChain(f)
	// Two authenticated certificates for round 12 that do not agree.
	other12 := f.cert(12, 111, stateB, stateC, h32(0xcc), 16)
	split = bundleOf(source, mid, other12, head)
	full = bundleOf(source, mid, head)

	rf.observe(t, source, mid, head)
	require.NoError(t, rf.req.Need())
	st := rf.settled(t)

	require.Equal(t, RecoveryReady, st.State, "err: %v", st.LastErr)
	asked, _ := rf.fetcher.calls()
	require.Equal(t, []peer.ID{"a", "b"}, asked, "the second provider is still consulted")
	require.Equal(t, 1, st.Contradictions)
	c, ok := rf.req.Contradiction()
	require.True(t, ok)
	require.ErrorIs(t, c.Err, ErrEvidenceCandidateSplit)
	require.Equal(t, 1, c.Count)
}

// --- context the node supplies itself -------------------------------------------------------------

/*
Everything a bundle is judged against is the RUNNING NODE's own — the partition it runs, the shard
configuration it was started with, the trust bases in its own store, and the epoch its own source
names. Nothing travelling with the evidence contributes to any of it.

Each of these is a refusal about the CANDIDATE, so each costs one attempt and none of them ends
recovery for good. The epoch crossing is the one worth stating: it says this candidate crosses a
boundary, not that every candidate does, so another provider still gets asked (§4.1).
*/
func TestEvidenceRequester_ConfigurationAndEpochAreThisNodesOwn(t *testing.T) {
	stateA, stateB := h32(0x0a), h32(0x0b)

	t.Run("a chain this node's trust store cannot authenticate", func(t *testing.T) {
		// Covered end to end by TransportSuccessIsNotEvidence; asserted here for the attempt
		// accounting: it is a candidate refusal, so the budget is spent and recovery is retryable.
		var foreign AnchorEvidence
		rf := newRecoveryFixture(t, []peer.ID{"a", "b"}, testBudget(),
			func(context.Context, peer.ID, EvidenceRequest) (AnchorEvidence, error) { return foreign, nil })
		_, _, head := quietTailChain(rf.evidenceFixture)
		other := newEvidenceFixture(t)
		osrc, omid, ohead := quietTailChain(other)
		foreign = bundleOf(osrc, omid, ohead)

		rf.observe(t, head)
		require.NoError(t, rf.req.Need())
		st := rf.settled(t)
		require.Equal(t, RecoveryFailed, st.State)
		require.ErrorIs(t, st.LastErr, ErrEvidenceUnauthenticated)
		asked, _ := rf.fetcher.calls()
		require.Len(t, asked, 2, "an unauthenticated candidate is not a verdict on the shard")
	})

	t.Run("a chain for the shard configuration this node is not running", func(t *testing.T) {
		var bundle AnchorEvidence
		rf := newRecoveryFixture(t, []peer.ID{"a"}, testBudget(),
			func(context.Context, peer.ID, EvidenceRequest) (AnchorEvidence, error) { return bundle, nil },
			func(c *RecoveryConfig) { c.ShardConfHash = h32(0x77) })
		source, mid, head := quietTailChain(rf.evidenceFixture)
		bundle = bundleOf(source, mid, head)

		rf.observe(t, head)
		require.NoError(t, rf.req.Need())
		st := rf.settled(t)
		require.ErrorIs(t, st.LastErr, ErrEvidenceWrongContext)
		require.ErrorIs(t, st.LastErr, ErrRecoveryUnavailable)
	})

	t.Run("a chain for another partition", func(t *testing.T) {
		var bundle AnchorEvidence
		rf := newRecoveryFixture(t, []peer.ID{"a"}, testBudget(),
			func(context.Context, peer.ID, EvidenceRequest) (AnchorEvidence, error) { return bundle, nil },
			func(c *RecoveryConfig) { c.PartitionID = evidencePartitionID + 1 })
		source, mid, head := quietTailChain(rf.evidenceFixture)
		bundle = bundleOf(source, mid, head)

		rf.observe(t, head)
		require.NoError(t, rf.req.Need())
		require.ErrorIs(t, rf.settled(t).LastErr, ErrEvidenceWrongContext)
	})

	t.Run("recovery across an epoch boundary is unsupported, and only for this candidate", func(t *testing.T) {
		var crossing, same AnchorEvidence
		rf := newRecoveryFixture(t, []peer.ID{"old", "current"}, testBudget(),
			func(_ context.Context, p peer.ID, _ EvidenceRequest) (AnchorEvidence, error) {
				if p == "old" {
					return crossing, nil
				}
				return same, nil
			})
		f := rf.evidenceFixture
		// The head this node holds is in shard epoch 1. One provider offers a source from epoch 0 —
		// a genuine chain that this predicate will not follow across the boundary. Another holds a
		// source in the same epoch, and that one recovers.
		old := f.certAtEpoch(10, 100, stateA, stateB, h32(0xbb), 12, 0)
		e1src := f.certAtEpoch(14, 115, stateA, stateB, h32(0xbb), 16, 1)
		head := f.certAtEpoch(16, 120, stateB, stateB, nil, 19, 1)
		crossing = bundleOf(old, head)
		same = bundleOf(e1src, head)

		rf.observe(t, head)
		require.NoError(t, rf.req.Need())
		st := rf.settled(t)
		require.Equal(t, RecoveryReady, st.State, "err: %v", st.LastErr)
		asked, _ := rf.fetcher.calls()
		require.Equal(t, []peer.ID{"old", "current"}, asked,
			"an epoch-crossing candidate is the provider's choice of source, not a fact about the shard")
		anchor, ok := rf.req.Target()
		require.True(t, ok)
		require.EqualValues(t, 14, anchor.Anchor.Round)
	})
}

// The budget is configuration, and a caller that forgets it must fail loudly rather than run
// unbounded — the same stance the predicate takes on its own bounds.
func TestEvidenceRequester_RefusesAnUnusableConfiguration(t *testing.T) {
	base := func() RecoveryConfig {
		f := newEvidenceFixture(t)
		return RecoveryConfig{
			PartitionID: evidencePartitionID, ShardConfHash: f.conf, TrustBases: f.trust,
			Fetcher: &recordingFetcher{}, Providers: stubProviders{"a"},
			Limits: DefaultAnchorEvidenceLimits, Budget: testBudget(),
		}
	}
	for _, tc := range []struct {
		name   string
		break_ func(*RecoveryConfig)
		want   error
	}{
		{"no fetcher", func(c *RecoveryConfig) { c.Fetcher = nil }, ErrRecoveryBudgetInvalid},
		{"no provider source", func(c *RecoveryConfig) { c.Providers = nil }, ErrRecoveryBudgetInvalid},
		{"no trust bases", func(c *RecoveryConfig) { c.TrustBases = nil }, ErrRecoveryBudgetInvalid},
		{"no evidence bounds", func(c *RecoveryConfig) { c.Limits = AnchorEvidenceLimits{} }, ErrEvidenceLimitsInvalid},
		{"no attempt bound", func(c *RecoveryConfig) { c.Budget.MaxProviders = 0 }, ErrRecoveryBudgetInvalid},
		{"no overall deadline", func(c *RecoveryConfig) { c.Budget.Overall = 0 }, ErrRecoveryBudgetInvalid},
		{"no witness bound", func(c *RecoveryConfig) { c.Budget.MaxWitness = 0 }, ErrRecoveryBudgetInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base()
			tc.break_(&cfg)
			_, err := NewEvidenceRequester(cfg)
			require.ErrorIs(t, err, tc.want)
		})
	}
}

// Observation is the one feed, and it must not make a chain of what it witnessed unrepresentable.
func TestEvidenceRequester_ObservationFeed(t *testing.T) {
	stateB := h32(0x0b)

	t.Run("an exact re-delivery is not new information", func(t *testing.T) {
		rf := newRecoveryFixture(t, []peer.ID{"a"}, testBudget(), always(AnchorEvidence{}, nil))
		_, _, head := quietTailChain(rf.evidenceFixture)
		rf.observe(t, head, head, head)
		require.Equal(t, 1, rf.req.Status().Witness)
		require.EqualValues(t, 16, rf.req.Status().HeldRound)
	})

	t.Run("a repeat at a later root round is", func(t *testing.T) {
		rf := newRecoveryFixture(t, []peer.ID{"a"}, testBudget(), always(AnchorEvidence{}, nil))
		f := rf.evidenceFixture
		_, _, head := quietTailChain(f)
		rf.observe(t, head, f.cert(16, 125, stateB, stateB, nil, 21))
		require.Equal(t, 2, rf.req.Status().Witness)
	})

	t.Run("a structurally incomplete observation is refused, and retains nothing", func(t *testing.T) {
		rf := newRecoveryFixture(t, []peer.ID{"a"}, testBudget(), always(AnchorEvidence{}, nil))
		_, _, head := quietTailChain(rf.evidenceFixture)
		require.ErrorIs(t, rf.req.Observe(nil, head.Technical), ErrEvidenceMalformed)
		require.ErrorIs(t, rf.req.Observe(head.UC, nil), ErrEvidenceMalformed)
		require.Zero(t, rf.req.Status().Witness)
	})

	t.Run("the witness does not grow without bound", func(t *testing.T) {
		budget := testBudget()
		budget.MaxWitness = 3
		rf := newRecoveryFixture(t, []peer.ID{"a"}, budget, always(AnchorEvidence{}, nil))
		f := rf.evidenceFixture
		for i := uint64(0); i < 10; i++ {
			rf.observe(t, f.cert(16+i*2, 120+i, stateB, stateB, nil, 18+i*2))
		}
		require.Equal(t, 3, rf.req.Status().Witness)
	})
}

// Copying evidence must not be able to SHORTEN it. A shortened chain is still structurally a chain,
// and §4 is explicit that it is not evidence of anything — so a copy that cannot be completed is a
// refusal rather than a smaller bundle.
func TestEvidenceRequester_CopyingEvidenceCannotShortenIt(t *testing.T) {
	f := newEvidenceFixture(t)
	source, mid, head := quietTailChain(f)

	ok, err := copyEvidence(bundleOf(source, mid, head))
	require.NoError(t, err)
	require.Len(t, ok.Tail, 2)
	require.NotSame(t, source.UC, ok.Source, "the copy shares nothing with what it was made from")

	_, err = copyEvidence(AnchorEvidence{
		Source: source.UC, SourceTechnical: source.Technical,
		Tail: []EvidenceLink{mid, {UC: head.UC}},
	})
	require.ErrorContains(t, err, "tail[1] is structurally incomplete")
}

// The diagnostic accessors are read while a recovery is running — that is what they are for — so
// they must be safe to call then. Taking the record's POINTER under the lock and dereferencing it
// after was a race on every scalar field of it, Count included, because a running recovery
// increments Count under that same lock.
func TestEvidenceRequester_DiagnosticsAreSafeWhileRecovering(t *testing.T) {
	stateA, stateB, stateC := h32(0x0a), h32(0x0b), h32(0x0c)
	budget := testBudget()
	budget.MaxProviders = 8

	var split AnchorEvidence
	rf := newRecoveryFixture(t, []peer.ID{"a", "b", "c", "d", "e", "f", "g", "h"}, budget,
		func(context.Context, peer.ID, EvidenceRequest) (AnchorEvidence, error) {
			time.Sleep(time.Millisecond) // widen the window the reader has to hit
			return split, nil
		})
	f := rf.evidenceFixture
	source, mid, head := quietTailChain(f)
	// Two authenticated certificates for round 12 that disagree: a candidate split, which is
	// retryable — so every provider is asked and every one of them records a disagreement.
	split = bundleOf(source, mid, f.cert(12, 111, stateB, stateC, h32(0xcc), 16), head)
	_ = stateA
	rf.observe(t, source, mid, head)

	require.NoError(t, rf.req.Need())

	stop := make(chan struct{})
	var readers sync.WaitGroup
	for i := 0; i < 4; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_ = rf.req.Status()
				if c, ok := rf.req.Contradiction(); ok {
					require.GreaterOrEqual(t, c.Count, 1)
				}
				_, _ = rf.req.Target()
			}
		}()
	}
	st := rf.settled(t)
	close(stop)
	readers.Wait()

	require.Equal(t, RecoveryFailed, st.State)
	require.Equal(t, 8, st.Contradictions, "every provider disagreed, and every disagreement was counted")
	c, ok := rf.req.Contradiction()
	require.True(t, ok)
	require.Equal(t, 8, c.Count)
	require.ErrorIs(t, c.Err, ErrEvidenceCandidateSplit)
}

/*
The target and the certificate it was verified against travel together, because a consumer that had
to reconstruct the second from the first would be inferring it from a state root — and across a quiet
tail every certificate carries the same one.
*/
func TestEvidenceRequester_TargetCarriesTheCertificateItWasVerifiedAgainst(t *testing.T) {
	stateB := h32(0x0b)
	var full AnchorEvidence
	rf := newRecoveryFixture(t, []peer.ID{"a"}, testBudget(),
		func(context.Context, peer.ID, EvidenceRequest) (AnchorEvidence, error) { return full, nil })
	f := rf.evidenceFixture
	source, mid, head := quietTailChain(f)
	full = bundleOf(source, mid, head)
	rf.observe(t, source, mid, head)

	require.NoError(t, rf.req.Need())
	require.Equal(t, RecoveryReady, rf.settled(t).State)

	vt, ok := rf.req.Target()
	require.True(t, ok)
	want, err := BindingFor(head.UC)
	require.NoError(t, err)
	require.True(t, vt.For.same(want), "the binding names the certificate the anchor was verified against")
	require.Equal(t, []byte(want.State), []byte(vt.For.State))

	// A further quiet round: the anchor is unchanged and the BINDING advances, which is the only
	// thing that distinguishes the two certificates.
	next := f.cert(19, 130, stateB, stateB, nil, 23)
	rf.observe(t, next)
	require.NoError(t, rf.req.Need())
	require.Equal(t, RecoveryReady, rf.settled(t).State)

	after, ok := rf.req.Target()
	require.True(t, ok)
	require.Equal(t, after.Anchor.BlockHash, vt.Anchor.BlockHash, "the same block")
	require.False(t, after.For.same(vt.For), "and a different certificate")
	require.EqualValues(t, 19, after.For.Round)
	require.Equal(t, []byte(vt.For.State), []byte(after.For.State), "at the same state root, which is why state cannot say which")

	// And the binding a caller is handed is its own.
	wantNext, err := BindingFor(next.UC)
	require.NoError(t, err)
	after.For.Identity[0] ^= 0xff
	after.For.State[0] ^= 0xff
	again, ok := rf.req.Target()
	require.True(t, ok)
	require.True(t, again.For.same(wantNext), "editing a returned binding does not edit the retained one")
	require.Equal(t, []byte(wantNext.State), []byte(again.For.State))
}

func TestBindingFor(t *testing.T) {
	f := newEvidenceFixture(t)
	_, _, head := quietTailChain(f)

	b, err := BindingFor(head.UC)
	require.NoError(t, err)
	require.EqualValues(t, 16, b.Round)
	require.EqualValues(t, 120, b.RootRound)
	require.Equal(t, h32(0x0b), []byte(b.State))
	identity, err := head.UC.InputRecord.Bytes()
	require.NoError(t, err)
	require.Equal(t, identity, b.Identity, "identity is the canonical encoding the signatures cover")

	_, err = BindingFor(nil)
	require.ErrorIs(t, err, ErrEvidenceMalformed)
	_, err = BindingFor(&types.UnicityCertificate{})
	require.ErrorIs(t, err, ErrEvidenceMalformed)
}
