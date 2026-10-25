package posreject

import (
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/evmstate"
	"github.com/unicitynetwork/bft-core/rootchain/evmstate/evmstatetest"
)

const fixture = "../evmstate/testdata/publication.json"
const reservedAt = 100_000 // the fixture's reservation progress

// submissions records what the service offered to the other roots.
type submissions struct {
	mu   sync.Mutex
	got  []rctypes.PosControl
	fail error
}

func (s *submissions) submit(_ context.Context, c rctypes.PosControl, witness []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sha256.Sum256(witness) != c.WitnessHash {
		return errors.New("the witness is not the committed one")
	}
	s.got = append(s.got, c)
	return s.fail
}

func (s *submissions) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.got)
}

type clock struct{ now atomic.Int64 }

func (c *clock) Now() time.Time      { return time.Unix(c.now.Load(), 0) }
func (c *clock) add(d time.Duration) { c.now.Add(int64(d / time.Second)) }

// realService is the builder over the real state of the contracts' fixture in a scenario, at a registry progress.
func realService(t *testing.T, scenario string, progress uint64) (*Service, *evmstatetest.Rejectable, *submissions, *clock, *atomic.Int32) {
	t.Helper()
	r := evmstatetest.LoadRejectable(t, fixture, scenario, progress)
	subs := &submissions{}
	clk := &clock{}
	var builds atomic.Int32
	svc, err := New(Config{
		Deployment: storage.PosDeployment{RootNetwork: 7, Deployment: evmassign.Deployment{NetworkWord: r.Pins.NetworkWord, ChainID: [32]byte{31: 9},
			Custody: r.Pins.Custody}, Election: r.Pins.Election},
		Pins: r.Pins, Proofs: func([32]byte) evmstate.ProofSource { return r.Source }, Submit: subs.submit, Now: clk.Now,
		Build: func(ctx context.Context, src evmstate.ProofSource, pins evmstate.Pins, id [32]byte) ([]byte, storage.RejectFacts, error) {
			builds.Add(1)
			return evmstate.BuildRejectWitness(ctx, src, pins, id)
		},
	})
	require.NoError(t, err)
	return svc, r, subs, clk, &builds
}

func contextAt(r *evmstatetest.Rejectable, attempt uint64, blockHash byte) storage.RejectionContext {
	return storage.RejectionContext{Parent: storage.EVMParent{StateRoot: r.StateRoot, BlockHash: [32]byte{blockHash}}, Predecessor: [32]byte{0x77}, Attempt: attempt}
}

func prepare(s *Service, rc storage.RejectionContext) {
	s.Prepare(rc)
	s.Wait()
}

// A non-leader's builder discovers a due result without any operator: lost at once, or old enough. The control it hands out names the
// context's EVM state, root authority and next attempt, its witness proves the result due through the real authority, and it is offered to
// every root once.
func TestADueResultIsDiscoveredAndOfferedWithoutAnOperator(t *testing.T) {
	for _, c := range []struct {
		scenario string
		progress uint64
	}{{"lost", reservedAt}, {"reservedLost", reservedAt}, {"reserved", reservedAt + storage.ResultReservationLifetimeProgress}} {
		svc, r, subs, _, _ := realService(t, c.scenario, c.progress)
		rc := contextAt(r, 3, 0xb1)
		prepare(svc, rc)
		p, ok := svc.Ready(rc)
		require.True(t, ok, c.scenario)
		require.Equal(t, r.ResultID, p.ResultID)
		require.Equal(t, rctypes.OpRejectResult, p.Control.Op)
		require.Equal(t, rc.Parent.BlockHash, p.Control.Reject.EVMBlockHash)
		require.Equal(t, rc.Parent.StateRoot, p.Control.Reject.EVMStateRoot)
		require.Equal(t, rc.Predecessor, p.Control.Reject.PredecessorBodyID)
		require.EqualValues(t, 3, p.Control.Reject.Attempt, "the root's attempt, unlike the election's (%d)", r.ElectionAttempt)
		require.Zero(t, p.Control.OrderingRound, "a submitted control names no ordering position")
		f, err := evmstate.Authority{Pins: r.Pins}.VerifyReject(p.Witness, r.StateRoot, r.ResultID)
		require.NoError(t, err)
		require.True(t, storage.RejectDue(f))
		require.Equal(t, 1, subs.count(), "%s: offered to the other roots", c.scenario)
		_, ok = svc.Ready(contextAt(r, 3, 0xb2))
		require.False(t, ok, "only for exactly the context it was built for")
	}
}

// A result that is not due is not offered, and the context is not looked at again; a newer EVM state is a new context and is looked at.
func TestAResultThatIsNotDueIsNotOfferedAndIsLookedAtAgainOnlyAtANewState(t *testing.T) {
	svc, r, subs, _, builds := realService(t, "reserved", reservedAt+storage.ResultReservationLifetimeProgress-1)
	rc := contextAt(r, 0, 0xb1)
	prepare(svc, rc)
	_, ok := svc.Ready(rc)
	require.False(t, ok)
	require.Zero(t, subs.count())
	prepare(svc, rc)
	require.EqualValues(t, 1, builds.Load(), "the same context is not collected again")
	next := rc
	next.Parent.StateRoot[0] ^= 1 // another certified state: the builder looks again (the proof then fails here: not the world's root)
	prepare(svc, next)
	require.EqualValues(t, 2, builds.Load())
}

// Proofs that are unavailable are no verdict: nothing is cached and the same context is collected again at the next parent.
func TestUnavailableProofsAreRetried(t *testing.T) {
	r := evmstatetest.LoadRejectable(t, fixture, "lost", reservedAt)
	var opens atomic.Int32
	fail := atomic.Bool{}
	fail.Store(true)
	svc, err := New(Config{Pins: r.Pins, Proofs: func([32]byte) evmstate.ProofSource { return r.Source },
		Open: func(ctx context.Context, src evmstate.ProofSource, pins evmstate.Pins) ([32]byte, error) {
			opens.Add(1)
			if fail.Load() {
				return [32]byte{}, errors.New("node unavailable")
			}
			return evmstate.OpenResult(ctx, src, pins)
		}})
	require.NoError(t, err)
	rc := contextAt(r, 0, 0xb1)
	prepare(svc, rc)
	_, ok := svc.Ready(rc)
	require.False(t, ok)
	fail.Store(false)
	prepare(svc, rc)
	_, ok = svc.Ready(rc)
	require.True(t, ok, "collected once the source answers")
	require.EqualValues(t, 2, opens.Load())
}

// A quiet parent certifies no block hash: proofs are fetched at the block that certified the same state root earlier, and the control
// still names the parent's own zero hash. A quiet parent whose root was never seen with a block is not looked at.
func TestAQuietParentIsProvenAtTheBlockThatCertifiedItsRoot(t *testing.T) {
	r := evmstatetest.LoadRejectable(t, fixture, "lost", reservedAt)
	var fetchedAt [][32]byte
	var mu sync.Mutex
	svc, err := New(Config{Pins: r.Pins, Proofs: func(h [32]byte) evmstate.ProofSource {
		mu.Lock()
		fetchedAt = append(fetchedAt, h)
		mu.Unlock()
		return r.Source
	}})
	require.NoError(t, err)
	quiet := contextAt(r, 0, 0)
	prepare(svc, quiet)
	require.Empty(t, fetchedAt, "an unseen root: nothing to fetch at")
	prepare(svc, contextAt(r, 0, 0xb1))
	prepare(svc, quiet)
	p, ok := svc.Ready(quiet)
	require.True(t, ok)
	require.Equal(t, [32]byte{}, p.Control.Reject.EVMBlockHash, "the control names the quiet parent's zero hash")
	require.Equal(t, [][32]byte{{0xb1}, {0xb1}}, fetchedAt, "both fetched at the block that certified the root")
}

// A change of the root's attempt or authority is a new context: the rejection is built again for it. A restart is a new service that
// rediscovers everything from chain state.
func TestAnAttemptOrEpochChangeOrARestartBuildsAgain(t *testing.T) {
	svc, r, _, _, builds := realService(t, "lost", reservedAt)
	rc := contextAt(r, 0, 0xb1)
	prepare(svc, rc)
	later := rc
	later.Attempt = 1
	prepare(svc, later)
	p, ok := svc.Ready(later)
	require.True(t, ok)
	require.EqualValues(t, 1, p.Control.Reject.Attempt)
	epoch := rc
	epoch.Predecessor = [32]byte{0x78}
	prepare(svc, epoch)
	p, ok = svc.Ready(epoch)
	require.True(t, ok)
	require.Equal(t, [32]byte{0x78}, p.Control.Reject.PredecessorBodyID)
	require.EqualValues(t, 3, builds.Load())

	restarted, _, _, _, _ := realService(t, "lost", reservedAt)
	prepare(restarted, rc)
	_, ok = restarted.Ready(rc)
	require.True(t, ok, "nothing persisted, nothing lost")
}

// A submission is offered once per context; a queue entry that may have expired is offered again after Resubmit; a refused submission is
// retried the same way. A resolved result is never offered again, even at a new context.
func TestOffersAreDedupedRepeatedAfterExpiryAndEndWithTheResult(t *testing.T) {
	svc, r, subs, clk, _ := realService(t, "lost", reservedAt)
	subs.fail = errors.New("queue full")
	rc := contextAt(r, 0, 0xb1)
	prepare(svc, rc)
	prepare(svc, rc)
	require.Equal(t, 1, subs.count(), "not offered twice for one context")
	clk.add(Resubmit)
	prepare(svc, rc)
	require.Equal(t, 2, subs.count(), "offered again once the queue entry may have expired")

	svc.Resolved(r.ResultID)
	_, ok := svc.Ready(rc)
	require.False(t, ok)
	require.Empty(t, svc.Pending())
	clk.add(Resubmit)
	prepare(svc, contextAt(r, 0, 0xb2))
	_, ok = svc.Ready(contextAt(r, 0, 0xb2))
	require.False(t, ok, "a resolved result is not offered at a new context either")
	require.Equal(t, 2, subs.count())
}

// The work is bounded: at most MaxInflight collections run at once, and further contexts wait for a later parent.
func TestCollectionsInFlightAreBounded(t *testing.T) {
	r := evmstatetest.LoadRejectable(t, fixture, "lost", reservedAt)
	release := make(chan struct{})
	var running, peak atomic.Int32
	svc, err := New(Config{Pins: r.Pins, Proofs: func([32]byte) evmstate.ProofSource { return r.Source },
		Open: func(ctx context.Context, src evmstate.ProofSource, pins evmstate.Pins) ([32]byte, error) {
			n := running.Add(1)
			for p := peak.Load(); n > p && !peak.CompareAndSwap(p, n); p = peak.Load() {
			}
			<-release
			running.Add(-1)
			return evmstate.OpenResult(ctx, src, pins)
		}})
	require.NoError(t, err)
	for i := byte(1); i <= 5; i++ {
		svc.Prepare(contextAt(r, 0, i))
	}
	close(release)
	svc.Wait()
	require.LessOrEqual(t, peak.Load(), int32(MaxInflight))
}

func TestNewNeedsAProofSourceAndAPinnedElection(t *testing.T) {
	_, err := New(Config{})
	require.Error(t, err)
	_, err = New(Config{Proofs: func([32]byte) evmstate.ProofSource { return nil }})
	require.Error(t, err)
}
