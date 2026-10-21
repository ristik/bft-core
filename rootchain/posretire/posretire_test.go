package posretire

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	"github.com/unicitynetwork/bft-core/rootchain/evmstate"
)

type fakeChain struct {
	mu   sync.Mutex
	head uint64
	reqs []Request
	err  error
	from []uint64
}

func (c *fakeChain) Head(context.Context) (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.head, c.err
}

func (c *fakeChain) Requests(_ context.Context, from, to uint64) ([]Request, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.from = append(c.from, from)
	var out []Request
	for _, r := range c.reqs {
		if r.Block >= from && r.Block <= to {
			out = append(out, r)
		}
	}
	return out, c.err
}

func eligible(id, generation uint64) storage.RetirementFacts {
	return storage.RetirementFacts{ID: id, Generation: generation, RefDigest: [32]byte{0xc4}, Requested: true, NotImported: true, NoLiveExposures: true,
		NoLotReferences: true, RecordsCaughtUp: true}
}

type harness struct {
	t      *testing.T
	chain  *fakeChain
	facts  func(id, generation uint64) storage.RetirementFacts
	built  atomic.Int32
	block  chan struct{} // when set, Build waits on it
	fetch  []string
	fetchM sync.Mutex
	path   string
}

func newHarness(t *testing.T) *harness {
	return &harness{t: t, chain: &fakeChain{head: 1000}, path: filepath.Join(t.TempDir(), "pos-retirements.json"),
		facts: func(id, generation uint64) storage.RetirementFacts { return eligible(id, generation) }}
}

func (h *harness) service() *Service {
	svc, err := New(Config{
		Deployment: storage.PosDeployment{RootNetwork: 5}, Chain: h.chain, StatePath: h.path, Log: nil,
		Proofs: func(blockHash [32]byte) evmstate.ProofSource {
			h.fetchM.Lock()
			h.fetch = append(h.fetch, string(blockHash[:2]))
			h.fetchM.Unlock()
			return nil
		},
		Build: func(ctx context.Context, _ evmstate.ProofSource, _ evmstate.Pins, id, generation uint64) ([]byte, storage.RetirementFacts, error) {
			h.built.Add(1)
			if h.block != nil {
				select {
				case <-h.block:
				case <-ctx.Done():
					return nil, storage.RetirementFacts{}, ctx.Err()
				}
			}
			return []byte{byte(id), byte(generation), 0xaa}, h.facts(id, generation), nil
		},
	})
	require.NoError(h.t, err)
	return svc
}

func parentOf(b byte) storage.EVMParent {
	return storage.EVMParent{StateRoot: [32]byte{b, 1}, BlockHash: [32]byte{b, 2}}
}

func waitReady(t *testing.T, svc *Service, p storage.EVMParent, n int) []storage.PreparedRetirement {
	t.Helper()
	var got []storage.PreparedRetirement
	require.Eventually(t, func() bool { got = svc.Ready(p, 100); return len(got) >= n }, 2*time.Second, 5*time.Millisecond)
	return got
}

func TestDiscoveryFindsConfirmedRequestsAndKeepsAKeyedSetAcrossRestarts(t *testing.T) {
	h := newHarness(t)
	h.chain.reqs = []Request{{Key{ID: 3, Generation: 2}, 500}, {Key{ID: 1, Generation: 1}, 400}, {Key{ID: 3, Generation: 3}, 995}}
	svc := h.service()
	require.NoError(t, svc.Poll(context.Background()))
	// block 995 is within Confirmations of the head: not yet
	require.Equal(t, []Key{{ID: 1, Generation: 1}, {ID: 3, Generation: 2}}, svc.Pending(), "ascending by block, then key")
	// the same request again (and a repeat scan) changes nothing
	require.NoError(t, svc.Poll(context.Background()))
	require.Len(t, svc.Pending(), 2)
	h.chain.mu.Lock()
	h.chain.head = 1100
	h.chain.mu.Unlock()
	require.NoError(t, svc.Poll(context.Background()))
	require.Equal(t, []Key{{ID: 1, Generation: 1}, {ID: 3, Generation: 2}, {ID: 3, Generation: 3}}, svc.Pending(), "the work is keyed by (id, generation)")

	// restart: the pending set and the cursor come back from the file; the scan resumes after the cursor, not from zero
	svc.Flush()
	again := h.service()
	require.Equal(t, svc.Pending(), again.Pending())
	h.chain.mu.Lock()
	h.chain.from = nil
	h.chain.head = 1200
	h.chain.mu.Unlock()
	require.NoError(t, again.Poll(context.Background()))
	require.Equal(t, []uint64{1093}, h.chain.from, "resumes after the cursor (head 1100 - 8 confirmations = 1092)")
}

func TestAnUnreadableStateFileIsAnErrorNotAnEmptySet(t *testing.T) {
	h := newHarness(t)
	svc := h.service()
	require.True(t, svc.Add(Key{ID: 1, Generation: 1}))
	svc.Flush()
	require.NoError(t, writeFileAtomic(h.path, []byte("{not json")))
	_, err := New(Config{Chain: h.chain, Proofs: func([32]byte) evmstate.ProofSource { return nil }, StatePath: h.path})
	require.Error(t, err)
}

func TestAFailingChainIsRetriedAndLosesNothing(t *testing.T) {
	h := newHarness(t)
	h.chain.reqs = []Request{{Key{ID: 1, Generation: 1}, 100}}
	h.chain.err = errors.New("rpc down")
	svc := h.service()
	require.Error(t, svc.Poll(context.Background()))
	require.Empty(t, svc.Pending())
	h.chain.mu.Lock()
	h.chain.err = nil
	h.chain.mu.Unlock()
	require.NoError(t, svc.Poll(context.Background()))
	require.Len(t, svc.Pending(), 1)
}

func TestAReadyRetirementIsForExactlyItsParent(t *testing.T) {
	h := newHarness(t)
	svc := h.service()
	svc.Add(Key{ID: 3, Generation: 2})
	p := parentOf(1)
	svc.Prepare(p)
	got := waitReady(t, svc, p, 1)
	require.Len(t, got, 1)
	c := got[0].Control
	require.EqualValues(t, 2, c.Op)
	require.Equal(t, p.StateRoot, c.Retire.EVMStateRoot)
	require.Equal(t, p.BlockHash, c.Retire.EVMBlockHash)
	require.Equal(t, sha256.Sum256(got[0].Witness), c.WitnessHash)
	require.Zero(t, c.OrderingRound, "the leader stamps the position")
	require.NoError(t, c.Validate())
	// the ABI words of the record payload: id, generation, custody's exposure chain verbatim
	require.EqualValues(t, 3, c.Data[31])
	require.EqualValues(t, 2, c.Data[63])
	require.Equal(t, byte(0xc4), c.Data[64])

	// another parent (the view moved on): nothing is ready for it, and the old proof is not offered for it
	require.Empty(t, svc.Ready(parentOf(2), 10))
	other := p
	other.StateRoot[0] ^= 1
	require.Empty(t, svc.Ready(other, 10), "a different root")
	other = p
	other.BlockHash[0] ^= 1
	require.Empty(t, svc.Ready(other, 10), "a different block hash")
	// a later parent is proved on its own
	svc.Prepare(parentOf(2))
	require.Len(t, waitReady(t, svc, parentOf(2), 1), 1)
}

func TestTheEligibilityOfARequestAtTheParentDecidesWhatHappensToIt(t *testing.T) {
	for name, c := range map[string]struct {
		mut      func(f *storage.RetirementFacts)
		stays    bool
		prepared bool
	}{
		"eligible":                {func(*storage.RetirementFacts) {}, true, true},
		"a live exposure":         {func(f *storage.RetirementFacts) { f.NoLiveExposures = false }, true, false},
		"a lot reference":         {func(f *storage.RetirementFacts) { f.NoLotReferences = false }, true, false},
		"records not caught up":   {func(f *storage.RetirementFacts) { f.RecordsCaughtUp = false }, true, false},
		"not requested at P yet":  {func(f *storage.RetirementFacts) { f.Requested = false }, true, false},
		"retired in the registry": {func(f *storage.RetirementFacts) { f.NotImported = false }, false, false},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			h.facts = func(id, generation uint64) storage.RetirementFacts {
				f := eligible(id, generation)
				c.mut(&f)
				return f
			}
			svc := h.service()
			svc.Add(Key{ID: 1, Generation: 1})
			svc.Prepare(parentOf(1))
			require.Eventually(t, func() bool { return h.built.Load() == 1 }, 2*time.Second, 5*time.Millisecond)
			if c.prepared {
				require.Len(t, waitReady(t, svc, parentOf(1), 1), 1)
			}
			time.Sleep(50 * time.Millisecond)
			require.Equal(t, c.prepared, len(svc.Ready(parentOf(1), 10)) == 1)
			require.Equal(t, c.stays, len(svc.Pending()) == 1, "an ineligible request stays pending for a later parent; a retired one is complete")
		})
	}
}

// The certified parent can lag the log for any number of rounds (a stalled EVM certification keeps the same old root): the request stays
// pending, and becomes ready for the first parent that includes it.
func TestARequestNotYetRequestedAtTheCertifiedStatesStaysPendingHoweverLongItLags(t *testing.T) {
	h := newHarness(t)
	var visible atomic.Bool
	h.facts = func(id, generation uint64) storage.RetirementFacts {
		f := eligible(id, generation)
		f.Requested = visible.Load()
		return f
	}
	svc := h.service()
	svc.Add(Key{ID: 1, Generation: 1})
	for i := 0; i < 300; i++ {
		before := h.built.Load()
		svc.Prepare(storage.EVMParent{StateRoot: [32]byte{1, byte(i), byte(i >> 8)}, BlockHash: [32]byte{2, byte(i), byte(i >> 8)}})
		require.Eventually(t, func() bool { return h.built.Load() == before+1 }, 2*time.Second, time.Millisecond)
		require.Eventually(t, func() bool { svc.mu.Lock(); defer svc.mu.Unlock(); return len(svc.inflight) == 0 }, 2*time.Second, time.Millisecond)
	}
	require.Equal(t, []Key{{ID: 1, Generation: 1}}, svc.Pending(), "300 parents that predate the request did not end it")
	svc.Flush()
	require.Equal(t, []Key{{ID: 1, Generation: 1}}, h.service().Pending(), "nor on disk")

	visible.Store(true)
	p := parentOf(9)
	svc.Prepare(p)
	require.Len(t, waitReady(t, svc, p, 1), 1, "the first parent that includes the request")
}

// The same parent is not proved again for a request it cannot retire.
func TestAnOutcomeIsRememberedPerParentAndRequest(t *testing.T) {
	h := newHarness(t)
	h.facts = func(id, generation uint64) storage.RetirementFacts {
		f := eligible(id, generation)
		f.NoLiveExposures = false
		return f
	}
	svc := h.service()
	svc.Add(Key{ID: 1, Generation: 1})
	svc.Add(Key{ID: 2, Generation: 1})
	p := parentOf(1)
	svc.Prepare(p)
	require.Eventually(t, func() bool { return h.built.Load() == 2 }, 2*time.Second, time.Millisecond)
	require.Eventually(t, func() bool { svc.mu.Lock(); defer svc.mu.Unlock(); return len(svc.inflight) == 0 }, 2*time.Second, time.Millisecond)
	for i := 0; i < 5; i++ {
		svc.Prepare(p)
	}
	time.Sleep(30 * time.Millisecond)
	require.EqualValues(t, 2, h.built.Load(), "nothing was collected again for the same parent")
	svc.Prepare(parentOf(2))
	require.Eventually(t, func() bool { return h.built.Load() == 4 }, 2*time.Second, time.Millisecond)
	require.Len(t, svc.Pending(), 2)
}

// Persisting never waits for the disk: a write that blocks does not hold the lock the consensus loop takes in Ordered.
func TestOrderedDoesNotWaitForTheDisk(t *testing.T) {
	h := newHarness(t)
	svc := h.service()
	svc.Add(Key{ID: 1, Generation: 1})
	svc.Flush()
	// the state file's directory is gone: every write fails, none may block or panic
	require.NoError(t, os.RemoveAll(filepath.Dir(h.path)))
	start := time.Now()
	for i := uint64(2); i < 200; i++ {
		svc.Add(Key{ID: i, Generation: 1})
		svc.Ordered(i, 1)
	}
	require.Less(t, time.Since(start), time.Second)
	svc.Flush()
	require.Len(t, svc.Pending(), 1, "the in-memory state is right whatever the disk says")
}

func TestOrderedEndsTheRequestAndItIsNotRediscovered(t *testing.T) {
	h := newHarness(t)
	h.chain.reqs = []Request{{Key{ID: 3, Generation: 2}, 100}}
	svc := h.service()
	require.NoError(t, svc.Poll(context.Background()))
	svc.Prepare(parentOf(1))
	waitReady(t, svc, parentOf(1), 1)

	svc.Ordered(3, 2)
	require.Empty(t, svc.Pending())
	require.Empty(t, svc.Ready(parentOf(1), 10), "nothing more to propose for it")
	// a scan of the same range (a restart that lost the cursor, a re-org) does not bring it back
	svc.mu.Lock()
	svc.cursor = 0
	svc.mu.Unlock()
	require.NoError(t, svc.Poll(context.Background()))
	require.Empty(t, svc.Pending())
	svc.Flush()
	require.Empty(t, h.service().Pending(), "and the restart sees it ended")
}

// Collecting a proof never blocks the caller (the consensus loop), is bounded, and a slow or missing node costs a proposal nothing but
// the Retirement.
func TestAProofThatIsSlowOrMissingNeverBlocksTheCaller(t *testing.T) {
	h := newHarness(t)
	h.block = make(chan struct{})
	svc := h.service()
	for i := uint64(1); i <= 20; i++ {
		svc.Add(Key{ID: i, Generation: 1})
	}
	start := time.Now()
	svc.Prepare(parentOf(1))
	svc.Prepare(parentOf(2))
	svc.Prepare(parentOf(3))
	require.Less(t, time.Since(start), 500*time.Millisecond, "Prepare returns at once")
	require.Empty(t, svc.Ready(parentOf(1), 10), "not ready: nothing to propose")
	require.Eventually(t, func() bool { return h.built.Load() >= 1 }, 2*time.Second, time.Millisecond)
	time.Sleep(50 * time.Millisecond)
	require.LessOrEqual(t, int(h.built.Load()), MaxInflight, "at most MaxInflight proofs are collected at once, whatever is pending")
	close(h.block)
	require.Eventually(t, func() bool { return len(svc.Ready(parentOf(1), 100)) > 0 }, 2*time.Second, 5*time.Millisecond)
	require.LessOrEqual(t, len(svc.Ready(parentOf(1), 100)), MaxPerPrepare)
}

func TestARootsFailingNodeLeavesTheRequestPendingForALaterParent(t *testing.T) {
	h := newHarness(t)
	var fail atomic.Bool
	fail.Store(true)
	svc, err := New(Config{Chain: h.chain, StatePath: h.path, Proofs: func([32]byte) evmstate.ProofSource { return nil },
		Build: func(context.Context, evmstate.ProofSource, evmstate.Pins, uint64, uint64) ([]byte, storage.RetirementFacts, error) {
			if fail.Load() {
				return nil, storage.RetirementFacts{}, errors.New("node unavailable")
			}
			return []byte{1}, eligible(1, 1), nil
		}})
	require.NoError(t, err)
	svc.Add(Key{ID: 1, Generation: 1})
	svc.Prepare(parentOf(1))
	time.Sleep(50 * time.Millisecond)
	require.Empty(t, svc.Ready(parentOf(1), 10))
	require.Len(t, svc.Pending(), 1)
	fail.Store(false)
	svc.Prepare(parentOf(2))
	require.Len(t, waitReady(t, svc, parentOf(2), 1), 1)
}

// A quiet parent certified no block: the control names the zero block hash, the proof is fetched at the block that certified the same root.
func TestAQuietParentIsProvedAtTheBlockThatCertifiedItsRoot(t *testing.T) {
	h := newHarness(t)
	svc := h.service()
	svc.Add(Key{ID: 1, Generation: 1})
	quiet := storage.EVMParent{StateRoot: parentOf(1).StateRoot}
	svc.Prepare(quiet)
	time.Sleep(30 * time.Millisecond)
	require.Zero(t, h.built.Load(), "the root was never seen with a block: nothing to fetch at")

	svc.Prepare(parentOf(1)) // the block that certified it
	waitReady(t, svc, parentOf(1), 1)
	svc.Prepare(quiet)
	got := waitReady(t, svc, quiet, 1)
	require.Equal(t, [32]byte{}, got[0].Control.Retire.EVMBlockHash, "the control names what the root certified: no block")
	require.Equal(t, quiet.StateRoot, got[0].Control.Retire.EVMStateRoot)
	h.fetchM.Lock()
	defer h.fetchM.Unlock()
	bh := parentOf(1).BlockHash
	require.Equal(t, []string{string(bh[:2]), string(bh[:2])}, h.fetch, "both proofs are fetched at the certifying block")
}

// When more are ready than fit, successive proposals serve different requests: one cannot starve the others.
func TestReadyRotatesAmongRequests(t *testing.T) {
	h := newHarness(t)
	svc := h.service()
	for i := uint64(1); i <= 4; i++ {
		svc.Add(Key{ID: i, Generation: 1})
	}
	p := parentOf(1)
	svc.Prepare(p)
	waitReady(t, svc, p, 4)
	var order []uint64
	for i := 0; i < 8; i++ {
		got := svc.Ready(p, 1)
		require.Len(t, got, 1)
		order = append(order, got[0].ID)
	}
	require.Equal(t, []uint64{1, 2, 3, 4, 1, 2, 3, 4}, order)
	all := svc.Ready(p, 10)
	for i := 1; i < len(all); i++ {
		require.Less(t, all[i-1].ID, all[i].ID, "ascending by (id, generation), the order a payload accepts")
	}
}

// Two roots (a leader rotation) discover the same requests from the same log, each with its own file.
func TestEveryRootDiscoversTheSameRequests(t *testing.T) {
	a, b := newHarness(t), newHarness(t)
	reqs := []Request{{Key{ID: 3, Generation: 2}, 100}, {Key{ID: 1, Generation: 1}, 90}}
	a.chain.reqs, b.chain.reqs = reqs, reqs
	sa, sb := a.service(), b.service()
	require.NoError(t, sa.Poll(context.Background()))
	require.NoError(t, sb.Poll(context.Background()))
	require.Equal(t, sa.Pending(), sb.Pending())
}
