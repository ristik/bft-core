package shardnode

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"

	testpeer "github.com/unicitynetwork/bft-core/internal/testutils/peer"
	"github.com/unicitynetwork/bft-go-base/types"
)

/*
The lifecycle, wired: one node retains what it sees, another node behind a quiet tail asks it, and
the certified block ends up committed in the second node's executor — driven entirely by
Round.HandleCertificate, over real libp2p, with no transaction injected anywhere.

This is the software half of #92's acceptance: the four pieces have each been reviewed alone, and
what a test of any one of them cannot show is whether a node driven only by arriving certificates
ever reaches the executor call. Every defect found by wiring — the one-certificate lag that Refresh
fixes, the double buffer feed, the head not propagating out of the identity check — was invisible to
all four unit suites.
*/

// trackingExecutor is a shard executor whose head this test moves, so "the node recovered" is
// observable as the executor's own state rather than as a return value.
type trackingExecutor struct {
	mu       sync.Mutex
	head     BlockRef
	genesis  BlockRef
	blocks   map[string]BlockRef // block hash -> what committing it makes the head
	commits  []Hash
	status   Status
	err      error
	onCommit func() // called inside Commit, so a test can observe what is held while it runs
}

func newTrackingExecutor(head, genesis BlockRef) *trackingExecutor {
	return &trackingExecutor{head: head, genesis: genesis, blocks: map[string]BlockRef{}, status: StatusValid}
}

func (e *trackingExecutor) Head(context.Context) (BlockRef, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.head, nil
}
func (e *trackingExecutor) GenesisBlock(context.Context) (BlockRef, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.genesis, nil
}
func (e *trackingExecutor) Commit(_ context.Context, hash Hash) (Status, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.commits = append(e.commits, Hash(append([]byte(nil), hash...)))
	if e.onCommit != nil {
		hook := e.onCommit
		e.mu.Unlock()
		hook()
		e.mu.Lock()
	}
	if e.err != nil {
		return StatusSyncing, e.err
	}
	if e.status != StatusValid {
		return e.status, nil
	}
	if ref, ok := e.blocks[string(hash)]; ok {
		e.head = ref
	}
	return StatusValid, nil
}
func (e *trackingExecutor) Build(context.Context, RoundParams) (BuildID, error) {
	return "", errors.New("not a leader in this test")
}
func (e *trackingExecutor) Seal(context.Context, BuildID) (Block, error) {
	return Block{}, errors.New("not used")
}
func (e *trackingExecutor) Verify(context.Context, Block, RoundParams) (Status, error) {
	return StatusValid, nil
}

func (e *trackingExecutor) currentHead() BlockRef {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.head
}

func (e *trackingExecutor) committed() []Hash {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]Hash(nil), e.commits...)
}

// waitRecovered waits for the requester's background fetch to finish. Recovery is bounded background
// work off the round lock by design (§6.3), so a wired test has to wait for it exactly as a running
// node does — by letting certificates keep arriving.
func waitRecovered(t *testing.T, r *EvidenceRequester) RecoveryStatus {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		st := r.Status()
		if st.State != RecoveryFetching {
			return st
		}
		if time.Now().After(deadline) {
			t.Fatal("the recovery fetch never finished")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestRecoveryLifecycle_AQuietTailIsRecoveredOverRealLibp2p(t *testing.T) {
	f := newEvidenceFixture(t)
	stateA, stateB, blockB := h32(0x0a), h32(0x0b), h32(0xbb)

	// The measured situation (§1): block bb was certified in round 10, and every certified round
	// since has been quiet at the state it produced. Rounds are non-consecutive throughout.
	source := f.cert(10, 100, stateA, stateB, blockB, 12)
	mid := f.cert(12, 110, stateB, stateB, nil, 16)
	held := f.cert(16, 120, stateB, stateB, nil, 19)
	next := f.cert(19, 130, stateB, stateB, nil, 23)

	// --- the provider: a node that stayed up, retaining what it observed --------------------------
	providerHost := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	providerExec := &headlessExecutor{err: errors.New("the provider's own round is not under test")}
	provider := NewRound("provider", evidencePartitionID, types.ShardID{}, providerExec, NewLoopbackDisseminator(), nil, nil, nil)
	providerStack, err := NewRecoveryStack(
		RecoveryOptions{Serve: true, Buffer: DefaultEvidenceBufferLimits, Transport: DefaultEvidenceTransportLimits},
		RecoveryDeps{Host: providerHost, Executor: providerExec, PartitionID: evidencePartitionID,
			TrustBases: f.trust, Gate: NewFinalityGate()})
	require.NoError(t, err)
	t.Cleanup(providerStack.Close)
	provider.SetRecovery(providerStack)
	require.NotNil(t, providerStack.Buffer)
	require.NotNil(t, providerStack.Server)
	require.Nil(t, providerStack.Requester, "a serving node takes no dependency on anyone")

	ctx := context.Background()
	for _, l := range []EvidenceLink{source, mid, held, next} {
		// Each round fails at the provider's stub executor; retention happens regardless, which is
		// the ordering §6.2 depends on.
		require.Error(t, provider.HandleCertificate(ctx, l.UC, l.Technical))
	}
	count, from, to := providerStack.Buffer.Retained()
	require.Equal(t, 4, count)
	require.EqualValues(t, 10, from)
	require.EqualValues(t, 19, to)

	// --- the returning node: behind the certified block, and it never saw round 10 ----------------
	requesterHost := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	requesterHost.Network().Peerstore().AddAddrs(providerHost.ID(), providerHost.MultiAddresses(), peerstore.PermanentAddrTTL)

	genesis := BlockRef{Number: 0, Hash: Hash(h32(0x01)), StateRoot: Hash(h32(0x02))}
	behind := BlockRef{Number: 4, Hash: Hash(h32(0xaa)), StateRoot: Hash(stateA)}
	exec := newTrackingExecutor(behind, genesis)
	exec.blocks[string(blockB)] = BlockRef{Number: 5, Hash: Hash(blockB), StateRoot: Hash(stateB)}

	returning := NewRound("returning", evidencePartitionID, types.ShardID{}, exec, NewLoopbackDisseminator(), nil, nil, nil)
	// This node is a follower and no leader disseminates anything in this fixture, so the round it
	// finally reaches ends by abstaining. That is the assertion, not an inconvenience: what is
	// under test is whether the ANCHOR stops being the blocker.
	returning.SetAwaitTimeout(50 * time.Millisecond)
	stack, err := NewRecoveryStack(
		RecoveryOptions{
			Serve: true, Recover: true,
			Providers: EvidenceProviders{providerHost.ID()},
			Buffer:    DefaultEvidenceBufferLimits, Transport: DefaultEvidenceTransportLimits,
			Evidence: DefaultAnchorEvidenceLimits, Budget: DefaultRecoveryBudget, Apply: DefaultApplyBudget,
		},
		RecoveryDeps{Host: requesterHost, Executor: exec, PartitionID: evidencePartitionID,
			TrustBases: f.trust, Gate: NewFinalityGate()})
	require.NoError(t, err)
	t.Cleanup(stack.Close)
	returning.SetRecovery(stack)

	// 1. The first certificate it sees is QUIET, and names no block. It cannot say which block
	//    produced the state it is being asked to build on, so it refuses the round — and asks.
	err = returning.HandleCertificate(ctx, held.UC, held.Technical)
	require.Error(t, err, "a node that cannot name the certified block must not build on it")
	require.ErrorContains(t, err, "no-anchor")
	require.Empty(t, exec.committed(), "nothing was committed on the strength of not knowing")

	st := waitRecovered(t, stack.Requester)
	require.Equal(t, RecoveryReady, st.State, "err: %v", st.LastErr)

	// 2. The next quiet certificate arrives. The retained bundle is carried onto it locally, the
	//    verified block is committed, and the executor is where the root chain says it should be.
	err = returning.HandleCertificate(ctx, next.UC, next.Technical)
	require.Error(t, err, "this fixture has no leader, so the round still ends by abstaining")
	require.ErrorContains(t, err, "awaiting round 23 block from leader",
		"and it got that far: the anchor is no longer what refuses the round")
	require.NotContains(t, err.Error(), "no-anchor")
	require.NotContains(t, err.Error(), "head-identity-mismatch")

	require.Equal(t, []Hash{Hash(blockB)}, exec.committed(),
		"exactly the certified block, and only it")
	require.Equal(t, Hash(blockB), exec.currentHead().Hash)
	require.Equal(t, Hash(stateB), exec.currentHead().StateRoot)

	// And no transaction was injected anywhere: every certificate after round 10 is quiet, which is
	// the whole point — this is recovery from evidence, not from new activity.
	for _, l := range []EvidenceLink{mid, held, next} {
		require.Empty(t, l.UC.InputRecord.BlockHash, "round %d must be quiet", l.UC.InputRecord.RoundNumber)
	}
}

func TestRecoveryStack_RefusesConfigurationsThatCannotDoWhatTheySay(t *testing.T) {
	f := newEvidenceFixture(t)
	host := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	exec := newTrackingExecutor(BlockRef{}, BlockRef{})
	deps := func() RecoveryDeps {
		return RecoveryDeps{Host: host, Executor: exec, PartitionID: evidencePartitionID,
			TrustBases: f.trust, Gate: NewFinalityGate()}
	}

	t.Run("neither half is not an error, it is a node that does not run this", func(t *testing.T) {
		st, err := NewRecoveryStack(RecoveryOptions{}, deps())
		require.NoError(t, err)
		require.Nil(t, st)
		st.Close() // safe on nil, so a caller need not branch
	})

	t.Run("recovery with nobody to ask is refused, not silently idle", func(t *testing.T) {
		opts := DefaultRecoveryOptions()
		opts.Recover = true
		opts.Providers = nil
		_, err := NewRecoveryStack(opts, deps())
		require.ErrorContains(t, err, "no providers to ask")
	})

	t.Run("no host means it can neither serve nor ask", func(t *testing.T) {
		d := deps()
		d.Host = nil
		_, err := NewRecoveryStack(DefaultRecoveryOptions(), d)
		require.ErrorContains(t, err, "no libp2p host")
	})

	t.Run("no finality gate is refused, because recovery commits", func(t *testing.T) {
		d := deps()
		d.Gate = nil
		_, err := NewRecoveryStack(DefaultRecoveryOptions(), d)
		require.ErrorContains(t, err, "no finality gate")
	})

	t.Run("the default serves and does not recover", func(t *testing.T) {
		st, err := NewRecoveryStack(DefaultRecoveryOptions(), deps())
		require.NoError(t, err)
		t.Cleanup(st.Close)
		require.NotNil(t, st.Buffer)
		require.NotNil(t, st.Server)
		require.Nil(t, st.Requester, "recovering is a deliberate switch, not a default")
		require.Nil(t, st.Applier)
	})
}

// A node with no lifecycle wired behaves exactly as it did before any of this existed. This is what
// makes the whole of §6 a deployment decision rather than a protocol change.
func TestRecoveryLifecycle_ANodeWithoutItIsUnchanged(t *testing.T) {
	f := newEvidenceFixture(t)
	stateA, stateB := h32(0x0a), h32(0x0b)
	held := f.cert(16, 120, stateB, stateB, nil, 19)

	genesis := BlockRef{Number: 0, Hash: Hash(h32(0x01)), StateRoot: Hash(h32(0x02))}
	exec := newTrackingExecutor(BlockRef{Number: 4, Hash: Hash(h32(0xaa)), StateRoot: Hash(stateA)}, genesis)
	r := NewRound("plain", evidencePartitionID, types.ShardID{}, exec, NewLoopbackDisseminator(), nil, nil, nil)

	err := r.HandleCertificate(context.Background(), held.UC, held.Technical)
	require.Error(t, err)
	require.ErrorContains(t, err, "no-anchor", "the refusal is the same one, named the same way")
	require.Empty(t, exec.committed())
}

// The stack owns the buffer's feed once it is attached, so the standalone one is not left running
// alongside it. Two feeds would hand the buffer every certificate twice.
func TestRound_SetRecoveryOwnsTheBufferFeed(t *testing.T) {
	f := newEvidenceFixture(t)
	host := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	exec := newTrackingExecutor(BlockRef{}, BlockRef{})
	r := NewRound("n", evidencePartitionID, types.ShardID{}, exec, NewLoopbackDisseminator(), nil, nil, nil)

	standalone := newTestBuffer(t)
	r.SetEvidenceBuffer(standalone)
	require.NotNil(t, r.evidence)

	stack, err := NewRecoveryStack(DefaultRecoveryOptions(), RecoveryDeps{
		Host: host, Executor: exec, PartitionID: evidencePartitionID, TrustBases: f.trust, Gate: NewFinalityGate()})
	require.NoError(t, err)
	t.Cleanup(stack.Close)
	r.SetRecovery(stack)

	require.Nil(t, r.evidence, "the standalone feed is cleared, not left to run alongside the stack's")
	require.NotNil(t, r.recovery.Buffer)
	require.Same(t, stack.Gate, r.finality, "and the round shares the stack's gate")
}
