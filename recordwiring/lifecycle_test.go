package recordwiring_test

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"

	"github.com/unicitynetwork/bft-core/internal/testutils/certifiedchain"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/recordwiring"
	"github.com/unicitynetwork/bft-core/shardnode"
)

/*
TestCertifiedRecordLifecycle composes the units the earlier per-unit tests cannot see together: a
node with the store and the gate, driven through an ordinary certified commit, a restart, a recovery
across a quiet tail, and capture, ending with the gate finding readiness for the child of the
recovered block. It is deliberately a composition rather than a second copy of each unit's fixture.

The vote is asserted at the last stage: once the recovery-applied block is durable and this node can
prove the child's continuity, the leader builds and signs. Before that the same node declines to lead
because the record has not caught up, which is the gate doing its job rather than a failure.
*/

// lifecycleExecutor is a minimal execution client that remembers its head, commits the configured
// block, and answers Build/Seal/Verify so a leader can complete a quiet round.
type lifecycleExecutor struct {
	shardnode.Executor
	mu      sync.Mutex
	head    shardnode.BlockRef
	genesis shardnode.BlockRef
	blocks  map[string]shardnode.BlockRef
	built   int
}

func newLifecycleExecutor(genesis shardnode.BlockRef) *lifecycleExecutor {
	return &lifecycleExecutor{head: genesis, genesis: genesis, blocks: map[string]shardnode.BlockRef{}}
}

func (e *lifecycleExecutor) Head(context.Context) (shardnode.BlockRef, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.head, nil
}

func (e *lifecycleExecutor) GenesisBlock(context.Context) (shardnode.BlockRef, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.genesis, nil
}

func (e *lifecycleExecutor) Commit(_ context.Context, hash shardnode.Hash) (shardnode.Status, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if ref, ok := e.blocks[string(hash)]; ok {
		e.head = ref
	}
	return shardnode.StatusValid, nil
}

func (e *lifecycleExecutor) Build(context.Context, shardnode.RoundParams) (shardnode.BuildID, error) {
	e.mu.Lock()
	e.built++
	e.mu.Unlock()
	return "build", nil
}

func (e *lifecycleExecutor) Seal(context.Context, shardnode.BuildID) (shardnode.Block, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	// A quiet block on top of the current head: this shard has nothing to execute.
	return shardnode.Block{Number: e.head.Number, Hash: e.head.Hash, StateRoot: e.head.StateRoot, ParentHash: e.head.Hash}, nil
}

func (e *lifecycleExecutor) Verify(context.Context, shardnode.Block, shardnode.RoundParams) (shardnode.Status, error) {
	return shardnode.StatusValid, nil
}

func (e *lifecycleExecutor) set(b certifiedchain.Block) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.head = ref(b)
}

func (e *lifecycleExecutor) builtRounds() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.built
}

type recordingSubmitter struct {
	mu  sync.Mutex
	got []*certification.BlockCertificationRequest
}

func (s *recordingSubmitter) Submit(_ context.Context, req *certification.BlockCertificationRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.got = append(s.got, req)
	return nil
}

func (s *recordingSubmitter) rounds() []uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]uint64, 0, len(s.got))
	for _, r := range s.got {
		out = append(out, r.InputRecord.RoundNumber)
	}
	return out
}

type staticFetcher struct{ ev shardnode.AnchorEvidence }

func (f staticFetcher) Fetch(context.Context, peer.ID, shardnode.EvidenceRequest) (shardnode.AnchorEvidence, error) {
	return f.ev, nil
}

type staticProviders []peer.ID

func (p staticProviders) EvidenceProviders() []peer.ID { return []peer.ID(p) }

// waitRecoveryReady lets the requester's background fetch finish, which is bounded work off the
// round lock by design, so a composed test has to wait for it exactly as a running node does.
func waitRecoveryReady(t *testing.T, req *shardnode.EvidenceRequester) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		st := req.Status()
		if st.State != shardnode.RecoveryFetching {
			require.Equal(t, shardnode.RecoveryReady, st.State, "err: %v", st.LastErr)
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("recovery never finished")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestCertifiedRecordLifecycle(t *testing.T) {
	ctx := context.Background()
	c := certifiedchain.New(t, 3, 3)
	d := mustDeployment(t, c)
	path := filepath.Join(t.TempDir(), "certified.db")
	rpc := newWitnessRPC(c)
	gate := shardnode.NewFinalityGate()
	exec := newLifecycleExecutor(ref(c.Blocks[0]))
	for i := 1; i < len(c.Blocks); i++ {
		exec.blocks[string(c.Blocks[i].Hash.Bytes())] = ref(c.Blocks[i])
	}

	// --- ordinary round: a certified commit is captured and published ---------------------------------
	results := make(chan recordwiring.CaptureResult, 64)
	s, err := recordwiring.OpenStore(path, 8)
	require.NoError(t, err)
	capOrdinary, err := recordwiring.NewCapturer(recordwiring.CaptureConfig{
		Deployment: d, Store: s, RPC: rpc, Executor: exec, Finality: gate, AcquireTimeout: 20 * time.Second,
		OnResult: func(r recordwiring.CaptureResult) { results <- r },
	})
	require.NoError(t, err)
	runCtx, stopOrdinary := context.WithCancel(ctx)
	ordinaryDone := make(chan struct{})
	go func() { defer close(ordinaryDone); _ = capOrdinary.Run(runCtx) }()

	exec.set(c.Blocks[1])
	uc1, tr1 := c.Certificate(1)
	capOrdinary.ObserveCommit(shardnode.CertifiedCommit{Certificate: uc1, Technical: tr1, BlockHash: c.Blocks[1].Hash.Bytes()})
	res := <-results
	require.Equal(t, recordwiring.CapturePublished, res.Outcome, "%v", res.Err)
	stopOrdinary()
	<-ordinaryDone
	require.NoError(t, s.Close())

	// --- restart: the store reopens and the durable record is ready for the recorded block -----------
	s, err = recordwiring.OpenStore(path, 8)
	require.NoError(t, err)
	defer func() { require.NoError(t, s.Close()) }()
	reload := recordwiring.Reload(ctx, s, d, exec)
	require.Equal(t, recordwiring.OutcomeDurableReady, reload.Outcome, "%v", reload.Err)
	require.Equal(t, c.Blocks[1].Hash, reload.Record.BlockHash())

	// --- recovery: a returning node behind block 1 recovers block 2 from authenticated evidence ------
	sourceUC, sourceTR := c.Certificate(2)
	childUC, childTR := childAfter(t, c, sourceUC, sourceTR)
	grandchildUC, grandchildTR := childAfter(t, c, childUC, childTR)
	greatUC, greatTR := childAfter(t, c, grandchildUC, grandchildTR)
	bundle := shardnode.AnchorEvidence{Source: sourceUC, SourceTechnical: sourceTR,
		Tail: []shardnode.EvidenceLink{{UC: childUC, Technical: childTR}}}

	sc := d.StoreContext()
	req, err := shardnode.NewEvidenceRequester(shardnode.RecoveryConfig{
		PartitionID: sc.PartitionID, ShardID: sc.ShardID, ShardConfHash: sc.FullShardConfHash,
		TrustBases: sc.TrustBases, Fetcher: staticFetcher{ev: bundle}, Providers: staticProviders{"peer"},
		Limits: shardnode.DefaultAnchorEvidenceLimits, Budget: shardnode.DefaultRecoveryBudget,
	})
	require.NoError(t, err)
	t.Cleanup(req.Close)
	applier, err := shardnode.NewTargetApplier(shardnode.ApplyConfig{
		Executor: exec, Source: req, Budget: shardnode.DefaultApplyBudget, Gate: gate})
	require.NoError(t, err)
	stack := &shardnode.RecoveryStack{Requester: req, Applier: applier, Gate: gate}

	obs, err := recordwiring.NewObservations(recordwiring.DefaultObservationLimits)
	require.NoError(t, err)
	readiness, err := recordwiring.NewReadiness(d, s, exec, obs)
	require.NoError(t, err)

	signer, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	sub := &recordingSubmitter{}
	r := shardnode.NewRound("leader", sc.PartitionID, sc.ShardID, exec, shardnode.NewLoopbackDisseminator(), signer, sub, nil)
	r.SetAwaitTimeout(50 * time.Millisecond)
	r.SetRecovery(stack)
	health := shardnode.NewHealth()
	r.SetHealth(health)
	r.SetChildReadiness(recordwiring.NewChildReadiness(readiness))
	r.SetCertificateObserver(recordwiring.NewCertificateObserver(obs))

	recoveryResults := make(chan recordwiring.CaptureResult, 64)
	capRecovery, err := recordwiring.NewCapturer(recordwiring.CaptureConfig{
		Deployment: d, Store: s, RPC: rpc, Executor: exec, Finality: gate, AcquireTimeout: 20 * time.Second,
		OnResult: func(res recordwiring.CaptureResult) { recoveryResults <- res },
	})
	require.NoError(t, err)
	recoveryCtx, stopRecovery := context.WithCancel(ctx)
	recoveryDone := make(chan struct{})
	go func() { defer close(recoveryDone); _ = capRecovery.Run(recoveryCtx) }()
	defer func() { stopRecovery(); <-recoveryDone }()
	r.SetCommitObserver(capRecovery)

	// The first quiet certificate starts the fetch and refuses the round; nothing is committed.
	require.Error(t, r.HandleCertificate(ctx, childUC, childTR))
	require.Empty(t, sub.rounds(), "a node that cannot name the certified block signs nothing")
	waitRecoveryReady(t, req)

	// The next certificate applies the retained evidence: block 2 is committed and reported, and the
	// capturer is about to publish it. The record has not caught up yet, so this leader correctly
	// declines on readiness rather than building on a parent it cannot yet explain.
	require.NoError(t, r.HandleCertificate(ctx, grandchildUC, grandchildTR))
	select {
	case res := <-recoveryResults:
		require.Equal(t, recordwiring.CapturePublished, res.Outcome, "%v", res.Err)
		require.Equal(t, c.Blocks[2].Hash, res.Attempt.BlockHash)
	case <-time.After(30 * time.Second):
		t.Fatal("the recovery commit was never captured")
	}
	loaded, err := s.Load(ctx, d.StoreContext())
	require.NoError(t, err)
	require.Equal(t, c.Blocks[2].Hash, loaded.BlockHash())
	require.Empty(t, sub.rounds(), "the record had not caught up when the recovered certificate was handled")

	// --- gate: with block 2 durable and observable, the child's child is buildable and signed --------
	require.NoError(t, r.HandleCertificate(ctx, greatUC, greatTR))
	require.Equal(t, []uint64{greatTR.Round}, sub.rounds(),
		"a leader that can prove the recovered block's continuity builds and signs its child")
	require.True(t, health.Snapshot().Voting)
	require.GreaterOrEqual(t, exec.builtRounds(), 1)
}
