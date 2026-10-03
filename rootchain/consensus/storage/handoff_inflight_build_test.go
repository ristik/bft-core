package storage

import (
	"bytes"
	"context"
	"crypto"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/internal/testutils/logger"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-core/shardnode/executortest"
	"github.com/unicitynetwork/bft-go-base/types"
)

// buildGatedExecutor is the Fake executor with the seal held open: Build has returned its BuildID (the engine's payloadId) and
// Seal waits for the test, so a proposal is under construction for exactly as long as the test wants. It records every block it
// sealed.
type buildGatedExecutor struct {
	*executortest.Fake
	started chan shardnode.BuildID
	release chan struct{}
	gated   bool

	mu     sync.Mutex
	sealed []shardnode.Block
}

func (e *buildGatedExecutor) Build(ctx context.Context, p shardnode.RoundParams) (shardnode.BuildID, error) {
	id, err := e.Fake.Build(ctx, p)
	if err == nil && e.gated {
		e.started <- id
	}
	return id, err
}

func (e *buildGatedExecutor) Seal(ctx context.Context, id shardnode.BuildID) (shardnode.Block, error) {
	if e.gated {
		select {
		case <-e.release:
		case <-ctx.Done():
			return shardnode.Block{}, ctx.Err()
		}
	}
	b, err := e.Fake.Seal(ctx, id)
	if err == nil {
		e.mu.Lock()
		e.sealed = append(e.sealed, b)
		e.mu.Unlock()
	}
	return b, err
}

func (e *buildGatedExecutor) sealedBlocks() []shardnode.Block {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]shardnode.Block(nil), e.sealed...)
}

type submissions struct {
	mu  sync.Mutex
	got []*certification.BlockCertificationRequest
}

func (s *submissions) Submit(_ context.Context, req *certification.BlockCertificationRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.got = append(s.got, req)
	return nil
}

func (s *submissions) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.got)
}

func (s *submissions) last() *certification.BlockCertificationRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.got[len(s.got)-1]
}

func certified(req *certification.BlockCertificationRequest, rootRound uint64) *types.UnicityCertificate {
	return &types.UnicityCertificate{Version: 1, InputRecord: req.InputRecord,
		UnicitySeal: &types.UnicitySeal{Version: 1, RootChainRoundNumber: rootRound, Timestamp: 1000}}
}

func shardTR(round, epoch uint64, leader string) *certification.TechnicalRecord {
	return &certification.TechnicalRecord{Round: round, Epoch: epoch, Leader: leader, StatHash: []byte{0x01}, FeeHash: []byte{0x01}}
}

// W3b (#20) and AC1: a membership change that lands while an EVM block is under construction cannot certify that proposal, and
// the successor resumes from the agreed certified parent.
//
// What this exercises, with the real code on each side: the shard node's Round is the leader of round 2 and has started its build
// (Build returned a BuildID; no request exists yet). While that build is open the root orders the coupled handoff's Prepare and
// Freeze and the successor assignment is installed and activated through the real activation path. Only then is the build sealed.
// The Round signs and submits what it built (the shard side holds no cancellation of its own: it does not know the freeze), and
// the ROOT refuses it: ErrHandoffFrozen while frozen. After activation the successor's first block is built on the certified
// parent, never on the abandoned payload.
func TestMembershipChangeDuringPayloadConstructionCannotCertifyTheProposalAndTheSuccessorResumesFromTheAgreedParent(t *testing.T) {
	ctx := context.Background()
	f := newAssignmentFixture(t)
	f.useRealOrchestration(t)
	a := f.addAggregator(t)
	f.changes = nil
	evm := f.oldKeys[0] // ev-a leads, and is kept by the successor set (nextKeys[0])
	exec := &buildGatedExecutor{Fake: executortest.New(), started: make(chan shardnode.BuildID, 1), release: make(chan struct{})}
	subs := &submissions{}
	round := shardnode.NewRound(evm.id, f.shard.PartitionID, types.ShardID{}, exec, shardnode.NewLoopbackDisseminator(), evm.signer, subs, nil)

	// Round 1 is the agreed certified parent P: built, signed, and certified by the (modelled) root.
	genesis := &types.UnicityCertificate{Version: 1, InputRecord: &types.InputRecord{Version: 1},
		UnicitySeal: &types.UnicitySeal{Version: 1, RootChainRoundNumber: 1, Timestamp: 1000}}
	exec.AddEntries([]byte("tx-of-the-certified-parent"))
	require.NoError(t, round.HandleCertificate(ctx, genesis, shardTR(1, 0, evm.id)))
	req1 := subs.last()
	parentHash := bytes.Clone(req1.InputRecord.BlockHash)
	require.NotEmpty(t, parentHash)
	uc1 := certified(req1, 2)
	f.parent = bytes.Clone(parentHash) // the root's certified parent of the shard is P
	f.seedFees(t)

	// Round 2: a paid transaction is queued and the build starts. It stays open.
	exec.gated = true
	exec.AddEntries([]byte("tx-of-the-old-epoch"))
	done := make(chan error, 1)
	go func() { done <- round.HandleCertificate(ctx, uc1, shardTR(2, 0, evm.id)) }()
	buildID := <-exec.started
	require.NotEmpty(t, buildID, "a payload is under construction")
	require.Equal(t, 1, subs.count(), "while the build is open no request exists for round 2")

	var oldRequest *certification.BlockCertificationRequest
	f.afterFreeze = func(t *testing.T) {
		// The membership change is now ordered (Prepare, Freeze) and still the build is open: nothing was signed meanwhile.
		require.Equal(t, 1, subs.count(), "the freeze did not sign or release anything")
		exec.gated = false
		close(exec.release)
		require.NoError(t, <-done)
		require.Equal(t, 2, subs.count(), "the leader signed what it had built")
		oldRequest = subs.last()
		require.EqualValues(t, 2, oldRequest.InputRecord.RoundNumber)
		require.NotEmpty(t, oldRequest.InputRecord.BlockHash)
		require.NotEqual(t, parentHash, []byte(oldRequest.InputRecord.BlockHash))

		// (a) The root refuses it: the EVM shard is frozen, by the real executor of a block carrying exactly this request.
		freezeBlock := mustBlock(t, f.store, 3)
		verifier := mockIRVerifier{verify: func(_ uint64, req *rctypes.IRChangeReq) (*types.InputRecord, error) {
			return req.Requests[0].InputRecord, nil
		}}
		extend := func(reqs ...*rctypes.IRChangeReq) (*ExecutedBlock, error) {
			return freezeBlock.Extend(&rctypes.BlockData{Version: 2, Epoch: 1, Round: 4, Payload: &rctypes.Payload{Version: 2, Requests: reqs}},
				verifier, f.orch, crypto.SHA256, logger.New(t))
		}
		_, err := extend(&rctypes.IRChangeReq{Partition: f.shard.PartitionID, Shard: types.ShardID{}, CertReason: rctypes.Quorum,
			Requests: []*certification.BlockCertificationRequest{oldRequest}})
		require.ErrorIs(t, err, ErrHandoffFrozen, "the old proposal is refused by the root once the handoff froze the shard")

		// (c) Other partitions are unaffected and the root keeps advancing: the aggregator's request is still certified in the
		// same window.
		ext, err := extend(signedRequest(t, a.key, a.oldKey))
		require.NoError(t, err)
		require.Contains(t, ext.ShardState.Changed, a.key)
		require.NotContains(t, ext.ShardState.Changed, f.shard)
		require.Equal(t, parentHash, []byte(ext.ShardState.States[f.shard].IR.BlockHash), "the frozen shard's certified parent did not move")
	}
	h := f.commitAssignment(t)
	require.NotNil(t, oldRequest, "the in-window assertions ran")

	anchor, err := f.store.InstallEpochAnchor(h.head, h.verified, h.genesis)
	require.NoError(t, err)
	s, err := New(crypto.SHA256, f.store.storage, f.orch, logger.New(t), ProfileHandoff)
	require.NoError(t, err)
	activation := addBlockWithRequests(t, s, 7, anchor)
	si := activation.ShardState.States[f.shard]
	require.EqualValues(t, 1, si.TR.Epoch, "the successor set is active")
	require.EqualValues(t, 0, si.IR.Epoch, "its input record stays the old one until the acknowledgement")
	require.Equal(t, parentHash, []byte(si.IR.BlockHash), "the agreed certified parent is still P: the abandoned payload was never certified")

	// (b) The successor (ev-a, retained by the new set) leads the first round of the new epoch from the same certified P.
	exec.AddEntries([]byte("tx-of-the-new-epoch"))
	ucSuccessor := certified(req1, 9)
	require.NoError(t, round.HandleCertificate(ctx, ucSuccessor, shardTR(2, 1, evm.id)))
	sealed := exec.sealedBlocks()
	require.Len(t, sealed, 3, "genesis block, the abandoned old-epoch block, the successor's block")
	abandoned, successor := sealed[1], sealed[2]
	require.Equal(t, parentHash, []byte(sealed[0].Hash))
	require.Equal(t, parentHash, []byte(abandoned.ParentHash))
	require.NotEqual(t, abandoned.Hash, successor.Hash)
	require.Equal(t, parentHash, []byte(successor.ParentHash), "the successor's first block extends the agreed certified parent, not the abandoned payload")
	head, err := exec.Head(ctx)
	require.NoError(t, err)
	require.Equal(t, parentHash, []byte(head.Hash), "the abandoned payload never became canonical")
	newRequest := subs.last()
	require.Equal(t, 3, subs.count())
	require.Equal(t, req1.InputRecord.Hash, newRequest.InputRecord.PreviousHash)
	require.Equal(t, []byte(successor.Hash), []byte(newRequest.InputRecord.BlockHash))
	require.NotEqual(t, oldRequest.InputRecord.BlockHash, newRequest.InputRecord.BlockHash)

	// The new set's quorum (the successor leader and two further members, same request) is certified by the root, and the
	// root's own round advanced past the handoff meanwhile.
	signed := []*certification.BlockCertificationRequest{newRequest}
	for _, k := range f.nextKeys[1:3] {
		r := *newRequest
		r.NodeID = k.id
		require.NoError(t, r.Sign(k.signer))
		signed = append(signed, &r)
	}
	next := addBlockWithRequests(t, s, 8, nil, &rctypes.IRChangeReq{Partition: f.shard.PartitionID, Shard: types.ShardID{},
		CertReason: rctypes.Quorum, Requests: signed})
	require.Contains(t, next.ShardState.Changed, f.shard, "the successor's proposal is certified")
	require.Greater(t, next.GetRound(), activation.GetRound())
}
