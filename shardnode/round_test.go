package shardnode_test

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-core/shardnode/executortest"
)

// recordingSubmitter captures every BlockCertificationRequest handed to it,
// standing in for BFTClient so round.go can be tested with no libp2p.
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

func (s *recordingSubmitter) last(t *testing.T) *certification.BlockCertificationRequest {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	require.NotEmpty(t, s.got, "no request submitted")
	return s.got[len(s.got)-1]
}

func newTestRound(t *testing.T, exec shardnode.Executor, sub *recordingSubmitter) (*shardnode.Round, string) {
	t.Helper()
	signer, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	verifier, err := signer.Verifier()
	require.NoError(t, err)
	pk, err := verifier.MarshalPublicKey()
	require.NoError(t, err)
	// A synthetic-but-stable node ID is fine here: round.go only compares it
	// against TechnicalRecord.Leader by string equality, it never decodes it.
	nodeID := "node-" + string(pk[:8])

	r := shardnode.NewRound(nodeID, types.PartitionID(8), types.ShardID{}, exec, shardnode.NewLoopbackDisseminator(), signer, sub, nil)
	return r, nodeID
}

// genesisUC is what a shard node sees before it has ever certified
// anything: nil InputRecord.Hash/PreviousHash, matching bft-core's own
// genesis ShardInfo (rootchain/consensus/storage/sharding.go NewShardInfo).
// RoundNumber/Epoch are 0 on the sync/genesis UC itself; the TechnicalRecord
// passed alongside it carries the round the shard should submit next.
func genesisUC(timestamp uint64) *types.UnicityCertificate {
	return &types.UnicityCertificate{
		Version:     1,
		InputRecord: &types.InputRecord{Version: 1},
		UnicitySeal: &types.UnicitySeal{Version: 1, RootChainRoundNumber: 1, Timestamp: timestamp},
	}
}

func tr(round, epoch uint64, leader string) *certification.TechnicalRecord {
	return &certification.TechnicalRecord{Round: round, Epoch: epoch, Leader: leader, StatHash: []byte{0x01}, FeeHash: []byte{0x01}}
}

type invalidSelfVerification struct {
	*executortest.Fake
	verifyCalls int
}

func (e *invalidSelfVerification) Verify(context.Context, shardnode.Block, shardnode.RoundParams) (shardnode.Status, error) {
	e.verifyCalls++
	return shardnode.StatusInvalid, nil
}

func TestRound_RefusesCertificationWhenSelfVerificationIsInvalid(t *testing.T) {
	exec := &invalidSelfVerification{Fake: executortest.New()}
	sub := &recordingSubmitter{}
	r, nodeID := newTestRound(t, exec, sub)

	err := r.HandleCertificate(context.Background(), genesisUC(1000), tr(1, 0, nodeID))

	require.ErrorContains(t, err, "refusing to submit it for certification")
	require.Equal(t, 1, exec.verifyCalls, "the candidate must be checked before the certification boundary")
	require.Empty(t, sub.got, "a candidate rejected by Ureth must never become a certification request")
}

func TestRound_SingleValidator_GenesisToThreeRounds(t *testing.T) {
	ctx := context.Background()
	exec := executortest.New()
	sub := &recordingSubmitter{}
	r, nodeID := newTestRound(t, exec, sub)

	// Round 1: genesis. PreviousHash is nil (root chain's convention); the
	// executor's own genesis state root is a real, non-nil value, so this
	// is always non-quiet regardless of whether there is anything to do —
	// see round.go's blockHashOrFallback and docs/shard-protocol.md.
	require.NoError(t, r.HandleCertificate(ctx, genesisUC(1000), tr(1, 0, nodeID)))
	req1 := sub.last(t)
	require.Equal(t, uint64(1), req1.InputRecord.RoundNumber)
	require.Empty(t, req1.InputRecord.PreviousHash)
	require.NotEmpty(t, req1.InputRecord.Hash)
	require.NotEmpty(t, req1.InputRecord.BlockHash, "genesis round must never be quiet")
	require.NoError(t, req1.InputRecord.IsValid())

	// Root chain certifies round 1 exactly as submitted.
	uc1 := certifyFrom(req1, 2, 1000)
	require.NoError(t, r.HandleCertificate(ctx, uc1, tr(2, 0, nodeID)))
	req2 := sub.last(t)
	require.Equal(t, uint64(2), req2.InputRecord.RoundNumber)
	require.Equal(t, req1.InputRecord.Hash, req2.InputRecord.PreviousHash)
	// No entries were queued, and we are now past genesis, so round 2 must
	// be quiet: this is the case the genesis special-case must NOT leak into.
	require.Equal(t, req2.InputRecord.PreviousHash, req2.InputRecord.Hash)
	require.Empty(t, req2.InputRecord.BlockHash)

	// Root chain certifies the quiet round 2.
	uc2 := certifyFrom(req2, 3, 1000)
	require.NoError(t, r.HandleCertificate(ctx, uc2, tr(3, 0, nodeID)))
	req3 := sub.last(t)
	require.Equal(t, uint64(3), req3.InputRecord.RoundNumber)
	require.Equal(t, req2.InputRecord.Hash, req3.InputRecord.PreviousHash)
}

func TestRound_RepeatUC_DoesNotCommitButAdvancesRound(t *testing.T) {
	ctx := context.Background()
	exec := executortest.New()
	sub := &recordingSubmitter{}
	r, nodeID := newTestRound(t, exec, sub)

	require.NoError(t, r.HandleCertificate(ctx, genesisUC(1000), tr(1, 0, nodeID)))
	req1 := sub.last(t)
	headBefore, err := exec.Head(ctx)
	require.NoError(t, err)
	require.Empty(t, headBefore.Hash, "round 1's block must not be committed until its UC arrives")

	// Root chain times out waiting (T2) and re-issues a repeat UC: same
	// input record as the (never-sent) prior certificate, later root round,
	// fresh TechnicalRecord for the next attempt at the same round number.
	repeat := &types.UnicityCertificate{
		Version:     1,
		InputRecord: &types.InputRecord{Version: 1}, // still nil hash — round 1 was never certified
		UnicitySeal: &types.UnicitySeal{Version: 1, RootChainRoundNumber: 2, Timestamp: 1000},
	}
	require.NoError(t, r.HandleCertificate(ctx, repeat, tr(1, 0, nodeID)))
	req2 := sub.last(t)
	require.Equal(t, uint64(1), req2.InputRecord.RoundNumber, "repeat UC re-attempts the same round number")
	require.Equal(t, req1.InputRecord.Hash, req2.InputRecord.Hash, "same head, same entries (none) ⇒ identical result")
}

func TestRound_RejectsBuildingOnDivergedState(t *testing.T) {
	ctx := context.Background()
	exec := executortest.New()
	sub := &recordingSubmitter{}
	r, nodeID := newTestRound(t, exec, sub)

	// A certificate claiming a PreviousHash the executor never produced —
	// e.g. this node missed a round entirely.
	diverged := &types.UnicityCertificate{
		Version:     1,
		InputRecord: &types.InputRecord{Version: 1, Hash: []byte{0xDE, 0xAD, 0xBE, 0xEF}},
		UnicitySeal: &types.UnicitySeal{Version: 1, RootChainRoundNumber: 5, Timestamp: 1000},
	}
	err := r.HandleCertificate(ctx, diverged, tr(6, 0, nodeID))
	require.Error(t, err)
	require.Contains(t, err.Error(), "diverges")
}

// certifyFrom builds the next UC as if the root chain accepted req exactly
// as submitted — the honest-majority happy path this test suite exercises.
func certifyFrom(req *certification.BlockCertificationRequest, rootRound, timestamp uint64) *types.UnicityCertificate {
	return &types.UnicityCertificate{
		Version:     1,
		InputRecord: req.InputRecord,
		UnicitySeal: &types.UnicitySeal{Version: 1, RootChainRoundNumber: rootRound, Timestamp: timestamp},
	}
}
