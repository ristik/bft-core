package shardnode_test

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-core/shardnode/executortest"
)

// paramRecordingExecutor wraps executortest.Fake and records the RoundParams it is
// handed on Build and Verify, so a test can assert what actually crossed the
// executor boundary. It changes no Fake behaviour.
type paramRecordingExecutor struct {
	*executortest.Fake

	mu       sync.Mutex
	builds   []shardnode.RoundParams
	verifies []shardnode.RoundParams
}

func newParamRecordingExecutor() *paramRecordingExecutor {
	return &paramRecordingExecutor{Fake: executortest.New()}
}

func (e *paramRecordingExecutor) Build(ctx context.Context, p shardnode.RoundParams) (shardnode.BuildID, error) {
	e.mu.Lock()
	e.builds = append(e.builds, p)
	e.mu.Unlock()
	return e.Fake.Build(ctx, p)
}

func (e *paramRecordingExecutor) Verify(ctx context.Context, b shardnode.Block, p shardnode.RoundParams) (shardnode.Status, error) {
	e.mu.Lock()
	e.verifies = append(e.verifies, p)
	e.mu.Unlock()
	return e.Fake.Verify(ctx, b, p)
}

func (e *paramRecordingExecutor) lastBuild(t *testing.T) shardnode.RoundParams {
	t.Helper()
	e.mu.Lock()
	defer e.mu.Unlock()
	require.NotEmpty(t, e.builds, "the executor was never asked to Build")
	return e.builds[len(e.builds)-1]
}

func (e *paramRecordingExecutor) lastVerify(t *testing.T) shardnode.RoundParams {
	t.Helper()
	e.mu.Lock()
	defer e.mu.Unlock()
	require.NotEmpty(t, e.verifies, "the executor was never asked to Verify")
	return e.verifies[len(e.verifies)-1]
}

// newRoundWithDisseminator builds a Round with an explicit node ID and a
// caller-supplied disseminator, so a leader and a follower can share one.
func newRoundWithDisseminator(t *testing.T, nodeID string, exec shardnode.Executor, sub *recordingSubmitter, d shardnode.Disseminator) *shardnode.Round {
	t.Helper()
	signer, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	return shardnode.NewRound(nodeID, types.PartitionID(8), types.ShardID{}, exec, d, signer, sub, nil)
}

func TestRoundParamsCarryTheAuthorizingCertificateOnALeaderRound(t *testing.T) {
	ctx := context.Background()
	exec := newParamRecordingExecutor()
	sub := &recordingSubmitter{}
	r, nodeID := newTestRound(t, exec, sub)

	uc := genesisUC(1000)
	tr := tr(1, 0, nodeID)
	require.NoError(t, r.HandleCertificate(ctx, uc, tr))

	params := exec.lastBuild(t)
	require.Same(t, uc, params.AuthorizingCertificate,
		"Build must receive the very certificate HandleCertificate was authorized by")
	require.Same(t, tr, params.AuthorizingTechnicalRecord,
		"Build must receive the very technical record that certificate commits to")
	require.Equal(t, uint64(1), params.Round)
}

func TestRoundParamsCarryTheAuthorizingCertificateOnAFollowerRound(t *testing.T) {
	ctx := context.Background()
	// Leader and follower share one disseminator, so the follower obtains the
	// leader's block the same way a real one does.
	disseminator := shardnode.NewLoopbackDisseminator()
	leaderExec := newParamRecordingExecutor()
	followerExec := newParamRecordingExecutor()
	sub := &recordingSubmitter{}

	leader := newRoundWithDisseminator(t, "leader", leaderExec, sub, disseminator)
	follower := newRoundWithDisseminator(t, "follower", followerExec, sub, disseminator)

	uc := genesisUC(1000)
	tr := tr(1, 0, "leader")
	require.NoError(t, leader.HandleCertificate(ctx, uc, tr))
	require.NoError(t, follower.HandleCertificate(ctx, uc, tr))

	params := followerExec.lastVerify(t)
	require.Same(t, uc, params.AuthorizingCertificate,
		"Verify must receive the certificate the round was authorized by, not one restated from scalars")
	require.Same(t, tr, params.AuthorizingTechnicalRecord)
	require.Equal(t, uint64(1), params.Round)
}

func TestQuietRoundStillProducesAQuietInputRecordAndCarriesTheAuthorization(t *testing.T) {
	ctx := context.Background()
	exec := newParamRecordingExecutor()
	sub := &recordingSubmitter{}
	r, nodeID := newTestRound(t, exec, sub)

	// Round 1: genesis, which is non-quiet by convention.
	require.NoError(t, r.HandleCertificate(ctx, genesisUC(1000), tr(1, 0, nodeID)))
	uc1 := certifyFrom(sub.last(t), 2, 1000)

	// Round 2: nothing was queued, so this round genuinely does not move state.
	tr2 := tr(2, 0, nodeID)
	require.NoError(t, r.HandleCertificate(ctx, uc1, tr2))
	req2 := sub.last(t)
	require.Equal(t, req2.InputRecord.PreviousHash, req2.InputRecord.Hash,
		"a quiet round does not move the certified state")
	require.Empty(t, req2.InputRecord.BlockHash, "a quiet round carries a nil block hash")

	params := exec.lastBuild(t)
	require.Same(t, uc1, params.AuthorizingCertificate)
	require.Same(t, tr2, params.AuthorizingTechnicalRecord)
}
