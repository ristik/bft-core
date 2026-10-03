package shardnode_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-core/shardnode/executortest"
)

// commitGuardFixture leaves a leader with round 1 certified and committed (head P) and its round-2 proposal A pending, then
// returns A's request and a second valid child B of the same parent P that the executor holds but the round never proposed.
func commitGuardFixture(t *testing.T) (round *shardnode.Round, exec *recordingExecutor, a shardnode.Hash, b shardnode.Block, rootRound uint64, nodeID string, sub *recordingSubmitter, fake *executortest.Fake) {
	t.Helper()
	ctx := context.Background()
	fake = executortest.New()
	exec = &recordingExecutor{Executor: fake}
	sub = &recordingSubmitter{}
	round, nodeID = newTestRound(t, exec, sub)

	fake.AddEntries([]byte("the certified parent"))
	require.NoError(t, round.HandleCertificate(ctx, genesisUC(1000), tr(1, 0, nodeID)))
	fake.AddEntries([]byte("the proposal for round 2"))
	require.NoError(t, round.HandleCertificate(ctx, certifyFrom(sub.last(t), 2, 1000), tr(2, 0, nodeID)))
	a = shardnode.Hash(sub.last(t).InputRecord.BlockHash)
	require.NotEmpty(t, a)

	// B: a different valid child of the same parent P, known to the executor (verified, so committable by hash).
	head, err := fake.Head(ctx)
	require.NoError(t, err)
	fake.AddEntries([]byte("a different block of the same parent"))
	id, err := fake.Build(ctx, shardnode.RoundParams{Round: 2, Parent: head})
	require.NoError(t, err)
	blk, err := fake.Seal(ctx, id)
	require.NoError(t, err)
	status, err := fake.Verify(ctx, blk, shardnode.RoundParams{})
	require.NoError(t, err)
	require.Equal(t, shardnode.StatusValid, status)
	require.NotEqual(t, []byte(a), []byte(blk.Hash))
	return round, exec, a, blk, 3, nodeID, sub, fake
}

// TestRound_CommitPreviousGuards_EachFailsAlone isolates the two guards of commitPrevious. Neither is made redundant by the
// other: each case is built so that the guard under test is the ONLY thing standing between the pending proposal (or a
// certificate's other block) and a commit. Disabling only that guard makes the named subtest fail.
func TestRound_CommitPreviousGuards_EachFailsAlone(t *testing.T) {
	t.Run("round guard: a replayed earlier certificate commits nothing and leaves the proposal pending", func(t *testing.T) {
		// A repeat of round 1's certificate is not about the round-2 proposal A. The round check must leave A pending: the
		// genuine round-2 certificate that follows then commits A. (The target rule alone cannot do this: with the round check
		// gone the replay consumes A, commits the replay's block, and the real certificate finds nothing pending.)
		ctx := context.Background()
		round, exec, a, _, rootRound, nodeID, sub, _ := commitGuardFixture(t)

		before := len(exec.commitTargets())
		replay := certifyFrom(sub.got[0], rootRound, 1000)
		_ = round.HandleCertificate(ctx, replay, tr(3, 0, nodeID))
		require.Equal(t, before, len(exec.commitTargets()), "a certificate for round 1 certifies nothing about the round-2 proposal")

		genuine := certifyFrom(sub.got[1], rootRound+1, 1000)
		require.Equal(t, []byte(a), []byte(genuine.InputRecord.BlockHash))
		require.NoError(t, round.HandleCertificate(ctx, genuine, tr(3, 0, nodeID)))
		targets := exec.commitTargets()[before:]
		require.NotEmpty(t, targets, "the proposal was still pending, so its own certificate commits it")
		require.Equal(t, []byte(a), []byte(targets[0]))
	})

	t.Run("target guard: a same-round certificate commits the block it names, not the pending proposal", func(t *testing.T) {
		// The round matches, so the round check passes; the certificate names B, a different valid child of the same parent.
		// Only the target rule (commit the certificate's block hash, never p.hash) commits B and not A.
		ctx := context.Background()
		round, exec, a, b, rootRound, nodeID, sub, _ := commitGuardFixture(t)

		same := *sub.last(t).InputRecord
		same.BlockHash = []byte(b.Hash)
		same.Hash = []byte(b.StateRoot)
		uc := &types.UnicityCertificate{Version: 1, InputRecord: &same,
			UnicitySeal: &types.UnicitySeal{Version: 1, RootChainRoundNumber: rootRound, Timestamp: 1000}}

		before := len(exec.commitTargets())
		require.NoError(t, round.HandleCertificate(ctx, uc, tr(3, 0, nodeID)))
		targets := exec.commitTargets()[before:]
		require.NotEmpty(t, targets)
		require.Equal(t, []byte(b.Hash), []byte(targets[0]), "the commit target is the certificate's block")
		require.NotContains(t, targets, a, "the pending proposal is never committed on a certificate that names another block")
	})
}
