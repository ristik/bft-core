package shardnode_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-core/shardnode/executortest"
)

// identityFixture drives a Round to the state every case below starts from: round 1 certified
// (genesis), round 2 non-quiet and APPLIED, so the node holds a live anchor and its executor is at
// the certified block. It returns the certificate for the quiet round that follows — the next thing
// this node would ordinarily vote on.
//
// It also establishes §4 row 13, the genesis exception, as a side effect rather than by assertion
// alone: the shard's first certified round carries its state root in place of a block hash (see
// BlockHashOrFallback), and if the identity gate did not admit that one anchor the node could never
// have got past round 2 to build this fixture at all.
func identityFixture(t *testing.T) (context.Context, *executortest.Fake, *rewindableExecutor, *shardnode.Round, *recordingSubmitter, string, *types.UnicityCertificate) {
	t.Helper()
	ctx := context.Background()
	fake := executortest.New()
	exec := &rewindableExecutor{Executor: fake}
	sub := &recordingSubmitter{}
	round, nodeID := newTestRound(t, exec, sub)

	require.NoError(t, round.HandleCertificate(ctx, genesisUC(1000), tr(1, 0, nodeID)))
	req1 := sub.last(t)
	require.NotEmpty(t, req1.InputRecord.BlockHash, "genesis is never quiet")

	// Round 2 changes state, so its certificate is non-quiet and installs the anchor.
	fake.AddEntries([]byte("block A"))
	require.NoError(t, round.HandleCertificate(ctx, certifyFrom(req1, 2, 1000), tr(2, 0, nodeID)))
	req2 := sub.last(t)
	require.NotEmpty(t, req2.InputRecord.BlockHash, "round 2 must be non-quiet")

	// Certifying round 2 applies it: the executor is now AT the anchor block.
	uc2 := certifyFrom(req2, 3, 1000)
	require.NoError(t, round.HandleCertificate(ctx, uc2, tr(3, 0, nodeID)))
	head, err := exec.Head(ctx)
	require.NoError(t, err)
	require.Equal(t, []byte(uc2.InputRecord.BlockHash), []byte(head.Hash), "the fixture starts ON the certified block")

	quiet := certifyFrom(sub.last(t), 4, 1000)
	require.Empty(t, quiet.InputRecord.BlockHash, "round 3 is quiet")
	return ctx, fake, exec, round, sub, nodeID, quiet
}

/*
TestRound_IdentityGate drives the real Round through the §4 rows that decide whether this node may
vote — with the executor's STATE ROOT matching the certified one in every single case.

That last clause is the whole test. HandleCertificate used to enter the recovery path only when the
state roots DIFFERED, so a round whose state root already matched was built and signed with nothing
in anchor.go consulted: not the anchor, not block identity, not continuity. Two different blocks can
share a post-state (§3.3.1), so a matching state root is not evidence of standing on the certified
block, and a node that missed a non-quiet interval and came back to the same state could sign from
the wrong one. An earlier revision of the transition table had exactly that fast path and it was
removed as unsound; these cases are what removing it means in the code.

Each case reaches the gate at the same state root and differs only in what the node can prove about
the block underneath it.
*/
func TestRound_IdentityGate(t *testing.T) {
	t.Run("row 1 control: an undisturbed node still votes", func(t *testing.T) {
		// Without this, every case below could be passing because the node had stopped voting
		// altogether.
		ctx, _, _, round, sub, nodeID, quiet := identityFixture(t)
		before := len(sub.got)
		require.NoError(t, round.HandleCertificate(ctx, quiet, tr(4, 0, nodeID)))
		require.Len(t, sub.got, before+1, "the ordinary path must still submit")
		require.Equal(t, uint64(4), sub.last(t).InputRecord.RoundNumber)
	})

	t.Run("row 2: same state, different block — the vote is withheld, the node is not", func(t *testing.T) {
		ctx, _, exec, round, sub, nodeID, quiet := identityFixture(t)
		health := shardnode.NewHealth()
		round.SetHealth(health)

		// The executor reports the certified STATE on a different block. This is the shape a
		// missed non-quiet interval leaves behind, and the one state-root equality cannot see.
		head, err := exec.Head(ctx)
		require.NoError(t, err)
		head.Hash = make([]byte, 32)
		head.Hash[0] = 0xff
		exec.rewindTo(head)

		before, commits := len(sub.got), len(exec.commitTargets())
		require.NoError(t, round.HandleCertificate(ctx, quiet, tr(4, 0, nodeID)),
			"abstaining from a vote is not a processing error")
		require.Len(t, sub.got, before, "a node on an uncertified block must not sign")
		require.False(t, health.Snapshot().Voting)
		require.Contains(t, health.Snapshot().NonVotingReason, "head-identity-mismatch",
			"the refusal names its transition-table row, and an operator can see it without logs")
		require.Equal(t, commits, len(exec.commitTargets()),
			"nothing is applied to an executor whose state already matches")
	})

	t.Run("row 8: no anchor is a voting barrier even when the state agrees", func(t *testing.T) {
		ctx, _, exec, _, _, _, quiet := identityFixture(t)

		// A fresh Round over the SAME executor: the head is the certified block and the state
		// root matches, but this Round has observed no non-quiet certificate, so it cannot say
		// which certified block produced that state. Nothing about the head tells it — after a
		// run of quiet rounds the executor's head is the same whatever round it is (§6.1).
		restartedSub := &recordingSubmitter{}
		restarted, restartedID := newTestRound(t, exec, restartedSub)
		health := shardnode.NewHealth()
		restarted.SetHealth(health)

		require.NoError(t, restarted.HandleCertificate(ctx, quiet, tr(4, 0, restartedID)))
		require.Empty(t, restartedSub.got, "no anchor, no vote")
		require.Contains(t, health.Snapshot().NonVotingReason, "no-anchor", "nothing observed in this process: row 8")
	})

	t.Run("an abstaining node keeps up, and starts voting again on its own", func(t *testing.T) {
		// The reason the verdict is applied at the signing gate rather than before block
		// production. A node that refuses to build never runs Verify, so its execution client
		// never receives the payload, so it can never commit the block and is permanently behind
		// — measured on a real devnet. Here the node abstains, stays in lockstep, and the next
		// state-changing certificate re-arms it with no operator action.
		ctx, fake, exec, round, sub, nodeID, quiet := identityFixture(t)
		health := shardnode.NewHealth()
		round.SetHealth(health)

		head, err := exec.Head(ctx)
		require.NoError(t, err)
		head.Hash = make([]byte, 32)
		head.Hash[0] = 0xff
		exec.rewindTo(head)
		require.NoError(t, round.HandleCertificate(ctx, quiet, tr(4, 0, nodeID)))
		require.False(t, health.Snapshot().Voting)

		// The executor is put back where the shard is, and a state-changing round follows.
		exec.rewindTo(shardnode.BlockRef{})
		fake.AddEntries([]byte("the round that re-arms this node"))
		next := certifyFrom(sub.last(t), 5, 1000)
		require.NoError(t, round.HandleCertificate(ctx, next, tr(5, 0, nodeID)))
		require.True(t, health.Snapshot().Voting, "an anchor that matches the head re-arms voting")
		require.Equal(t, uint64(5), sub.last(t).InputRecord.RoundNumber)
	})

	t.Run("a gap that returns to the same state root is refused", func(t *testing.T) {
		// §3.3.1's counterexample, through the real Round rather than continuityState alone: the
		// node misses partition round 4 entirely and sees round 5, quiet, at the state it is
		// already sitting at. The gap means it cannot say what happened in round 4 — a non-quiet
		// round can leave the same state root behind a DIFFERENT block — so the anchor is
		// invalidated and the matching state root must not resurrect it.
		ctx, _, exec, round, sub, nodeID, quiet := identityFixture(t)

		gapped := quietFrom(quiet, 5, 1000)
		gapped.InputRecord.RoundNumber = quiet.InputRecord.RoundNumber + 2 // round 5, skipping 4
		require.Equal(t, []byte(quiet.InputRecord.Hash), []byte(gapped.InputRecord.Hash),
			"the fixture's point: the certified state root is unchanged across the gap")

		health := shardnode.NewHealth()
		round.SetHealth(health)
		before, commits := len(sub.got), len(exec.commitTargets())
		require.NoError(t, round.HandleCertificate(ctx, gapped, tr(6, 0, nodeID)))
		require.Contains(t, health.Snapshot().NonVotingReason, "continuity-gap",
			"the gap is named as such (row 10) rather than reported as never having had an anchor")
		require.Len(t, sub.got, before, "and nothing is signed while it holds")
		require.Equal(t, commits, len(exec.commitTargets()))
	})
}

/*
TestRound_TransientCommitFailureKeepsTheAnchor pins the ordering that makes a failed apply
recoverable at all (design §5, §5.1).

The certificate is authenticated evidence about what the root chain certified; whether this node
then manages to apply it is a different question with a different answer, and the two were
conflated. commitPrevious ran BEFORE the certificate was observed, so a Commit that returned SYNCING
— the executor being briefly unavailable, exactly the case the retry contract exists for — ended the
round before the certified block hash was ever recorded. The next quiet certificate then found no
anchor and refused `no-anchor`: a transient failure turned into a permanent inability to recover,
with the certified payload still sitting in the executor.

`anchor.round > appliedRound` is the normal, retryable state. This test drives exactly it.
*/
func TestRound_TransientCommitFailureKeepsTheAnchor(t *testing.T) {
	ctx := context.Background()
	fake := executortest.New()
	exec := &rewindableExecutor{Executor: fake}
	sub := &recordingSubmitter{}
	round, nodeID := newTestRound(t, exec, sub)

	require.NoError(t, round.HandleCertificate(ctx, genesisUC(1000), tr(1, 0, nodeID)))
	fake.AddEntries([]byte("the block whose commit fails once"))
	require.NoError(t, round.HandleCertificate(ctx, certifyFrom(sub.last(t), 2, 1000), tr(2, 0, nodeID)))
	req2 := sub.last(t)
	require.NotEmpty(t, req2.InputRecord.BlockHash)

	// The confirming certificate arrives while the executor is momentarily unable to apply it.
	uc2 := certifyFrom(req2, 3, 1000)
	exec.forceCommitStatus(shardnode.StatusSyncing)
	require.Error(t, round.HandleCertificate(ctx, uc2, tr(3, 0, nodeID)),
		"the round fails, as it should — the executor did not apply the certified block")

	// The executor recovers. Nothing else about the shard changed: the next certificate is an
	// ordinary quiet one, which carries no block hash of its own.
	exec.commitStatus = nil
	quiet := quietFrom(uc2, 4, 1000)
	require.Empty(t, quiet.InputRecord.BlockHash)

	require.NoError(t, round.HandleCertificate(ctx, quiet, tr(4, 0, nodeID)),
		"the anchor was recorded when its certificate verified, so the retry has a target")

	head, err := exec.Head(ctx)
	require.NoError(t, err)
	require.Equal(t, []byte(uc2.InputRecord.BlockHash), []byte(head.Hash),
		"P-id: the executor is at the certified BLOCK, not merely at a matching state")
	require.Equal(t, []byte(uc2.InputRecord.Hash), []byte(head.StateRoot))
	require.Equal(t, uint64(4), sub.last(t).InputRecord.RoundNumber, "and the node is voting again")
}
