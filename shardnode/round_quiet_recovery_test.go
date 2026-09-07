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

// quietFrom builds the certificate for a quiet round following prev: the state does not change, so
// Hash equals PreviousHash and BlockHash is nil — the shape BuildInputRecord produces for a round
// with nothing to execute, and required by InputRecord validation (unchanged state => nil block
// hash). This is the certificate shape #92 is about.
func quietFrom(prev *types.UnicityCertificate, rootRound, timestamp uint64) *types.UnicityCertificate {
	return &types.UnicityCertificate{
		Version: 1,
		InputRecord: &types.InputRecord{
			Version:      1,
			RoundNumber:  prev.InputRecord.RoundNumber + 1,
			Epoch:        prev.InputRecord.Epoch,
			PreviousHash: prev.InputRecord.Hash,
			Hash:         prev.InputRecord.Hash,
			BlockHash:    nil,
			SummaryValue: prev.InputRecord.SummaryValue,
			Timestamp:    prev.InputRecord.Timestamp,
		},
		UnicitySeal: &types.UnicitySeal{Version: 1, RootChainRoundNumber: rootRound, Timestamp: timestamp},
	}
}

// recordingExecutor wraps an Executor and records every Commit target, so a test can assert what
// the framework actually asked the executor to commit rather than only what came back.
type recordingExecutor struct {
	shardnode.Executor
	mu      sync.Mutex
	commits []shardnode.Hash
}

func (r *recordingExecutor) Commit(ctx context.Context, hash shardnode.Hash) (shardnode.Status, error) {
	r.mu.Lock()
	r.commits = append(r.commits, hash)
	r.mu.Unlock()
	return r.Executor.Commit(ctx, hash)
}

func (r *recordingExecutor) commitTargets() []shardnode.Hash {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]shardnode.Hash, len(r.commits))
	copy(out, r.commits)
	return out
}

/*
TestRound_QuietUCAfterMissedBlock_RecoveryTargetIsEmpty is the deterministic reproduction for
issue #92, stage 1: establish the failing transition before building any fetch mechanism.

The transition: a node falls behind a state-changing (non-quiet) certified block, and the next
certificate it processes is a QUIET one. Round.reconcile takes its recovery target from
uc.InputRecord.BlockHash, and a quiet certificate carries a nil BlockHash by construction (see
BuildInputRecord). So the node asks its executor to commit nothing at all.

This is not a corner case: an idle shard produces quiet rounds continuously, so any node that
misses one real block and then sees a quiet round lands here.

Two sub-cases are covered separately, as #92 requires, because they need different fixes:

	(a) the certified payload IS present locally, merely not canonical — the exact situation a
	    restarted node is in, since reth stores a block on newPayload before any forkchoiceUpdate
	    makes it canonical. Recovery is possible in principle and still fails.
	(b) the certified payload is absent — recovery genuinely cannot proceed locally, but the node
	    should say so precisely rather than reporting an empty commit target.

What this test does NOT establish, deliberately: why any particular real-reth scenario failed,
whether devp2p delivered a payload, or that #16's fake-executor stall shares this cause.
*/
func TestRound_QuietUCAfterMissedBlock_RecoveryTargetIsEmpty(t *testing.T) {
	for _, tc := range []struct {
		name           string
		payloadPresent bool
	}{
		{"payload present locally but not canonical", true},
		{"payload absent", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			fake := executortest.New()
			exec := &recordingExecutor{Executor: fake}

			signer, err := abcrypto.NewInMemorySecp256K1Signer()
			require.NoError(t, err)
			verifier, err := signer.Verifier()
			require.NoError(t, err)
			pk, err := verifier.MarshalPublicKey()
			require.NoError(t, err)
			nodeID := "node-" + string(pk[:8])

			sub := &recordingSubmitter{}
			round := shardnode.NewRound(nodeID, types.PartitionID(8), types.ShardID{}, exec,
				shardnode.NewLoopbackDisseminator(), signer, sub, nil)

			// Round 1: genesis, quiet.
			require.NoError(t, round.HandleCertificate(ctx, genesisUC(1000), tr(1, 0, nodeID)))
			uc1 := certifyFrom(sub.last(t), 2, 1000)

			// Round 2: real entries, so state genuinely changes and the certificate is non-quiet.
			fake.AddEntries([]byte("the block this node will miss"))
			require.NoError(t, round.HandleCertificate(ctx, uc1, tr(2, 0, nodeID)))
			req2 := sub.last(t)
			require.NotEmpty(t, req2.InputRecord.BlockHash, "round 2 must be non-quiet for this scenario")

			// The block is Verified but never Committed — exactly a node that died between
			// submitting and processing the confirming certificate.
			headBefore, err := exec.Head(ctx)
			require.NoError(t, err)
			require.Empty(t, headBefore.Hash, "round 2's block is not canonical yet")

			if !tc.payloadPresent {
				// Sub-case (b): the executor no longer has the payload at all.
				fake.ForgetUncommitted()
			}

			// --- restart: fresh Round, same executor, no in-memory pending record ---
			subAfter := &recordingSubmitter{}
			roundAfter := shardnode.NewRound(nodeID, types.PartitionID(8), types.ShardID{}, exec,
				shardnode.NewLoopbackDisseminator(), signer, subAfter, nil)

			// The root chain certified round 2, and round 3 was QUIET — nothing to execute, so
			// its input record carries a nil BlockHash while still advancing the certified state.
			uc2 := certifyFrom(req2, 3, 1000)
			quietUC3 := quietFrom(uc2, 4, 1000)
			require.Empty(t, quietUC3.InputRecord.BlockHash, "round 3 is quiet: nil BlockHash by construction")
			require.Equal(t, []byte(req2.InputRecord.Hash), []byte(quietUC3.InputRecord.PreviousHash),
				"the quiet round still extends round 2's certified state, which this node never applied")

			before := len(exec.commitTargets())
			err = roundAfter.HandleCertificate(ctx, quietUC3, tr(4, 0, nodeID))

			// The defect: recovery is attempted with an EMPTY target.
			targets := exec.commitTargets()
			require.Greater(t, len(targets), before, "reconcile must have attempted a recovery Commit")
			require.Empty(t, targets[len(targets)-1],
				"#92: the recovery Commit target is empty — Round.reconcile used the quiet certificate's nil BlockHash")

			require.Error(t, err, "the node cannot build on a state it never applied")

			// The certified block this node needed is round 2's, and it is named in the
			// certificate chain the node already holds — uc2's BlockHash. Recovery had a
			// usable, authenticated target available and did not use it.
			require.NotEmpty(t, uc2.InputRecord.BlockHash)
			t.Logf("#92 trace: executorHead=%x certifiedPrevious=%x quietUC.BlockHash=%v commitTarget=%v recoverableTarget(uc2.BlockHash)=%x payloadPresent=%t err=%v",
				headBefore.StateRoot, quietUC3.InputRecord.PreviousHash, quietUC3.InputRecord.BlockHash,
				targets[len(targets)-1], uc2.InputRecord.BlockHash, tc.payloadPresent, err)

			// And nothing was signed from the unreconciled executor.
			for _, req := range subAfter.got {
				require.NotEqual(t, uint64(4), req.InputRecord.RoundNumber,
					"must not submit for round 4 from an executor that never applied round 2")
			}
		})
	}
}

// TestRound_ReconcileCommentIsWrongAboutSyncing pins the specific claim #92 flagged: round.go's
// reconcile says a quiet certificate's nil BlockHash is harmless because "Commit will correctly
// report StatusSyncing for it". The fake executor does behave that way, which is exactly why the
// fake-executor chaos suite never surfaced this. A real Engine API adapter does not — it rejects
// the empty hash outright, which is the error seen in the retained real-reth logs.
func TestRound_ReconcileCommentIsWrongAboutSyncing(t *testing.T) {
	ctx := context.Background()

	fake := executortest.New()
	status, err := fake.Commit(ctx, nil)
	require.NoError(t, err, "the fake tolerates an empty commit target")
	require.Equal(t, shardnode.StatusSyncing, status, "and reports SYNCING, as reconcile's comment assumes")

	// The adapter's behaviour is asserted in engineapi (TestAdapterCommitRejectsEmptyHash):
	// "engineapi: commit: expected a 32-byte hash, got 0 bytes". The divergence between the two
	// is the reason this path survived the fake-only suite.
}
