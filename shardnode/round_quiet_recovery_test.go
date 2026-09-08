package shardnode_test

import (
	"context"
	"crypto"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"

	testcertificates "github.com/unicitynetwork/bft-core/internal/testutils/certificates"
	testtrustbase "github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
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

	(a) the certified payload IS present locally, merely not canonical. This models one possible
	    restart state; it does not prove reth payload durability across process/power failure.
	    A separate control establishes that the fake can apply the explicit block target.
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

			// The fake block is Verified but never Committed. This models retained local data;
			// the real client's restart/durability guarantees require separate evidence.
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
			// Authenticate both fixture certificates using the actual UC verifier. The test
			// retains uc2; roundAfter receives only quietUC3 and has no anchor store.
			tb := testtrustbase.NewTrustBase(t, signer)
			pdr := &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: 8}
			tr3Hash, err := tr(3, 0, nodeID).Hash()
			require.NoError(t, err)
			uc2 := testcertificates.CreateUnicityCertificate(t, signer, req2.InputRecord, pdr, 3, make([]byte, 32), tr3Hash)
			require.NoError(t, uc2.Verify(tb, crypto.SHA256, 8, types.ShardID{}, uc2.ShardConfHash))
			nextTR := tr(4, 0, nodeID)
			tr4Hash, err := nextTR.Hash()
			require.NoError(t, err)
			quietUC3 := testcertificates.CreateUnicityCertificate(t, signer, quietFrom(uc2, 4, 1000).InputRecord, pdr, 4, uc2.UnicitySeal.Hash, tr4Hash)
			require.NoError(t, quietUC3.Verify(tb, crypto.SHA256, 8, types.ShardID{}, uc2.ShardConfHash))
			require.Empty(t, quietUC3.InputRecord.BlockHash, "round 3 is quiet: nil BlockHash by construction")
			require.Equal(t, []byte(req2.InputRecord.Hash), []byte(quietUC3.InputRecord.PreviousHash),
				"the quiet round still extends round 2's certified state, which this node never applied")

			before := len(exec.commitTargets())
			err = roundAfter.HandleCertificate(ctx, quietUC3, nextTR)

			// STAGE 3 REPAIR. This block asserted the defect until #92 stage 3: reconcile used
			// to attempt a Commit with an EMPTY target, taken from the quiet certificate's nil
			// BlockHash. It must not any more.
			targets := exec.commitTargets()
			for _, target := range targets {
				require.NotEmpty(t, target, "Commit(nil) must be unreachable (#92)")
			}
			require.Equal(t, before, len(targets),
				"with no anchor there is no certified block to recover to, so no Commit is attempted at all")

			// It still fails — correctly. This roundAfter models a RESTART, and the anchor is
			// in-process state that a restart loses. Retaining it across a restart needs the
			// persisted evidence sequence AND the independent signing contract (#105) before a
			// restored node may vote, so the fail-closed refusal below is the intended stage-3
			// outcome for this scenario, not an unfixed defect. The live-anchor path — where the
			// node did observe the state-changing certificate — is
			// TestRound_QuietUCRecoversViaLiveAnchor.
			require.Error(t, err, "the node cannot build on a state it never applied")
			require.ErrorContains(t, err, "no-anchor",
				"the refusal must name which transition-table row rejected, not fail generically")

			// The fixture holds a verified UC naming the earlier block. It is NOT supplied
			// to roundAfter: this does not prove a restarted node has retained that anchor.
			require.NotEmpty(t, uc2.InputRecord.BlockHash)
			t.Logf("#92 trace: executorHead=%x certifiedPrevious=%x quietUC.BlockHash=%v commitTargets=%d fixtureAnchor(uc2.BlockHash)=%x payloadPresent=%t err=%v",
				headBefore.StateRoot, quietUC3.InputRecord.PreviousHash, quietUC3.InputRecord.BlockHash,
				len(targets), uc2.InputRecord.BlockHash, tc.payloadPresent, err)

			// Control: with the explicit fixture target, the two availability cases differ.
			// This is a test-only direct commit after observing the defect, not a repair.
			controlStatus, controlErr := fake.Commit(ctx, shardnode.Hash(uc2.InputRecord.BlockHash))
			require.NoError(t, controlErr)
			if tc.payloadPresent {
				require.Equal(t, shardnode.StatusValid, controlStatus)
				applied, err := fake.Head(ctx)
				require.NoError(t, err)
				require.Equal(t, []byte(uc2.InputRecord.Hash), []byte(applied.StateRoot))
			} else {
				require.Equal(t, shardnode.StatusSyncing, controlStatus)
			}

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

/*
rewindableExecutor models the one situation in which a node holding a LIVE anchor still finds its
executor behind: the execution client restarted while the shard node kept running (design §1.1's
restart matrix, row 2). The shard process never lost the anchor — it observed the state-changing
certificate itself — but the executor's head went backwards.

Head reports the rewound reference until a Commit succeeds — modelling a client that reports an
older head while the data is still present, which is what a restarting or syncing client does.
commitStatus lets a test make the payload unavailable without touching the underlying store, which
is how "unavailable" is separated from "invalid" here.
*/
type rewindableExecutor struct {
	shardnode.Executor
	mu           sync.Mutex
	stale        *shardnode.BlockRef
	commits      []shardnode.Hash
	commitStatus *shardnode.Status // when set, Commit returns this instead of delegating
}

func (r *rewindableExecutor) rewindTo(ref shardnode.BlockRef) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stale = &ref
}

func (r *rewindableExecutor) forceCommitStatus(s shardnode.Status) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.commitStatus = &s
}

func (r *rewindableExecutor) Head(ctx context.Context) (shardnode.BlockRef, error) {
	r.mu.Lock()
	stale := r.stale
	r.mu.Unlock()
	if stale != nil {
		return *stale, nil
	}
	return r.Executor.Head(ctx)
}

func (r *rewindableExecutor) Commit(ctx context.Context, hash shardnode.Hash) (shardnode.Status, error) {
	r.mu.Lock()
	r.commits = append(r.commits, hash)
	forced := r.commitStatus
	r.mu.Unlock()
	if forced != nil {
		return *forced, nil
	}
	status, err := r.Executor.Commit(ctx, hash)
	if err == nil && status == shardnode.StatusValid {
		r.mu.Lock()
		r.stale = nil // the executor caught up
		r.mu.Unlock()
	}
	return status, err
}

func (r *rewindableExecutor) commitTargets() []shardnode.Hash {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]shardnode.Hash(nil), r.commits...)
}

/*
TestRound_QuietUCRecoversViaLiveAnchor is the #92 stage-3 repair, in the case stage 3 actually
closes: the node OBSERVED the state-changing certificate, so it holds the anchor in process, and a
later QUIET certificate can still identify the block to recover to.

Stage 1 established the failure and stage 2 the design; this establishes the fix. It is deliberately
the same shape as the stage-1 reproduction except for one thing — the Round that receives the quiet
certificate is the one that saw the non-quiet certificate, rather than a fresh one modelling a
restart. That single difference is what the in-process anchor is.

Three cases, because they must not be conflated (design §4 rows 6, 7, 9):

	payload present  -> recovery succeeds via the anchor, and BOTH post-conditions hold
	payload absent   -> UNAVAILABLE, retryable, anchor retained; never reported as invalid
	anchor mismatch  -> refused by name, with no Commit attempted at all
*/
func TestRound_QuietUCRecoversViaLiveAnchor(t *testing.T) {
	// newFixture drives a live Round to the state that matters: it has OBSERVED the state-changing
	// certificate (so it holds the anchor in process and has committed round 2), and its executor
	// has then gone backwards — the execution-client restart of §1.1. The next certificate it sees
	// is QUIET, which is precisely the case that used to strand it.
	newFixture := func(t *testing.T) (context.Context, *executortest.Fake, *rewindableExecutor, *shardnode.Round, *types.UnicityCertificate, *certification.TechnicalRecord) {
		t.Helper()
		ctx := context.Background()
		fake := executortest.New()
		exec := &rewindableExecutor{Executor: fake}

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

		// Round 2: real entries, so the certificate is NON-QUIET and installs the anchor.
		fake.AddEntries([]byte("the block that becomes the anchor"))
		require.NoError(t, round.HandleCertificate(ctx, uc1, tr(2, 0, nodeID)))
		req2 := sub.last(t)
		require.NotEmpty(t, req2.InputRecord.BlockHash, "round 2 must be non-quiet for this scenario")

		uc2 := certifyFrom(req2, 3, 1000)
		require.NoError(t, round.HandleCertificate(ctx, uc2, tr(3, 0, nodeID)))

		applied, err := exec.Head(ctx)
		require.NoError(t, err)
		require.Equal(t, []byte(uc2.InputRecord.Hash), []byte(applied.StateRoot),
			"the node applied round 2 while it was live — the anchor is real, not hypothetical")

		// THE EXECUTION CLIENT RESTARTS. The shard process keeps running, so it still holds the
		// anchor; the executor's head goes back to before round 2.
		exec.rewindTo(shardnode.BlockRef{})

		nextTR := tr(4, 0, nodeID)
		quietUC3 := quietFrom(uc2, 4, 1000)
		require.Empty(t, quietUC3.InputRecord.BlockHash, "round 3 is quiet: nil BlockHash by construction")
		return ctx, fake, exec, round, quietUC3, nextTR
	}

	t.Run("payload present: recovers via the anchor across the quiet round", func(t *testing.T) {
		ctx, fake, exec, round, quietUC3, nextTR := newFixture(t)

		before := len(exec.commitTargets())
		require.NoError(t, round.HandleCertificate(ctx, quietUC3, nextTR),
			"the quiet certificate must no longer strand the node: the anchor names the block")

		targets := exec.commitTargets()
		require.Greater(t, len(targets), before, "a recovery Commit must have been attempted")
		for _, target := range targets {
			require.NotEmpty(t, target, "Commit(nil) must be unreachable (#92)")
		}

		// P-id: the executor is at the certified BLOCK, not merely at a matching state root.
		head, err := fake.Head(ctx)
		require.NoError(t, err)
		require.Equal(t, []byte(quietUC3.InputRecord.Hash), []byte(head.StateRoot))
		require.NotEmpty(t, head.Hash, "the executor head is a real block, not just a state")
	})

	t.Run("payload absent: unavailable and retryable, never reported as invalid", func(t *testing.T) {
		ctx, _, exec, round, quietUC3, nextTR := newFixture(t)
		exec.forceCommitStatus(shardnode.StatusSyncing) // the executor does not have the payload

		before := len(exec.commitTargets())
		err := round.HandleCertificate(ctx, quietUC3, nextTR)
		require.Error(t, err)

		targets := exec.commitTargets()
		require.Greater(t, len(targets), before, "the anchor must still supply a real target")
		require.NotEmpty(t, targets[len(targets)-1])

		require.ErrorContains(t, err, "unavailable in the executor")
		require.NotContains(t, err.Error(), "REJECTED",
			"an unavailable payload must never be reported as a rejected one")
		require.ErrorContains(t, err, "retaining the anchor")
	})

	t.Run("payload invalid is a fault, reported differently from unavailable", func(t *testing.T) {
		ctx, _, exec, round, quietUC3, nextTR := newFixture(t)
		exec.forceCommitStatus(shardnode.StatusInvalid)

		err := round.HandleCertificate(ctx, quietUC3, nextTR)
		require.Error(t, err)
		require.ErrorContains(t, err, "REJECTED")
		require.NotContains(t, err.Error(), "unavailable in the executor",
			"a rejected payload must never be reported as merely unavailable")
	})

	t.Run("the anchor survives a failed attempt, so the next certificate retries it", func(t *testing.T) {
		// "Unavailable is not invalid": the authority to retry is exactly what dropping the
		// anchor would lose (design §4). After a failed attempt the anchor must still be there,
		// and the next certificate must attempt the SAME target rather than refusing no-anchor.
		ctx, _, exec, round, quietUC3, nextTR := newFixture(t)
		exec.forceCommitStatus(shardnode.StatusSyncing)

		require.Error(t, round.HandleCertificate(ctx, quietUC3, nextTR))
		first := exec.commitTargets()
		require.NotEmpty(t, first)
		attempted := first[len(first)-1]

		// A repeat certificate for the same round — what the root chain sends on timeout.
		repeat := quietFrom(quietUC3, 5, 1000)
		repeat.InputRecord.RoundNumber = quietUC3.InputRecord.RoundNumber
		err := round.HandleCertificate(ctx, repeat, nextTR)
		require.Error(t, err, "the payload is still absent, so this attempt fails too")

		second := exec.commitTargets()
		require.Greater(t, len(second), len(first), "the retry must reach Commit again")
		require.Equal(t, []byte(attempted), []byte(second[len(second)-1]),
			"the retry must use the SAME anchor: a failed attempt must not discard it")
		require.ErrorContains(t, err, "unavailable in the executor")
	})

	t.Run("a quiet certificate at a state the anchor cannot explain is refused, with no Commit", func(t *testing.T) {
		ctx, _, exec, round, quietUC3, _ := newFixture(t)

		diverged := quietFrom(quietUC3, 5, 1000)
		diverged.InputRecord.Hash = []byte{0xDE, 0xAD, 0xBE, 0xEF}
		diverged.InputRecord.PreviousHash = diverged.InputRecord.Hash

		before := len(exec.commitTargets())
		err := round.HandleCertificate(ctx, diverged, tr(6, 0, "irrelevant"))
		require.Error(t, err)
		require.Equal(t, before, len(exec.commitTargets()),
			"a mismatched anchor must not be applied: no Commit may be attempted")
		require.ErrorContains(t, err, "continuity-gap",
			"continuity broke, so there is no anchor to offer — and the name distinguishes that "+
				"(row 10, this node has missed certified history) from never having had one "+
				"(row 8, ordinary after a restart)")
	})
}
