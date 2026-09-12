package shardnode_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-core/shardnode/executortest"
)

// TestRound_CrashAfterSubmitBeforeUC_RecoversWithoutEquivocatingOrDoubleBuilding
// is the exact scenario an external review of this plan flagged as the
// acceptance gate for the crash-recovery fix in round.go's reconcile:
// crash the adapter after Build/Seal/submit but before the confirming UC is
// processed, restart against the same (durable) executor state, and prove
// it reconciles instead of either erroring permanently or building a
// second, different candidate for the round that was already in flight.
//
// The two *shardnode.Round values below share one Executor instance on
// purpose: a real restart loses round.go's in-memory pending-submission
// bookkeeping but does NOT lose a persistent executor's own data (reth
// writes a block to disk on newPayload, before any forkchoiceUpdate makes
// it canonical) — a fresh Round wired to the same executortest.Fake models
// exactly that: process restarted, executor's data survived.
func TestRound_CrashAfterSubmitBeforeUC_RecoversWithoutEquivocatingOrDoubleBuilding(t *testing.T) {
	ctx := context.Background()
	exec := executortest.New()

	signer, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	verifier, err := signer.Verifier()
	require.NoError(t, err)
	pk, err := verifier.MarshalPublicKey()
	require.NoError(t, err)
	nodeID := "node-" + string(pk[:8])

	// --- pre-crash process ---
	subBeforeCrash := &recordingSubmitter{}
	roundBeforeCrash := shardnode.NewRound(nodeID, types.PartitionID(8), types.ShardID{}, exec, shardnode.NewLoopbackDisseminator(), signer, subBeforeCrash, nil)

	// Round 1: genesis, trivially quiet in executor terms (no entries) —
	// gets past the special-cased first round without exercising the
	// recovery path yet.
	require.NoError(t, roundBeforeCrash.HandleCertificate(ctx, genesisUC(1000), tr(1, 0, nodeID)))
	req1 := subBeforeCrash.last(t)
	uc1 := certifyFrom(req1, 2, 1000)

	// Round 2: real entries, so the executor genuinely changes state —
	// this is the case where losing in-memory pending state actually
	// matters (a round that never moved state has nothing to reconcile).
	exec.AddEntries([]byte("tx-in-flight-when-it-crashed"))
	require.NoError(t, roundBeforeCrash.HandleCertificate(ctx, uc1, tr(2, 0, nodeID)))
	req2 := subBeforeCrash.last(t)
	require.NotEmpty(t, req2.InputRecord.BlockHash, "round 2 has real entries, must not be quiet")

	headAfterSubmit, err := exec.Head(ctx)
	require.NoError(t, err)
	require.Empty(t, headAfterSubmit.Hash, "round 2's block must still be uncommitted — only Verified, never Committed, at the moment of the crash")

	// --- crash: roundBeforeCrash and its in-memory pending state are gone ---

	// The root chain, meanwhile, certified round 2 exactly as submitted
	// (single validator, quorum trivially met) and is now offering round 3.
	uc2 := certifyFrom(req2, 3, 1000)

	// --- restart: fresh Round, same executor instance, no memory of round 2 ---
	subAfterRestart := &recordingSubmitter{}
	roundAfterRestart := shardnode.NewRound(nodeID, types.PartitionID(8), types.ShardID{}, exec, shardnode.NewLoopbackDisseminator(), signer, subAfterRestart, nil)

	err = roundAfterRestart.HandleCertificate(ctx, uc2, tr(3, 0, nodeID))
	require.NoError(t, err, "must reconcile via Commit rather than requiring manual recovery")

	// Proof of reconciliation: the executor's head now matches what was
	// certified, even though roundAfterRestart never built or verified
	// this block itself in this process lifetime.
	headAfterRecovery, err := exec.Head(ctx)
	require.NoError(t, err)
	require.Equal(t, []byte(req2.InputRecord.Hash), []byte(headAfterRecovery.StateRoot))

	// Proof of no double-build: round 3's request extends round 2's
	// certified state exactly once — there is no second, divergent
	// candidate for round 2 anywhere in what was submitted after restart.
	req3 := subAfterRestart.last(t)
	require.Equal(t, uint64(3), req3.InputRecord.RoundNumber)
	require.Equal(t, []byte(req2.InputRecord.Hash), []byte(req3.InputRecord.PreviousHash))

	// Proof of no equivocation: nothing was ever submitted for round 2
	// after the restart — the only round-2 submission in existence is the
	// pre-crash one already certified as uc2.
	for _, req := range subAfterRestart.got {
		require.NotEqual(t, uint64(2), req.InputRecord.RoundNumber, "must never resubmit for an already-certified round after restart")
	}
}
