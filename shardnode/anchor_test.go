package shardnode

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-go-base/types"
)

// ir builds the input record shapes the continuity state machine distinguishes.
func nonQuietIR(round uint64, prev, hash, block []byte) *types.UnicityCertificate {
	return &types.UnicityCertificate{Version: 1, InputRecord: &types.InputRecord{
		Version: 1, RoundNumber: round, PreviousHash: prev, Hash: hash, BlockHash: block,
		SummaryValue: []byte{}, Timestamp: 1000,
	}}
}

func quietIR(round uint64, state []byte) *types.UnicityCertificate {
	return &types.UnicityCertificate{Version: 1, InputRecord: &types.InputRecord{
		Version: 1, RoundNumber: round, PreviousHash: state, Hash: state, BlockHash: nil,
		SummaryValue: []byte{}, Timestamp: 1000,
	}}
}

/*
TestContinuityState is the transition table of docs/design/f6b-quiet-uc-recovery.md §3.3, as code.

The state machine is small and every branch is a safety decision, so each is tested directly rather
than inferred from a recovery outcome three layers up.
*/
func TestContinuityState(t *testing.T) {
	s0 := []byte{0x51}
	s1 := []byte{0x52}
	blockA := []byte{0x0a}
	blockB := []byte{0x0b}

	t.Run("a non-quiet certificate installs the anchor and resets the interval", func(t *testing.T) {
		var c continuityState
		require.Equal(t, anchorInstalled, c.observe(nonQuietIR(10, nil, s0, blockA), 11))
		require.NotNil(t, c.anchor)
		require.Equal(t, blockA, []byte(c.anchor.BlockHash))
		require.Equal(t, s0, []byte(c.anchor.StateRoot))
		require.Equal(t, uint64(10), c.anchor.Round)
		require.Equal(t, uint64(10), c.through, "no quiet round has followed yet")
	})

	t.Run("consecutive quiet rounds extend the interval one at a time", func(t *testing.T) {
		var c continuityState
		c.observe(nonQuietIR(10, nil, s0, blockA), 11)
		require.Equal(t, anchorExtended, c.observe(quietIR(11, s0), 12))
		require.Equal(t, uint64(11), c.through)
		require.Equal(t, anchorExtended, c.observe(quietIR(12, s0), 13))
		require.Equal(t, uint64(12), c.through)
		require.Equal(t, blockA, []byte(c.anchor.BlockHash), "the anchor itself does not move")
	})

	t.Run("a repeat neither advances nor invalidates", func(t *testing.T) {
		var c continuityState
		c.observe(nonQuietIR(10, nil, s0, blockA), 11)
		c.observe(quietIR(11, s0), 12)
		require.Equal(t, anchorUnchanged, c.observe(quietIR(11, s0), 12), "same round again")
		require.Equal(t, uint64(11), c.through, "a repeat must not extend the covered interval")
		require.NotNil(t, c.anchor)
	})

	t.Run("a gap invalidates: a missed interval can return to the same state by another block", func(t *testing.T) {
		var c continuityState
		c.observe(nonQuietIR(10, nil, s0, blockA), 11)
		require.Equal(t, anchorInvalidated, c.observe(quietIR(13, s0), 14), "rounds 11 and 12 were never seen")
		require.Nil(t, c.anchor)

		_, err := c.recoveryTarget(s0)
		require.ErrorContains(t, err, "continuity-gap",
			"a coincidentally matching state root must not resurrect the anchor — and the refusal "+
				"says the evidence chain BROKE (row 10), not that none was ever established (row 8): "+
				"the first needs a resync, the second resolves itself on the next non-quiet certificate")
	})

	t.Run("a skipped round NUMBER is not a gap when the technical record assigned it", func(t *testing.T) {
		// MEASURED on a four-validator real-reth devnet: certified partition rounds are not
		// consecutive integers. The first certificate of the run was `partitionRound=0 ...
		// nextRound=2`, and a later one `partitionRound=5 ... nextRound=7`. Testing `through+1`
		// treated every such skip as a missed certificate and invalidated the anchor of every
		// honest node at once.
		var c continuityState
		c.observe(nonQuietIR(2, nil, s0, blockA), 3)
		require.Equal(t, anchorExtended, c.observe(quietIR(3, s0), 5),
			"round 3 was the assigned next round")
		require.Equal(t, anchorExtended, c.observe(quietIR(5, s0), 6),
			"round 4 was abandoned by the root chain, not missed by this node: 5 is what it assigned")
		require.Equal(t, uint64(5), c.through)
	})

	t.Run("a certificate for a round that was NOT assigned still invalidates", func(t *testing.T) {
		// The tightening that comes with the correction above: the test is no longer "is the
		// number one higher" but "is this the round the previous certificate named", which a
		// genuinely missed certificate fails.
		var c continuityState
		c.observe(nonQuietIR(2, nil, s0, blockA), 3)
		require.Equal(t, anchorInvalidated, c.observe(quietIR(4, s0), 5),
			"round 3 was assigned, so a certificate for 4 means 3's certificate was never seen")
	})

	t.Run("a quiet certificate at a different state invalidates", func(t *testing.T) {
		var c continuityState
		c.observe(nonQuietIR(10, nil, s0, blockA), 11)
		require.Equal(t, anchorInvalidated, c.observe(quietIR(11, s1), 12))
		require.Nil(t, c.anchor)
	})

	t.Run("a repeat disagreeing about the round's state invalidates", func(t *testing.T) {
		var c continuityState
		c.observe(nonQuietIR(10, nil, s0, blockA), 11)
		c.observe(quietIR(11, s0), 12)
		require.Equal(t, anchorInvalidated, c.observe(quietIR(11, s1), 12),
			"two certificates for one round that disagree cannot both be right")
		require.Nil(t, c.anchor)
	})

	t.Run("a later non-quiet certificate replaces the anchor entirely", func(t *testing.T) {
		var c continuityState
		c.observe(nonQuietIR(10, nil, s0, blockA), 11)
		c.observe(quietIR(11, s0), 12)
		require.Equal(t, anchorInstalled, c.observe(nonQuietIR(12, s0, s1, blockB), 13))
		require.Equal(t, blockB, []byte(c.anchor.BlockHash))
		require.Equal(t, uint64(12), c.through, "the interval restarts at the new anchor")
	})

	t.Run("quiet certificates before any block leave no anchor", func(t *testing.T) {
		// A shard whose first certificates are sync/genesis has certified no block yet. That is
		// not a fault, and must not be reported as a broken chain.
		var c continuityState
		require.Equal(t, anchorUnchanged, c.observe(quietIR(1, nil), 2))
		require.Nil(t, c.anchor)
	})

	t.Run("recoveryTarget names the row that refused", func(t *testing.T) {
		var c continuityState
		_, err := c.recoveryTarget(s0)
		require.ErrorContains(t, err, "no-anchor", "nothing observed yet: row 8")

		c.observe(nonQuietIR(10, nil, s0, blockA), 11)
		_, err = c.recoveryTarget(s1)
		require.ErrorContains(t, err, "anchor-mismatch",
			"an anchor producing a different state must be refused by name, not applied")

		target, err := c.recoveryTarget(s0)
		require.NoError(t, err)
		require.Equal(t, blockA, []byte(target))
	})

	t.Run("recoveryTarget never returns an empty hash", func(t *testing.T) {
		// Commit(nil) is the #92 defect. It must be unrepresentable here, not merely avoided by
		// callers.
		var c continuityState
		for _, uc := range []*types.UnicityCertificate{
			quietIR(1, nil), quietIR(2, s0), nonQuietIR(3, s0, s1, nil),
		} {
			c.observe(uc, uc.InputRecord.RoundNumber+1)
			target, err := c.recoveryTarget(s0)
			if err == nil {
				require.NotEmpty(t, target)
			}
		}
	})

	t.Run("a nil certificate or input record is ignored, not a panic", func(t *testing.T) {
		var c continuityState
		require.Equal(t, anchorUnchanged, c.observe(nil, 0))
		require.Equal(t, anchorUnchanged, c.observe(&types.UnicityCertificate{Version: 1}, 0))
	})
}

/*
TestCheckHeadIdentity is P-id (§4) at the level it is decided: the executor's head against the
certified block, with the state root already equal in every case.

Every case here has head.StateRoot == the certified state. That is the point — state equality was
the condition the round loop used to treat as "already reconciled, go ahead and sign", and it
decides nothing on its own, because two blocks can share a post-state.
*/
func TestCheckHeadIdentity(t *testing.T) {
	s0 := []byte{0x51}
	blockA := []byte{0x0a}
	blockB := []byte{0x0b}
	// The executor's own genesis block, as the round loop captures it before any certificate is
	// processed. Row 13's exception compares against this in full, never against "block 0".
	genesis := BlockRef{Number: 0, Hash: []byte{0x00}, StateRoot: s0}

	t.Run("row 1: the head is the certified block", func(t *testing.T) {
		var c continuityState
		c.observe(nonQuietIR(10, s0, s0, blockA), 11)
		require.NoError(t, c.checkHeadIdentity(BlockRef{Number: 7, Hash: blockA, StateRoot: s0}, s0, &genesis))
	})

	t.Run("row 2: same state, different block", func(t *testing.T) {
		var c continuityState
		c.observe(nonQuietIR(10, s0, s0, blockA), 11)
		err := c.checkHeadIdentity(BlockRef{Number: 7, Hash: blockB, StateRoot: s0}, s0, &genesis)
		require.ErrorContains(t, err, "head-identity-mismatch")
	})

	t.Run("row 8: no anchor is refused even at the certified state", func(t *testing.T) {
		var c continuityState
		require.ErrorContains(t, c.checkHeadIdentity(BlockRef{Number: 7, Hash: blockA, StateRoot: s0}, s0, &genesis), "no-anchor")
	})

	t.Run("row 13: the genesis round, and only at the executor's actual genesis block", func(t *testing.T) {
		// The shard's first certified round (nil PreviousHash) may name a block the executor never
		// made canonical — round.go does not commit a round whose state did not move, and "genesis
		// is always non-quiet" means such a round carries a block hash regardless. Against reth
		// that is every idle shard: the certificate names a block reth built and discarded while
		// its head stays at genesis. So the comparison is made against the genesis block itself.
		var c continuityState
		c.observe(nonQuietIR(1, nil, s0, blockA), 2)
		require.True(t, c.anchor.fromGenesisRound)
		require.NoError(t, c.checkHeadIdentity(genesis, s0, &genesis),
			"the executor is at its genesis block, at the certified state")

		// It is a comparison, not a category. A head that merely CLAIMS to be block 0 at the right
		// state is refused: this is the reviewer's same-state/different-block case, and an earlier
		// revision that tested only `Number == 0` let it through again.
		require.ErrorContains(t,
			c.checkHeadIdentity(BlockRef{Number: 0, Hash: blockB, StateRoot: s0}, s0, &genesis),
			"head-identity-mismatch",
			"block 0 with a different block hash is not the genesis block")
		require.ErrorContains(t,
			c.checkHeadIdentity(BlockRef{Number: 3, Hash: blockB, StateRoot: s0}, s0, &genesis),
			"head-identity-mismatch",
			"nor is any later head whose state root happens to match")
		require.ErrorContains(t,
			c.checkHeadIdentity(genesis, s0, nil),
			"head-identity-mismatch",
			"and with no genesis head captured there is nothing to compare against")
	})

	t.Run("the exception does not outlive the genesis anchor", func(t *testing.T) {
		var c continuityState
		c.observe(nonQuietIR(1, nil, s0, blockA), 2)
		c.observe(nonQuietIR(2, s0, s0, blockB), 3) // the first state-changing round replaces it
		require.False(t, c.anchor.fromGenesisRound)
		require.ErrorContains(t,
			c.checkHeadIdentity(BlockRef{Number: 0, Hash: nil, StateRoot: s0}, s0, &genesis),
			"head-identity-mismatch")
	})
}

// TestAnchorIsNotRestoredFromDisk pins the persistence half of the boundary this PR stops at: no
// path installs an execution anchor from disk. The SIGNING half — that restoring a certificate is
// not authorization to vote — is no longer left to follow from the anchor's absence; it is enforced
// and tested at the real restore-to-signing boundary in TestRestoredNodeIsNonVoting.
//
// Both must be replaced together, not deleted, when persistence and #105's monotonic signing record
// land: the restored anchor is precisely what that record exists to gate.
func TestAnchorIsNotRestoredFromDisk(t *testing.T) {
	r := &Round{}
	require.Nil(t, r.continuity.anchor, "a freshly constructed Round has no anchor")

	// SeedLUC seeds the certificate cursor, and only that.
	c := &BFTClient{}
	c.SeedLUC(nonQuietIR(10, nil, []byte{0x51}, []byte{0x0a}))
	require.NotNil(t, c.luc, "the certificate cursor is restored")

	r2 := &Round{}
	resumeFrom(c, r2, nonQuietIR(10, nil, []byte{0x51}, []byte{0x0a}))
	require.Nil(t, r2.continuity.anchor,
		"restoring a certificate must not install an execution anchor")
	require.NotNil(t, r2.restoredFrom,
		"and it must mark the process non-voting: until #105 supplies the monotonic signing "+
			"contract, a restored node may observe and reconcile but not vote on the strength of "+
			"retained evidence")
}
