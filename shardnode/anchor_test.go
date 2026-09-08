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
		require.Equal(t, anchorInstalled, c.observe(nonQuietIR(10, nil, s0, blockA)))
		require.NotNil(t, c.anchor)
		require.Equal(t, blockA, []byte(c.anchor.BlockHash))
		require.Equal(t, s0, []byte(c.anchor.StateRoot))
		require.Equal(t, uint64(10), c.anchor.Round)
		require.Equal(t, uint64(10), c.through, "no quiet round has followed yet")
	})

	t.Run("consecutive quiet rounds extend the interval one at a time", func(t *testing.T) {
		var c continuityState
		c.observe(nonQuietIR(10, nil, s0, blockA))
		require.Equal(t, anchorExtended, c.observe(quietIR(11, s0)))
		require.Equal(t, uint64(11), c.through)
		require.Equal(t, anchorExtended, c.observe(quietIR(12, s0)))
		require.Equal(t, uint64(12), c.through)
		require.Equal(t, blockA, []byte(c.anchor.BlockHash), "the anchor itself does not move")
	})

	t.Run("a repeat neither advances nor invalidates", func(t *testing.T) {
		var c continuityState
		c.observe(nonQuietIR(10, nil, s0, blockA))
		c.observe(quietIR(11, s0))
		require.Equal(t, anchorUnchanged, c.observe(quietIR(11, s0)), "same round again")
		require.Equal(t, uint64(11), c.through, "a repeat must not extend the covered interval")
		require.NotNil(t, c.anchor)
	})

	t.Run("a gap invalidates: a missed interval can return to the same state by another block", func(t *testing.T) {
		var c continuityState
		c.observe(nonQuietIR(10, nil, s0, blockA))
		require.Equal(t, anchorInvalidated, c.observe(quietIR(13, s0)), "rounds 11 and 12 were never seen")
		require.Nil(t, c.anchor)

		_, err := c.recoveryTarget(s0)
		require.ErrorContains(t, err, "no-anchor",
			"a coincidentally matching state root must not resurrect the anchor")
	})

	t.Run("a quiet certificate at a different state invalidates", func(t *testing.T) {
		var c continuityState
		c.observe(nonQuietIR(10, nil, s0, blockA))
		require.Equal(t, anchorInvalidated, c.observe(quietIR(11, s1)))
		require.Nil(t, c.anchor)
	})

	t.Run("a repeat disagreeing about the round's state invalidates", func(t *testing.T) {
		var c continuityState
		c.observe(nonQuietIR(10, nil, s0, blockA))
		c.observe(quietIR(11, s0))
		require.Equal(t, anchorInvalidated, c.observe(quietIR(11, s1)),
			"two certificates for one round that disagree cannot both be right")
		require.Nil(t, c.anchor)
	})

	t.Run("a later non-quiet certificate replaces the anchor entirely", func(t *testing.T) {
		var c continuityState
		c.observe(nonQuietIR(10, nil, s0, blockA))
		c.observe(quietIR(11, s0))
		require.Equal(t, anchorInstalled, c.observe(nonQuietIR(12, s0, s1, blockB)))
		require.Equal(t, blockB, []byte(c.anchor.BlockHash))
		require.Equal(t, uint64(12), c.through, "the interval restarts at the new anchor")
	})

	t.Run("quiet certificates before any block leave no anchor", func(t *testing.T) {
		// A shard whose first certificates are sync/genesis has certified no block yet. That is
		// not a fault, and must not be reported as a broken chain.
		var c continuityState
		require.Equal(t, anchorUnchanged, c.observe(quietIR(1, nil)))
		require.Nil(t, c.anchor)
	})

	t.Run("recoveryTarget names the row that refused", func(t *testing.T) {
		var c continuityState
		_, err := c.recoveryTarget(s0)
		require.ErrorContains(t, err, "no-anchor")

		c.observe(nonQuietIR(10, nil, s0, blockA))
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
			c.observe(uc)
			target, err := c.recoveryTarget(s0)
			if err == nil {
				require.NotEmpty(t, target)
			}
		}
	})

	t.Run("a nil certificate or input record is ignored, not a panic", func(t *testing.T) {
		var c continuityState
		require.Equal(t, anchorUnchanged, c.observe(nil))
		require.Equal(t, anchorUnchanged, c.observe(&types.UnicityCertificate{Version: 1}))
	})
}

// TestAnchorIsNotRestoredFromDisk pins the boundary this PR deliberately stops at.
//
// A restored checkpoint proves historical continuity, NOT authorization to sign (#105, design
// §6.1): an older checkpoint replays perfectly, and resuming from one can re-enter rounds this node
// has already voted in. So the anchor is in-process only, and there is no path that loads one.
//
// When persistence lands, this test must be replaced by the P-sign gate — not simply deleted. It is
// here so that "we persisted the anchor" cannot silently become "restored nodes may vote".
func TestAnchorIsNotRestoredFromDisk(t *testing.T) {
	r := &Round{}
	require.Nil(t, r.continuity.anchor,
		"a freshly constructed Round has no anchor")

	// SeedLUC is the only restore entry point on the client side, and it seeds the certificate
	// cursor — never an execution anchor.
	c := &BFTClient{}
	c.SeedLUC(nonQuietIR(10, nil, []byte{0x51}, []byte{0x0a}))
	require.NotNil(t, c.luc, "the certificate cursor is restored")

	r2 := &Round{}
	require.Nil(t, r2.continuity.anchor,
		"restoring a certificate must not install an execution anchor: until #105 supplies the "+
			"monotonic signing contract, a restored node may observe and reconcile but not vote on "+
			"the strength of retained evidence")
}
