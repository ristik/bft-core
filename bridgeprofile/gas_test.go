package bridgeprofile

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/b1ref"
)

// fitGas prices an envelope of the given shape through the gate terms.
func fitGas(envelopeBytes, semanticBytes, anchors, ucBytes int, sigs, steps uint64, leaves, siblings int) uint64 {
	uc := b1ref.UCGas(ucRequestFixed+1+uint64(ucBytes), sigs, 1, steps)
	rs := b1ref.RSMTGas(rsmtRequestFixed+32*uint64(siblings), uint64(siblings))
	return IntrinsicGas(envelopeBytes) + B2Gas(KernelRequestBytes(semanticBytes, semanticBytes), leaves) +
		uint64(anchors)*uc + uint64(leaves)*rs + GasReserve
}

// TestGateDecidesEachBundle pins what the 7,000,000 budget admits under the parser ceilings after the repricing of the
// certificate call (owner-decisions section 22) and the matching execution term (80 gas per envelope byte for the composing
// verifier's own work, which the cheaper certificates no longer hide inside the reserve): bundles of realistic size fit at the
// anchor ceiling, the maximum envelope no longer fits at all (65,536 bytes alone cost 6.3M), and the anchor ceiling (eight, B1's own
// claim ceiling) is a parser limit.
func TestGateDecidesEachBundle(t *testing.T) {
	const sigs, steps = 64, 1 + MaxUnicitySteps
	worst2 := fitGas(MaxEnvelopeBytes, MaxSemanticBytes, 2, MaxAnchorUCBytes, sigs, steps, MaxLeaves, MaxRSMTSiblings)
	t.Logf("two anchors at every cap: %d of %d", worst2, TxGasBudget)
	require.Equal(t, uint64(9_917_572), worst2)
	require.Greater(t, worst2, TxGasBudget, "the maximum envelope is priced out")
	typical := fitGas(8<<10, 2<<10, 2, 4<<10, 5, 8, MaxLeaves, 8)
	t.Logf("typical bundle (two 4 KiB UCs, 5 sigs, 8 steps): %d", typical)
	require.LessOrEqual(t, typical, TxGasBudget)
	// DN-B committee shape (measured in compose-anchors-max-dnb): 811-byte certificates, four signatures, one shard sibling.
	real8 := fitGas(12<<10, 4<<10, MaxAnchors, 811, 4, 1, MaxLeaves, 8)
	t.Logf("eight DN-B-shape UCs, 16 leaves, 8-sibling paths, 12 KiB envelope: %d", real8)
	require.LessOrEqual(t, real8, TxGasBudget)
	// A 40 KiB envelope with eight maximum-signature anchors and deep paths is priced out; the same with two anchors is not.
	require.Greater(t, fitGas(40<<10, 8<<10, MaxAnchors, 4<<10, sigs, steps, MaxLeaves, MaxRSMTSiblings), TxGasBudget)
	require.LessOrEqual(t, fitGas(24<<10, 8<<10, 2, 4<<10, sigs, steps, MaxLeaves, MaxRSMTSiblings), TxGasBudget)
	// The cheapest conceivable certificates (one signature, one step, 400 bytes) of one more than the ceiling still fit the gas.
	require.LessOrEqual(t, fitGas(4<<10, 1<<10, MaxAnchors+1, 400, 1, 1, MaxAnchors+1, 0), TxGasBudget)
}
