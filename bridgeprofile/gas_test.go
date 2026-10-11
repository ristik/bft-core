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
// certificate call (owner-decisions section 22): two anchors at every cap fit (4,674,692), eight DN-B-shape certificates fit,
// and eight maximum-size ones do not, so the gate still decides big bundles; the anchor ceiling (eight, B1's own claim
// ceiling) is a parser limit, no longer a consequence of the gate (nine of the cheapest certificates would still fit the gas).
func TestGateDecidesEachBundle(t *testing.T) {
	const sigs, steps = 64, 1 + MaxUnicitySteps
	worst2 := fitGas(MaxEnvelopeBytes, MaxSemanticBytes, 2, MaxAnchorUCBytes, sigs, steps, MaxLeaves, MaxRSMTSiblings)
	t.Logf("two anchors at every cap: %d of %d", worst2, TxGasBudget)
	require.Equal(t, uint64(4_674_692), worst2)
	require.LessOrEqual(t, worst2, TxGasBudget)
	typical := fitGas(8<<10, 2<<10, 2, 4<<10, 5, 8, MaxLeaves, 8)
	t.Logf("typical bundle (two 4 KiB UCs, 5 sigs, 8 steps): %d", typical)
	require.LessOrEqual(t, typical, TxGasBudget)
	// DN-B committee shape (measured in compose-anchors-max-dnb): 811-byte certificates, four signatures, one shard sibling.
	real8 := fitGas(12<<10, 4<<10, MaxAnchors, 811, 4, 1, MaxLeaves, 8)
	t.Logf("eight DN-B-shape UCs, 16 leaves, 8-sibling paths: %d", real8)
	require.LessOrEqual(t, real8, TxGasBudget)
	all := fitGas(MaxEnvelopeBytes, MaxSemanticBytes, MaxAnchors, MaxAnchorUCBytes, sigs, steps, MaxLeaves, MaxRSMTSiblings)
	t.Logf("eight anchors at every cap: %d", all)
	require.Greater(t, all, TxGasBudget)
	// The gate is not slack: six anchors at every cap already exceed it, five fit.
	require.Greater(t, fitGas(MaxEnvelopeBytes, MaxSemanticBytes, MaxAnchors-2, MaxAnchorUCBytes, sigs, steps, MaxLeaves, MaxRSMTSiblings), TxGasBudget)
	require.LessOrEqual(t, fitGas(MaxEnvelopeBytes, MaxSemanticBytes, MaxAnchors-3, MaxAnchorUCBytes, sigs, steps, MaxLeaves, MaxRSMTSiblings), TxGasBudget)
	// The cheapest conceivable certificates (one signature, one step, 400 bytes) of one more than the ceiling still fit the gas.
	require.LessOrEqual(t, fitGas(4<<10, 1<<10, MaxAnchors+1, 400, 1, 1, MaxAnchors+1, 0), TxGasBudget)
}
