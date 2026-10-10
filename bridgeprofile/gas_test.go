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

// TestGateDecidesEachBundle pins what the 7,000,000 budget admits under the parser ceilings: two anchors at
// every cap still fit (6,976,692), four real-size certificates fit, four maximum-size ones do not, and five
// can never fit however small the certificates are (so A_max=4 is a ceiling the gate need not defend).
func TestGateDecidesEachBundle(t *testing.T) {
	const sigs, steps = 64, 1 + MaxUnicitySteps
	worst2 := fitGas(MaxEnvelopeBytes, MaxSemanticBytes, 2, MaxAnchorUCBytes, sigs, steps, MaxLeaves, MaxRSMTSiblings)
	t.Logf("two anchors at every cap: %d of %d", worst2, TxGasBudget)
	require.Equal(t, uint64(6_976_692), worst2)
	require.LessOrEqual(t, worst2, TxGasBudget)
	typical := fitGas(8<<10, 2<<10, 2, 4<<10, 5, 8, MaxLeaves, 8)
	t.Logf("typical bundle (two 4 KiB UCs, 5 sigs, 8 steps): %d", typical)
	require.LessOrEqual(t, typical, TxGasBudget)
	// Real DN-B certificates: about 1.5 KB, four signatures, one shard sibling.
	real4 := fitGas(12<<10, 4<<10, MaxAnchors, 1536, 4, 1, MaxLeaves, 8)
	t.Logf("four real-size UCs, 16 leaves, 8-sibling paths: %d", real4)
	require.LessOrEqual(t, real4, TxGasBudget)
	require.Greater(t, fitGas(MaxEnvelopeBytes, MaxSemanticBytes, 3, MaxAnchorUCBytes, sigs, steps, MaxLeaves, MaxRSMTSiblings), TxGasBudget)
	require.Greater(t, fitGas(MaxEnvelopeBytes, MaxSemanticBytes, MaxAnchors, MaxAnchorUCBytes, sigs, steps, MaxLeaves, MaxRSMTSiblings), TxGasBudget)
	// Five of the smallest conceivable certificates (one signature, one step, 400 bytes) already exceed it.
	require.Greater(t, fitGas(4<<10, 1<<10, MaxAnchors+1, 400, 1, 1, MaxAnchors+1, 0), TxGasBudget)
}
