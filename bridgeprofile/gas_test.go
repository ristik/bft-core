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

// TestWorstAdmittedBundleFitsBudget proves the named bounds are consistent with
// the budget: a bundle at every cap (and the signature and step caps of the
// native scan) still passes the gate, so BudgetExceeded is never a surprise at
// the bounds.
func TestWorstAdmittedBundleFitsBudget(t *testing.T) {
	worst := fitGas(MaxEnvelopeBytes, MaxSemanticBytes, MaxAnchors, MaxAnchorUCBytes, 64, 1+MaxUnicitySteps, MaxLeaves, MaxRSMTSiblings)
	t.Logf("worst admitted bundle: %d of %d", worst, TxGasBudget)
	require.LessOrEqual(t, worst, TxGasBudget)
	typical := fitGas(8<<10, 2<<10, MaxAnchors, 4<<10, 5, 8, MaxLeaves, 8)
	t.Logf("typical bundle (4 KiB UC, 5 sigs, 8 steps): %d", typical)
	require.LessOrEqual(t, typical, TxGasBudget)
	// One more anchor or leaf than the bounds would not fit at worst sizes.
	require.Greater(t, fitGas(MaxEnvelopeBytes, MaxSemanticBytes, MaxAnchors+1, MaxAnchorUCBytes, 64, 1+MaxUnicitySteps, MaxLeaves+8, MaxRSMTSiblings), TxGasBudget)
}
