package consensus

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// A plan for an exact recovery K carries no readiness receipts, and receipts attached to one are refused; the receipt gate (the full set for
// everything else) is not consulted for it.
func TestPlanReceiptsOfAnExactRecoveryAreNoneAtAll(t *testing.T) {
	x := &ConsensusManager{} // no Q3 history: reaching the receipt gate would fail, so passing proves it was not consulted
	require.NoError(t, x.verifyPlanReceipts([]byte("body"), nil, 0, make([]byte, 32), true))
	require.ErrorIs(t, x.verifyPlanReceipts([]byte("body"), []byte{0x80}, 0, make([]byte, 32), true), ErrHandoffApproval)
}
