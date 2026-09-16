package frontierclient

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// These fixtures isolate budget accounting from cryptographic verification.
// Real-root tests establish how verified candidates and cuts are obtained.
func TestReviewCutSharesLifetimeBudgetAndClearsEvidence(t *testing.T) {
	c := &Collector{}
	require.Error(t, c.Add([]byte{0}).Err)
	_, err := c.AddCut([]byte{0})
	require.Error(t, err)
	require.EqualValues(t, 2, c.Snapshot().UsedBytes(), "both malformed input paths spend the same budget")

	c.used = maxAggregate - 1
	c.candidate = Candidate{pair: []byte{1}}
	c.cut = VerifiedCut{raw: []byte{2}}
	old := c.Snapshot()
	_, err = c.AddCut([]byte{0, 0})
	require.ErrorIs(t, err, ErrBudget)
	require.EqualValues(t, maxAggregate, c.Snapshot().UsedBytes())
	require.True(t, c.Snapshot().Exhausted())
	require.False(t, c.Snapshot().Candidate().Valid())
	require.False(t, c.Snapshot().VerifiedCut().Valid())
	require.True(t, old.Candidate().Valid(), "old snapshots are diagnostic copies")
	require.True(t, old.VerifiedCut().Valid())
	require.ErrorIs(t, c.Add(nil).Err, ErrBudget, "exhaustion is shared and sticky")
	_, err = c.AddCut(nil)
	require.ErrorIs(t, err, ErrBudget)
}
