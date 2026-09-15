package shardnode

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHealthReportsTheCertifiedRecordOutcomeWithoutChangingVoting(t *testing.T) {
	h := NewHealth()
	require.Empty(t, h.Snapshot().CertifiedRecord, "a node without a record store reports no record status")

	h.updateCertifiedRecord("executor-ahead", "executor at 3, record at 2")
	s := h.Snapshot()
	require.Equal(t, "executor-ahead", s.CertifiedRecord)
	require.Equal(t, "executor at 3, record at 2", s.CertifiedRecordDetail)
	require.True(t, s.Voting, "the record status is not a voting decision")

	var unset *Health
	unset.updateCertifiedRecord("durable-ready", "")
}
