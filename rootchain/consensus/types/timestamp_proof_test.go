package types

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTimestampProof(t *testing.T) {
	block := &BlockData{Epoch: 2, Round: 12, Timestamp: 5000}
	valid := &RoundInfo{Epoch: 2, RoundNumber: 12, Timestamp: 5000}
	require.NoError(t, VerifyTimestampProof(block, &QuorumCert{VoteInfo: valid}))
	for _, tc := range []struct {
		name  string
		block *BlockData
		qc    *QuorumCert
	}{
		{"nil block", nil, &QuorumCert{VoteInfo: valid}},
		{"nil certificate", block, nil},
		{"nil vote info", block, &QuorumCert{}},
		{"wrong epoch", block, &QuorumCert{VoteInfo: &RoundInfo{Epoch: 1, RoundNumber: 12, Timestamp: 5000}}},
		{"wrong round", block, &QuorumCert{VoteInfo: &RoundInfo{Epoch: 2, RoundNumber: 11, Timestamp: 5000}}},
		{"missing time", block, &QuorumCert{VoteInfo: &RoundInfo{Epoch: 2, RoundNumber: 12}}},
		{"wrong time", block, &QuorumCert{VoteInfo: &RoundInfo{Epoch: 2, RoundNumber: 12, Timestamp: 5001}}},
	} {
		t.Run(tc.name, func(t *testing.T) { require.ErrorIs(t, VerifyTimestampProof(tc.block, tc.qc), ErrTimestampProof) })
	}
}
