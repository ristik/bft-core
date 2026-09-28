package rootinput

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"
)

func TestCheckEpochCertificatesOrdersEpochBeforeRound(t *testing.T) {
	previous := &types.UnicityCertificate{InputRecord: &types.InputRecord{Version: 1, RoundNumber: 1, Hash: []byte{1}, BlockHash: []byte{0xb1}},
		UnicitySeal: &types.UnicitySeal{Epoch: 1, RootChainRoundNumber: 100}}
	next := &types.UnicityCertificate{InputRecord: &types.InputRecord{Version: 1, RoundNumber: 2, PreviousHash: []byte{1}, Hash: []byte{2}, BlockHash: []byte{0xb2}},
		UnicitySeal: &types.UnicitySeal{Epoch: 2, RootChainRoundNumber: 1}}
	require.NoError(t, CheckEpochCertificates(previous, next))
	next.UnicitySeal.Epoch = 3
	require.Error(t, CheckEpochCertificates(previous, next), "skipped trust epoch requires its own handoff")
	next.UnicitySeal.Epoch = 2
	next.InputRecord.PreviousHash = []byte{9}
	require.Error(t, CheckEpochCertificates(previous, next), "epoch reset cannot bypass state continuity")
}
