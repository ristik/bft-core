package trustbase

import (
	"bytes"
	"crypto"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/internal/testutils/logger"
	testtrustbase "github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	"github.com/unicitynetwork/bft-core/keyvaluedb/memorydb"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

func TestInstallV2ProjectionPreservesVerifiedCommittee(t *testing.T) {
	signer, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	old := testtrustbase.NewTrustBaseFromSigners(t, map[string]abcrypto.Signer{"old": signer}).(*types.RootTrustBaseV1)
	store, err := NewTrustBaseStore(memorydb.New(), logger.New(t))
	require.NoError(t, err)
	require.NoError(t, store.Store(old))
	oldID, err := old.Hash(crypto.SHA256)
	require.NoError(t, err)
	projection, err := types.NewTrustBase(old.NetworkID, old.RootNodes, types.WithEpoch(2),
		types.WithEpochStart(7), types.WithPreviousTrustBaseHash(oldID))
	require.NoError(t, err)
	projection.StateHash = bytes.Repeat([]byte{1}, 32)
	projection.ChangeRecordHash = bytes.Repeat([]byte{2}, 32)
	_, err = store.InstallV2Projection(nil)
	require.Error(t, err)
	wrong := *projection
	wrong.Epoch = 1
	_, err = store.InstallV2Projection(&wrong)
	require.Error(t, err)
	wrong = *projection
	wrong.Epoch = 3
	_, err = store.InstallV2Projection(&wrong)
	require.Error(t, err)
	wrong = *projection
	wrong.NetworkID++
	_, err = store.InstallV2Projection(&wrong)
	require.Error(t, err)
	wrong = *projection
	wrong.PreviousEntryHash = bytes.Repeat([]byte{9}, 32)
	_, err = store.InstallV2Projection(&wrong)
	require.Error(t, err)
	installed, err := store.InstallV2Projection(projection)
	require.NoError(t, err)
	require.Equal(t, projection, installed)
	again, err := store.InstallV2Projection(projection)
	require.NoError(t, err)
	require.Same(t, installed, again)
	for _, mutate := range []func(*types.RootTrustBaseV1){
		func(p *types.RootTrustBaseV1) { p.EpochStart++ },
		func(p *types.RootTrustBaseV1) { p.QuorumThreshold++ },
		func(p *types.RootTrustBaseV1) { p.RootNodes = append(p.RootNodes, &types.NodeInfo{}) },
		func(p *types.RootTrustBaseV1) { p.StateHash = bytes.Repeat([]byte{3}, 32) },
		func(p *types.RootTrustBaseV1) { p.ChangeRecordHash = bytes.Repeat([]byte{3}, 32) },
		func(p *types.RootTrustBaseV1) {
			p.RootNodes = append([]*types.NodeInfo(nil), p.RootNodes...)
			p.RootNodes[0] = &types.NodeInfo{NodeID: "other"}
		},
	} {
		wrong = *projection
		mutate(&wrong)
		_, err = store.InstallV2Projection(&wrong)
		require.ErrorIs(t, err, ErrAlreadyExists)
	}
}
