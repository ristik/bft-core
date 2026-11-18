package storage_test

import (
	"crypto"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	"github.com/unicitynetwork/bft-core/rootchain/vrstate"
	"github.com/unicitynetwork/bft-core/vradmit"
	"github.com/unicitynetwork/bft-go-base/types"
)

// VT-14: a VR generation's roots start in VR mode from the genesis configurations alone. The coupled EVM shard configuration pins VR
// (validator_registry, validator_registry_code_hash), so the genesis control state carries the genesis VR root state with N = the genesis
// committee; a genesis that pins no VR is exactly the P85 genesis.
func vrGenesisConfs(pins map[string]string, coupled bool, validators int) func(uint64) (map[types.PartitionShardID]*types.PartitionDescriptionRecord, error) {
	params := map[string]string{"chain_id": "3"}
	for k, v := range pins {
		params[k] = v
	}
	if coupled {
		params[evmassign.CouplingParam] = "true"
	}
	var infos []*types.NodeInfo
	for i := 0; i < validators; i++ {
		infos = append(infos, &types.NodeInfo{NodeID: string(rune('a' + i)), Stake: 1})
	}
	conf := &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: 8, PartitionTypeID: evmassign.EVMPartitionTypeID, PartitionParams: params,
		Validators: infos}
	return func(uint64) (map[types.PartitionShardID]*types.PartitionDescriptionRecord, error) {
		return map[types.PartitionShardID]*types.PartitionDescriptionRecord{{PartitionID: 8, ShardID: types.ShardID{}.Key()}: conf}, nil
	}
}

var vrPins = map[string]string{vrstate.ParamValidatorRegistry: "0xff00000000000000000000000000000000000003",
	vrstate.ParamValidatorRegistryCodeHash: "0x19094777cb74c783f82392439d1f6c79fe62b6b57c2915790f00a9e16ee490e9"}

func TestAVRGenesisStartsInVRMode(t *testing.T) {
	orch := storage.NewMockOrchestrationForTest(vrGenesisConfs(vrPins, true, 4), nil)
	b, err := storage.NewGenesisBlockOf(orch, crypto.SHA256, storage.ProfileHandoff)
	require.NoError(t, err)
	want, err := vradmit.GenesisRootState(1, 4).Encode()
	require.NoError(t, err)
	require.Equal(t, want, b.ShardState.Control.VR)
	st, err := vradmit.DecodeRootState(b.ShardState.Control.VR)
	require.NoError(t, err)
	require.EqualValues(t, 4, st.Backoff.N)
	require.EqualValues(t, 1, st.Backoff.Epoch)

	// the VR slot is committed: the genesis root differs from a P85 genesis of the same network
	p85, err := storage.NewGenesisBlockOf(storage.NewMockOrchestrationForTest(vrGenesisConfs(nil, true, 4), nil), crypto.SHA256, storage.ProfileHandoff)
	require.NoError(t, err)
	require.Nil(t, p85.ShardState.Control.VR)
	require.NotEqual(t, p85.RootHash, b.RootHash)
	plain, err := storage.NewGenesisBlock(5, crypto.SHA256, storage.ProfileHandoff)
	require.NoError(t, err)
	require.Equal(t, plain.RootHash, p85.RootHash, "a genesis that pins no VR is exactly the P85 genesis")
}

func TestAVRPinMustBeTheCoupledShardsAndComplete(t *testing.T) {
	for name, confs := range map[string]func(uint64) (map[types.PartitionShardID]*types.PartitionDescriptionRecord, error){
		"not coupled":  vrGenesisConfs(vrPins, false, 4),
		"address only": vrGenesisConfs(map[string]string{vrstate.ParamValidatorRegistry: vrPins[vrstate.ParamValidatorRegistry]}, true, 4),
		"hash only":    vrGenesisConfs(map[string]string{vrstate.ParamValidatorRegistryCodeHash: vrPins[vrstate.ParamValidatorRegistryCodeHash]}, true, 4),
		"17 members":   vrGenesisConfs(vrPins, true, 17),
	} {
		_, err := storage.NewGenesisBlockOf(storage.NewMockOrchestrationForTest(confs, nil), crypto.SHA256, storage.ProfileHandoff)
		require.ErrorIs(t, err, storage.ErrNetworkProfile, name)
	}
	// the legacy profile has no control state; it never reads the configurations
	_, err := storage.NewGenesisBlockOf(storage.NewMockOrchestrationForTest(vrGenesisConfs(vrPins, false, 4), nil), crypto.SHA256, storage.ProfileLegacy)
	require.NoError(t, err)
}
