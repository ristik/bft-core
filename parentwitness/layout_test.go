package parentwitness

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/registryproof"
	"github.com/unicitynetwork/bft-go-base/types"
)

func layoutContext(layout uint64) Context {
	return Context{NetworkID: 3, PartitionID: 8, ShardID: types.ShardID{}, FullShardConfHash: common.Hash{1}, RegistryAddress: registryproof.RegistryAddress,
		RegistryCodeHash: common.Hash{2}, GenesisCommitment: common.Hash{3}, EVMGenesisHash: common.Hash{4}, RootEpoch: 1, Layout: layout}
}

func TestRegistryLayoutIsCarriedIntoTheProofContextAndNeverDroppedOnTheWire(t *testing.T) {
	require.EqualValues(t, 2, layoutContext(2).proofContext().Layout, "a layout-2 deployment is verified as layout 2")
	require.EqualValues(t, 0, layoutContext(0).proofContext().Layout)

	// The version 1 wire context has no field for the layout. A layout-2 context is refused rather than encoded
	// as the other registry.
	_, err := EncodeRequest(Request{Context: layoutContext(2), BlockHash: common.Hash{9}})
	require.ErrorIs(t, err, ErrLayoutUnsupported)
	_, err = EncodeResponse(Response{Request: Request{Context: layoutContext(2), BlockHash: common.Hash{9}}, Outcome: OutcomeUnavailable})
	require.ErrorIs(t, err, ErrLayoutUnsupported)
	raw, err := EncodeRequest(Request{Context: layoutContext(1), BlockHash: common.Hash{9}})
	require.NoError(t, err)
	decoded, err := DecodeRequest(raw)
	require.NoError(t, err)
	require.EqualValues(t, 0, decoded.Context.Layout)

	_, err = EncodeRequest(Request{Context: layoutContext(registryproof.FreshB1 + 1), BlockHash: common.Hash{9}})
	require.ErrorIs(t, err, ErrInvalidRequest)

	require.EqualValues(t, registryproof.FreshB1, layoutContext(registryproof.FreshB1).proofContext().Layout)
	_, err = EncodeRequest(Request{Context: layoutContext(registryproof.FreshB1), BlockHash: common.Hash{9}})
	require.ErrorIs(t, err, ErrLayoutUnsupported)
	fresh, err := NewTarget(TargetConfig{NetworkID: 3, PartitionID: 8, ShardID: types.ShardID{}, FullShardConfHash: common.Hash{1}, Registry: layoutContext(registryproof.FreshB1).proofContext(), BlockHash: common.Hash{9}})
	require.NoError(t, err)
	require.EqualValues(t, registryproof.FreshB1, fresh.Request().Context.Layout)

	target, err := NewTarget(TargetConfig{NetworkID: 3, PartitionID: 8, ShardID: types.ShardID{}, FullShardConfHash: common.Hash{1},
		Registry: layoutContext(2).proofContext(), BlockHash: common.Hash{9}})
	require.NoError(t, err)
	require.EqualValues(t, 2, target.Request().Context.Layout)
}
