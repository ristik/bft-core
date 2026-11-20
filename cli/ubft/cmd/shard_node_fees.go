package cmd

import (
	"context"
	"errors"
	"math"

	"github.com/unicitynetwork/bft-core/engineapi"
	"github.com/unicitynetwork/bft-core/rootchain/evmstate"
	"github.com/unicitynetwork/bft-core/rootchain/vrstate"
	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-core/vrschema"
)

func vrFeeCollectorResolver(registry [20]byte, code [32]byte) engineapi.FeeCollectorResolver {
	return func(ctx context.Context, eth *engineapi.EthClient, parent shardnode.BlockRef) ([20]byte, error) {
		if len(parent.Hash) != 32 || len(parent.StateRoot) != 32 || parent.Number == math.MaxUint64 {
			return [20]byte{}, errors.New("fee proof requires a certified parent hash, state root and child number")
		}
		source := evmstate.RPCProofSource{Client: eth, BlockHash: [32]byte(parent.Hash)}
		fees, err := vrstate.ReadFees(ctx, source, registry, code, [32]byte(parent.StateRoot))
		if err != nil {
			return [20]byte{}, err
		}
		return vrschema.FeesFor(parent.Number+1, fees).FeeCollector, nil
	}
}
