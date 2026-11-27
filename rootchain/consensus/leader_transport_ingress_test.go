package consensus_test

import (
	"context"

	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/rootchain"
	"github.com/unicitynetwork/bft-core/rootchain/consensus"
)

func init() {
	consensus.SetNewRootNode(func(p *network.Peer, n consensus.RootPartitionNet, cm *consensus.ConsensusManager, obs network.Observability) (interface {
		Run(context.Context) error
	}, error) {
		return rootchain.New(p, n, cm, obs)
	})
}
