//go:build !q4shim

package cmd

import (
	"context"
	"log/slog"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/unicitynetwork/bft-go-base/crypto"

	"github.com/unicitynetwork/bft-core/rootchain/consensus"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
)

// wrapRootNet is the seam of the Q4 fault shim. Without the q4shim build tag it is the identity: a production binary carries no shim
// code and no way to switch one on.
func wrapRootNet(_ context.Context, net consensus.RootNet, _ peer.ID, _ crypto.Signer, _ func(uint64) (votesig.Config, error), _ *slog.Logger) (consensus.RootNet, func(), error) {
	return net, func() {}, nil
}
