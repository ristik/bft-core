package consensus

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/leader"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-go-base/types"
)

// bootstrapLeader uses the canonical new committee order for the entire epoch.
type bootstrapLeader struct {
	start   uint64
	members []peer.ID
}

func newBootstrapLeader(base Leader, start uint64, nodes []*types.NodeInfo) (*bootstrapLeader, error) {
	if base == nil || start == 0 || len(nodes) == 0 {
		return nil, errors.New("bootstrap leader has no committee")
	}
	members := make([]peer.ID, len(nodes))
	ordered := slices.Clone(nodes)
	slices.SortFunc(ordered, func(a, b *types.NodeInfo) int { return strings.Compare(a.NodeID, b.NodeID) })
	for i, node := range ordered {
		id, err := peer.Decode(node.NodeID)
		if err != nil {
			return nil, fmt.Errorf("bootstrap member %q: %w", node.NodeID, err)
		}
		members[i] = id
	}
	return &bootstrapLeader{start: start, members: members}, nil
}

func (b *bootstrapLeader) GetLeaderForRound(round uint64) (peer.ID, error) {
	if round < b.start {
		return "", errors.New("round precedes epoch genesis")
	}
	return b.members[(round-b.start)%uint64(len(b.members))], nil
}

func (b *bootstrapLeader) UpdateWithTrustBase(tb types.RootTrustBase, round uint64) error {
	return nil
}

func (b *bootstrapLeader) Update(qc *rctypes.QuorumCert, currentRound uint64, blocks leader.BlockLoader) error {
	// Nodes can install the same genesis after seeing different old-epoch
	// suffixes. Switching to a locally updated reputation selector would
	// let them disagree about the leader despite a common committee.
	return nil
}
