package consensus

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/leader"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-go-base/types"
)

// bootstrapLeader uses the canonical new committee order until certified
// ancestry contains the ordinary block history needed by reputation voting.
type bootstrapLeader struct {
	base     Leader
	start    uint64
	members  []peer.ID
	mu       sync.RWMutex
	fallback bool
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
	return &bootstrapLeader{base: base, start: start, members: members, fallback: true}, nil
}

func (b *bootstrapLeader) GetLeaderForRound(round uint64) (peer.ID, error) {
	b.mu.RLock()
	fallback := b.fallback
	b.mu.RUnlock()
	if fallback {
		if round < b.start {
			return "", errors.New("round precedes epoch genesis")
		}
		return b.members[(round-b.start)%uint64(len(b.members))], nil
	}
	return b.base.GetLeaderForRound(round)
}

func (b *bootstrapLeader) UpdateWithTrustBase(tb types.RootTrustBase, round uint64) error {
	b.mu.RLock()
	fallback := b.fallback
	b.mu.RUnlock()
	if fallback {
		return nil
	}
	return b.base.UpdateWithTrustBase(tb, round)
}

func (b *bootstrapLeader) Update(qc *rctypes.QuorumCert, currentRound uint64, blocks leader.BlockLoader) error {
	b.mu.RLock()
	fallback := b.fallback
	b.mu.RUnlock()
	if !fallback {
		return b.base.Update(qc, currentRound, blocks)
	}
	if qc == nil || qc.GetParentRound() < b.start {
		return nil
	}
	parent, err := blocks(qc.GetParentRound())
	if err != nil || parent == nil || parent.BlockData == nil || parent.BlockData.Author == "" {
		return nil
	}
	if err := b.base.Update(qc, currentRound, blocks); err != nil {
		return nil
	}
	b.mu.Lock()
	b.fallback = false
	b.mu.Unlock()
	return nil
}
