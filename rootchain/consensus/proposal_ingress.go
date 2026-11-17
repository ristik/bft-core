package consensus

import (
	"cmp"
	"fmt"
	"slices"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
)

// The consensus manager is the root consensus network's gate on received proposals (network.RootConsensusGate, #1113): which
// authenticated senders are admitted at all, and which have the protected share of the proposal ingress budget.

// admittedRoots is the set of roots a proposal is admitted from, for one installed trust base and one staged successor: the roots of the
// installed committee, of the staged successor, and of the trust bases the store holds for the epochs next to the installed one (the
// legacy profile switches committee by round, so a lagging root still hears the next epoch's leaders, and a leader at an epoch's start
// sends to the previous committee too). The set is rebuilt when the installed trust base, the staging or the store changes (a trust base
// can be stored while the root runs: PUT /api/v1/trustbases).
type admittedRoots struct {
	installed *types.RootTrustBaseV1
	staged    *stagedEVMMembers
	storeGen  uint64 // the trust base store's generation the adjacent epochs were read at
	ids       map[string]struct{}
}

// KnownRoot reports whether a proposal is admitted from the authenticated sender id: a root of the installed committee, of the staged
// successor or of the committee of an adjacent epoch the trust base store holds. It is safe for concurrent use, and it is cheap: the set
// is rebuilt only when the installed trust base, the staged successor or the trust base store changed.
func (x *ConsensusManager) KnownRoot(id peer.ID) bool {
	gen := x.trustBaseStore.VerifyGeneration() // before the state read with it: a store write meanwhile makes the next call rebuild
	tb := x.trustBase.Load()
	if tb == nil {
		return false
	}
	staged := x.pendingStaged()
	set := x.admitted.Load()
	if set == nil || set.installed != tb || set.staged != staged || set.storeGen != gen {
		set = x.admittedFor(tb, staged, gen)
		x.admitted.Store(set)
	}
	_, ok := set.ids[id.String()]
	return ok
}

func (x *ConsensusManager) admittedFor(tb *types.RootTrustBaseV1, staged *stagedEVMMembers, gen uint64) *admittedRoots {
	set := &admittedRoots{installed: tb, staged: staged, storeGen: gen, ids: map[string]struct{}{}}
	add := func(t *types.RootTrustBaseV1) {
		if t == nil {
			return
		}
		for _, n := range t.RootNodes {
			if n != nil {
				set.ids[n.NodeID] = struct{}{}
			}
		}
	}
	add(tb)
	if staged != nil {
		for id := range staged.roots {
			set.ids[id] = struct{}{}
		}
	}
	if x.trustBaseStore != nil {
		if tb.Epoch > 0 {
			if prev, err := x.trustBaseStore.GetByEpoch(tb.Epoch - 1); err == nil {
				add(prev)
			}
		}
		if next, err := x.trustBaseStore.GetByEpoch(tb.Epoch + 1); err == nil {
			add(next)
		}
	}
	return set
}

// proposerSet is what EligibleProposer answers from: the leaders of a round and of the round after it ("" for one not known).
type proposerSet struct {
	round uint64
	ids   [2]peer.ID
}

// EligibleProposer reports whether id is the leader of the current or of the next round, as last published by the loop
// (refreshProposers). It only gives priority in the proposal ingress budget: a stale answer admits nothing and refuses nothing.
func (x *ConsensusManager) EligibleProposer(id peer.ID) bool {
	p := x.proposers.Load()
	return p != nil && id != "" && (p.ids[0] == id || p.ids[1] == id)
}

// leaderIf is id when ok, else "".
func leaderIf(ok bool, id peer.ID) peer.ID {
	if ok {
		return id
	}
	return ""
}

// fitProposal keeps the proposal within abdrc.MaxProposalFrame, the bound every root enforces on a proposal frame before reading it
// (#1113): while the encoding is larger, the change request with the largest encoding is left out of the payload. It returns the requests
// left out; their shards are certified by a later proposal (a request that arrives again, or a T2 timeout). Under sustained oversize
// the same large-proof shard is the one left out each time: it then progresses by T2 timeouts only. The proposal is not signed yet and
// its controls are not ordered yet: limit leaves room for both. A proposal that is too large without any change request is an error.
func fitProposal(p *abdrc.ProposalMsg, limit uint64) ([]*drctypes.IRChangeReq, error) {
	size, err := encodedSize(p)
	if err != nil {
		return nil, err
	}
	if size <= limit {
		return nil, nil
	}
	payload := p.Block.Payload
	type sized struct {
		req  *drctypes.IRChangeReq
		size uint64
	}
	reqs := make([]sized, 0, len(payload.Requests))
	for _, r := range payload.Requests {
		n, err := encodedSize(r)
		if err != nil {
			return nil, err
		}
		reqs = append(reqs, sized{r, n})
	}
	// the largest first; equal sizes in the payload's order, so the choice is deterministic for a given payload
	order := slices.Clone(reqs)
	slices.SortStableFunc(order, func(a, b sized) int { return cmp.Compare(b.size, a.size) })
	var dropped []*drctypes.IRChangeReq
	for _, r := range order {
		if size <= limit {
			break
		}
		dropped = append(dropped, r.req)
		// the encoding shrinks by the request's own bytes, less at most the few bytes an array header can lose: re-measured below
		size -= min(size, r.size)
	}
	payload.Requests = slices.DeleteFunc(payload.Requests, func(r *drctypes.IRChangeReq) bool { return slices.Contains(dropped, r) })
	if size, err = encodedSize(p); err != nil {
		return nil, err
	}
	if size > limit {
		if len(payload.Requests) == 0 {
			return dropped, fmt.Errorf("the proposal without change requests is %d bytes, over the limit of %d", size, limit)
		}
		more, err := fitProposal(p, limit)
		return append(dropped, more...), err
	}
	return dropped, nil
}

// proposalSignatureRoom is what fitProposal leaves of abdrc.MaxProposalFrame for the proposal's signature: a signature is under 100 bytes.
// proposalControlRoom is what it leaves for the controls ordered after it (orderRejection, orderSubmittedControl, orderRetirements): at
// most drctypes.MaxPosControls fixed-shape controls, each well under a KiB (its record payload is at most 192 bytes and its witness is
// referenced by hash); TestProposalControlRoom holds the bound.
const (
	proposalSignatureRoom = 1 << 10
	proposalControlRoom   = 1 << 20
)

func encodedSize(v any) (uint64, error) {
	b, err := types.Cbor.Marshal(v)
	if err != nil {
		return 0, fmt.Errorf("encoding %T: %w", v, err)
	}
	return uint64(len(b)), nil
}
