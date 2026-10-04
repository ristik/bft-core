package leader

import (
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"sync"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/unicitynetwork/bft-go-base/types"

	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
)

var (
	// ErrNoMembers is returned for an empty committee.
	ErrNoMembers = errors.New("weighted leader: no members")
	// ErrInvalidMember is returned for a nil member, a node ID that is not a peer ID, or a peer ID in a non-canonical encoding.
	ErrInvalidMember = errors.New("weighted leader: invalid member")
	// ErrDuplicateMember is returned when two members decode to the same peer ID, however they are encoded.
	ErrDuplicateMember = errors.New("weighted leader: duplicate member")
	// ErrInvalidWeight is returned for a member whose weight is zero.
	ErrInvalidWeight = errors.New("weighted leader: invalid weight")
	// ErrInvalidStart is returned for an epoch start round of zero.
	ErrInvalidStart = errors.New("weighted leader: invalid epoch start")
	// ErrBeforeStart is returned for a round below the epoch start; the schedule has no position for it.
	ErrBeforeStart = errors.New("weighted leader: round precedes the epoch start")
)

// recentRounds is the number of most recent rounds whose leader is answered from the ring without a replay.
const recentRounds = 8

// Weighted is the fixed-epoch weighted proposer selector of policy root-wrr-v1: proposer priority over the epoch's members
// (the CometBFT scheme without its changing-set normalization), reset to zero at the epoch start.
//
// Priorities are zero immediately before the start round A*. For each round from A* on, every member's priority grows by its
// weight, the member with the greatest priority leads (ties: the smallest canonical node ID string) and total weight W is
// subtracted from the leader's priority. Every traversed round consumes a schedule position whether or not it produced a
// block; a repeated query consumes none. The inputs are the committee and the start round only: no QC, signer set, reputation,
// reachability or clock changes the schedule, and Update/UpdateWithTrustBase are no-ops. A new epoch builds a new Weighted.
//
// Arithmetic is exact (math/big). A query for a round d rounds past the cached one costs O(n·d) and a query below the ring
// replays from the epoch start in scratch state; the caller must authenticate the round before asking.
type Weighted struct {
	start   uint64
	members []peer.ID  // canonical order: node ID string ascending
	weights []*big.Int // immutable after construction
	total   *big.Int

	mu     sync.Mutex
	last   uint64     // the round the cached priorities are after; start-1 before any selection
	prio   []*big.Int // priorities after the selection of round last
	recent [recentRounds]recentLeader
}

type recentLeader struct {
	round  uint64
	member int
	valid  bool
}

// NewWeighted builds the selector from the epoch start round and the committee; NodeInfo.Stake is the weight. The input is
// copied. It returns a deterministic error for an empty or duplicate committee, a node ID that is not a peer ID, a zero weight
// or a zero start; there is no fallback to another selection.
func NewWeighted(start uint64, nodes []*types.NodeInfo) (*Weighted, error) {
	if start == 0 {
		return nil, ErrInvalidStart
	}
	if len(nodes) == 0 {
		return nil, ErrNoMembers
	}
	for _, n := range nodes {
		if n == nil {
			return nil, fmt.Errorf("%w: nil member", ErrInvalidMember)
		}
	}
	// Identity is the DECODED peer ID: peer.Decode accepts several encodings of one peer (the base58 form and the libp2p-key
	// CID form), so strings alone neither detect a duplicate nor give one ordering. Duplicates are refused on the decoded ID,
	// and only the canonical encoding of an ID is a valid NodeID (the trust base looks signers up by that string).
	type entry struct {
		id peer.ID
		n  *types.NodeInfo
	}
	ordered := make([]entry, len(nodes))
	seen := make(map[peer.ID]string, len(nodes))
	for i, n := range nodes {
		id, err := peer.Decode(n.NodeID)
		if err != nil {
			return nil, fmt.Errorf("%w: %q: %w", ErrInvalidMember, n.NodeID, err)
		}
		if first, dup := seen[id]; dup {
			return nil, fmt.Errorf("%w: %q and %q are the same peer", ErrDuplicateMember, first, n.NodeID)
		}
		seen[id] = n.NodeID
		ordered[i] = entry{id, n}
	}
	for _, e := range ordered {
		if canonical := e.id.String(); e.n.NodeID != canonical {
			return nil, fmt.Errorf("%w: %q is not the canonical encoding %q", ErrInvalidMember, e.n.NodeID, canonical)
		}
	}
	slices.SortFunc(ordered, func(a, b entry) int { return strings.Compare(a.id.String(), b.id.String()) })
	w := &Weighted{start: start, total: new(big.Int), last: start - 1}
	for _, e := range ordered {
		if e.n.Stake == 0 {
			return nil, fmt.Errorf("%w: %q has weight 0", ErrInvalidWeight, e.n.NodeID)
		}
		weight := new(big.Int).SetUint64(e.n.Stake)
		w.members = append(w.members, e.id)
		w.weights = append(w.weights, weight)
		w.total.Add(w.total, weight)
	}
	w.prio = zeroPriorities(len(w.members))
	return w, nil
}

func zeroPriorities(n int) []*big.Int {
	p := make([]*big.Int, n)
	for i := range p {
		p[i] = new(big.Int)
	}
	return p
}

// step consumes one schedule position: priorities grow by the weights, the maximum (smallest index on a tie) leads and loses W.
func (w *Weighted) step(prio []*big.Int) int {
	winner := 0
	for i := range prio {
		prio[i].Add(prio[i], w.weights[i])
		if prio[i].Cmp(prio[winner]) > 0 {
			winner = i
		}
	}
	prio[winner].Sub(prio[winner], w.total)
	return winner
}

// GetLeaderForRound returns the leader of the round from the schedule of this epoch.
func (w *Weighted) GetLeaderForRound(round uint64) (peer.ID, error) {
	if round < w.start {
		return "", fmt.Errorf("%w: round %d, start %d", ErrBeforeStart, round, w.start)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if e := w.recent[round%recentRounds]; e.valid && e.round == round {
		return w.members[e.member], nil
	}
	if round > w.last {
		for w.last < round {
			w.last++
			w.recent[w.last%recentRounds] = recentLeader{round: w.last, member: w.step(w.prio), valid: true}
		}
		return w.members[w.recent[round%recentRounds].member], nil
	}
	// older than the ring: replay in scratch state, the cache is never rewound
	scratch := zeroPriorities(len(w.members))
	winner := 0
	for r := w.start; ; r++ {
		winner = w.step(scratch)
		if r == round {
			break
		}
	}
	return w.members[winner], nil
}

// Update is a no-op: a QC, its signers or the current round must not change an epoch's schedule.
func (w *Weighted) Update(*rctypes.QuorumCert, uint64, BlockLoader) error { return nil }

// UpdateWithTrustBase is a no-op: a successor epoch installs a new selector.
func (w *Weighted) UpdateWithTrustBase(types.RootTrustBase, uint64) error { return nil }
