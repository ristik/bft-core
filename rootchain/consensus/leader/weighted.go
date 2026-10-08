package leader

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/internal/weightcap"
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
	// ErrTooManyMembers is returned for a committee above weightcap.MaxMembers.
	ErrTooManyMembers = errors.New("weighted leader: too many members")
	// ErrWeightBound is returned for a member weight or a total committed weight above weightcap.B; it is refused before any table is allocated.
	ErrWeightBound = errors.New("weighted leader: committed weight above the profile bound")
	// ErrPeriod is returned if the schedule did not close after one period; the period proof makes it unreachable.
	ErrPeriod = errors.New("weighted leader: schedule did not close after one period")
	// ErrInvalidStart is returned for an epoch start round of zero.
	ErrInvalidStart = errors.New("weighted leader: invalid epoch start")
	// ErrBeforeStart is returned for a round below the epoch start; the schedule has no position for it.
	ErrBeforeStart = errors.New("weighted leader: round precedes the epoch start")
)

// Weighted is the fixed-epoch weighted proposer selector of policy root-wrr-v1: proposer priority over the epoch's members
// (the CometBFT scheme without its changing-set normalization), reset to zero at the epoch start.
//
// Priorities are zero immediately before the start round A*. For each slot from A* on, every member's priority grows by its
// weight, the member with the greatest priority leads (ties: the smallest canonical node ID string) and total weight W is
// subtracted from the leader's priority. Every traversed round consumes a schedule position whether or not it produced a
// block. The inputs are the committee and the start round only: no QC, signer set, reputation, reachability or clock changes the
// schedule, and Update/UpdateWithTrustBase are no-ops. A new epoch builds a new Weighted.
//
// The schedule is periodic. With p(t) the priorities after t selections, p_i(t) = t*w_i - W*N_i(t) and the sum is zero; every p_i
// stays above -W, so at t = W/gcd(w) every p_i is a multiple of W above -W with sum zero, hence zero, and the sequence repeats
// exactly (briefs/leader-lookup.md). The selector therefore holds one immutable period table of winner indices, built once at
// construction from zero in at most n*B steps, and a lookup is table[(r-A*) mod P]: O(1), read-only, allocation-free and
// independent of the distance to the round, of any cache and of the epoch's age. Total weight is bounded by weightcap.B, so the
// table is at most 64 KiB and priorities fit in int64 (|p| <= n*W).
type Weighted struct {
	start   uint64
	members []peer.ID // canonical order: node ID string ascending
	table   []uint8   // winner member index of slot k of one period, P = W/gcd(weights) entries
}

// NewWeighted builds the selector from the epoch start round and the committee; NodeInfo.Stake is the weight. The input is
// copied. It returns a deterministic error for an empty or duplicate committee, a committee above weightcap.MaxMembers, a node ID
// that is not a peer ID, a zero weight, a total above weightcap.B or a zero start; there is no fallback to another selection and
// nothing is allocated for the table before the bounds hold.
func NewWeighted(start uint64, nodes []*types.NodeInfo) (*Weighted, error) {
	if start == 0 {
		return nil, ErrInvalidStart
	}
	if len(nodes) == 0 {
		return nil, ErrNoMembers
	}
	if len(nodes) > weightcap.MaxMembers {
		return nil, fmt.Errorf("%w: %d members, limit %d", ErrTooManyMembers, len(nodes), weightcap.MaxMembers)
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
	w := &Weighted{start: start}
	weights := make([]int64, len(ordered))
	var total, g uint64
	for i, e := range ordered {
		if e.n.Stake == 0 {
			return nil, fmt.Errorf("%w: %q has weight 0", ErrInvalidWeight, e.n.NodeID)
		}
		// each weight is checked before it is summed: with n <= MaxMembers and a member <= B the sum cannot overflow
		if e.n.Stake > weightcap.B {
			return nil, fmt.Errorf("%w: %q has weight %d, limit %d", ErrWeightBound, e.n.NodeID, e.n.Stake, weightcap.B)
		}
		total += e.n.Stake
		if total > weightcap.B {
			return nil, fmt.Errorf("%w: total weight above %d", ErrWeightBound, weightcap.B)
		}
		w.members = append(w.members, e.id)
		weights[i] = int64(e.n.Stake)
		g = gcd(g, e.n.Stake)
	}
	period := total / g
	w.table = make([]uint8, period)
	prio := make([]int64, len(weights))
	for k := range w.table {
		// step: priorities grow by the weights, the maximum (smallest index on a tie) leads and loses W. Each component is updated
		// before it is compared with the already updated current winner, and the winner changes only on a strictly greater value.
		winner := 0
		for i := range prio {
			prio[i] += weights[i]
			if prio[i] > prio[winner] {
				winner = i
			}
		}
		prio[winner] -= int64(total)
		w.table[k] = uint8(winner)
	}
	for _, p := range prio {
		if p != 0 { // the period proof makes this unreachable; a table that did not close would be a wrong schedule
			return nil, fmt.Errorf("%w: priorities are not zero after %d steps", ErrPeriod, period)
		}
	}
	return w, nil
}

func gcd(a, b uint64) uint64 {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}

// Period is the length of the schedule's period in rounds, W/gcd(weights).
func (w *Weighted) Period() uint64 { return uint64(len(w.table)) }

// GetLeaderForRound returns the leader of the round from the schedule of this epoch. It is read-only, allocation-free and takes the
// same time for every round at or after the epoch start, including math.MaxUint64.
func (w *Weighted) GetLeaderForRound(round uint64) (peer.ID, error) {
	if round < w.start {
		return "", fmt.Errorf("%w: round %d, start %d", ErrBeforeStart, round, w.start)
	}
	return w.members[w.table[(round-w.start)%uint64(len(w.table))]], nil
}

// Update is a no-op: a QC, its signers or the current round must not change an epoch's schedule.
func (w *Weighted) Update(*rctypes.QuorumCert, uint64, BlockLoader) error { return nil }

// UpdateWithTrustBase is a no-op: a successor epoch installs a new selector.
func (w *Weighted) UpdateWithTrustBase(types.RootTrustBase, uint64) error { return nil }
