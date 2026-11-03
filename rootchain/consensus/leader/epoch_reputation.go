package leader

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"sync"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/unicitynetwork/bft-go-base/types"

	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
)

const (
	// RecoveryRun is L, the consecutive rounds of one member's recovery run: enough for the commit chain of three leaders and for a
	// retained request arriving during its first slot.
	RecoveryRun = 4
	// RecoverySpacing is S, the rounds between the starts of two recovery runs (briefs/886-leader-schedule-design.md).
	RecoverySpacing = 256
	// activeTableCache bounds the weighted tables kept for active sets; a table is pure, so an evicted one is rebuilt with the same answer.
	activeTableCache = 16
)

// ErrInvalidSample is a committed participation sample that cannot define an active set: below the quorum weight, or empty.
var ErrInvalidSample = errors.New("leader: invalid participation sample")

// LeaderHead is what a lookup reads: the committed head's round, its leader-state ring (nil when the head has none) and whether its
// control state is terminal, so that its epoch can take no further sample.
type LeaderHead struct {
	Round  uint64
	State  *rctypes.LeaderState
	Sealed bool
}

// EpochReputation is the selector of policy root-reputation-v1 (#886). It is a pure function of the authenticated epoch (genesis, number,
// first round, committee and quorum), the round and the committed head's ring: two honest nodes that return a leader for one epoch and
// round return the same one, and a node without enough committed state returns ErrHistoryUnavailable. Nothing a node observes locally
// changes an answer, and Update does nothing: missing history must not reach the paths that treat an Update error as corruption.
type EpochReputation struct {
	genesis   []byte
	epoch     uint64
	start     uint64 // A
	lag       uint64 // D, also the bootstrap length B
	quorum    uint64
	nodes     []*types.NodeInfo // canonical order
	members   []peer.ID
	bootstrap *Weighted
	head      func() (LeaderHead, error)

	mu     sync.Mutex
	active map[string]*Weighted
}

// NewEpochReputation builds the selector. head reads the manager's current committed head; it is called for every normal-round lookup.
func NewEpochReputation(genesis []byte, epoch, start, quorum uint64, nodes []*types.NodeInfo, head func() (LeaderHead, error)) (*EpochReputation, error) {
	if head == nil || quorum == 0 || len(genesis) != sha256.Size {
		return nil, fmt.Errorf("%w: no committed head or quorum, or a genesis of %d bytes", ErrInvalidSample, len(genesis))
	}
	bootstrap, err := NewWeighted(start, nodes) // refuses an invalid committee or start: nothing below repeats it
	if err != nil {
		return nil, err
	}
	lag, err := rctypes.LeaderLag(uint64(len(nodes)))
	if err != nil {
		return nil, err
	}
	if lag <= RecoveryRun || RecoverySpacing <= RecoveryRun || start > math.MaxUint64-lag {
		return nil, fmt.Errorf("%w: lag %d, run %d, spacing %d, start %d", ErrInvalidStart, lag, RecoveryRun, RecoverySpacing, start)
	}
	ordered := slices.Clone(nodes)
	slices.SortFunc(ordered, func(a, b *types.NodeInfo) int { return strings.Compare(a.NodeID, b.NodeID) })
	members := make([]peer.ID, len(ordered))
	for i, n := range ordered {
		if members[i], err = peer.Decode(n.NodeID); err != nil {
			return nil, fmt.Errorf("%w: %q: %w", ErrInvalidMember, n.NodeID, err)
		}
	}
	return &EpochReputation{genesis: bytes.Clone(genesis), epoch: epoch, start: start, lag: lag, quorum: quorum, nodes: ordered, members: members,
		bootstrap: bootstrap, head: head, active: make(map[string]*Weighted)}, nil
}

// recoveryMember returns the recovery member of a round after the bootstrap and whether the round is in a recovery run: the last L rounds
// of each S-round period, so a period's first S-L rounds are normal and there is no initial sweep. Leadership in a run is unconditional:
// making it depend on a node's history would make a leader depend on local availability.
func (e *EpochReputation) recoveryMember(round uint64) (peer.ID, bool) {
	t := round - e.start - e.lag
	if t%RecoverySpacing < RecoverySpacing-RecoveryRun {
		return "", false
	}
	return e.members[(t/RecoverySpacing)%uint64(len(e.members))], true
}

// GetLeaderForRound returns the round's leader, or ErrHistoryUnavailable (no leader yet: the caller times the round out, never recovers
// because of it) or ErrHistoryRefused (an obsolete lookup below the coverage).
func (e *EpochReputation) GetLeaderForRound(round uint64) (peer.ID, error) {
	if round < e.start {
		return "", fmt.Errorf("%w: round %d, start %d", ErrBeforeStart, round, e.start)
	}
	if round-e.start < e.lag { // A <= r < A+B; timed-out rounds count toward B
		return e.bootstrap.GetLeaderForRound(round)
	}
	if member, ok := e.recoveryMember(round); ok {
		return member, nil
	}
	head, err := e.head()
	if err != nil {
		return "", err
	}
	cutoff := round - e.lag
	// A ring of another epoch is not history (the installed anchor keeps the outgoing root, ring and terminal control state): every cutoff
	// here is at or above A, above that head, and unavailable until this epoch's first child commits.
	if head.State == nil || head.State.Epoch != e.epoch || !bytes.Equal(head.State.Genesis, e.genesis) {
		return "", fmt.Errorf("%w: cutoff %d, committed head %d holds no history of epoch %d", rctypes.ErrHistoryUnavailable, cutoff, head.Round, e.epoch)
	}
	if head.State.Members != uint64(len(e.nodes)) || head.State.Start != e.start {
		return "", fmt.Errorf("%w: ring of %d members from round %d, committee of %d from round %d", ErrInvalidSample, head.State.Members, head.State.Start, len(e.nodes), e.start)
	}
	voters, err := head.State.Select(cutoff, head.Round, head.Sealed)
	if err != nil {
		return "", err
	}
	table, err := e.table(voters)
	if err != nil {
		return "", err
	}
	return table.GetLeaderForRound(round)
}

// table is the weighted table of an active set: the voters with their original weights from zero priorities at A, whatever other sets the
// rounds before used. Nil voters is the full committee.
func (e *EpochReputation) table(voters []byte) (*Weighted, error) {
	if voters == nil {
		return e.bootstrap, nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if t, ok := e.active[string(voters)]; ok {
		return t, nil
	}
	var active []*types.NodeInfo
	var weight uint64
	for i, n := range e.nodes {
		if voters[i/8]&(1<<(i%8)) != 0 {
			active = append(active, n)
			weight += n.Stake
		}
	}
	if weight < e.quorum {
		return nil, fmt.Errorf("%w: weight %d of quorum %d", ErrInvalidSample, weight, e.quorum)
	}
	t, err := NewWeighted(e.start, active)
	if err != nil {
		return nil, err
	}
	if len(e.active) >= activeTableCache {
		clear(e.active)
	}
	e.active[string(voters)] = t
	return t, nil
}

// Update does nothing: the schedule has no per-round election, and a missing cutoff belongs to GetLeaderForRound. It must not return
// ErrHistoryUnavailable, which the recovery path would latch as corruption.
func (e *EpochReputation) Update(*rctypes.QuorumCert, uint64, BlockLoader) error { return nil }

// UpdateWithTrustBase does nothing: a verified installation builds the next epoch's selector.
func (e *EpochReputation) UpdateWithTrustBase(types.RootTrustBase, uint64) error { return nil }
