package storage

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"slices"

	"github.com/unicitynetwork/bft-go-base/types"
)

// LeaderStateDomain separates the digest of the leader-state leaf from every other value of the unicity tree.
const LeaderStateDomain = "unicity/root-leader-state/v1"

var (
	// ErrHistoryUnavailable is the committed state not covering a cutoff yet: nobody has to have the history, so it is neither an empty
	// history nor a reason for state recovery (#886 B2). The node has no leader for the round and times it out (B1).
	ErrHistoryUnavailable = errors.New("leader history is not committed yet")
	// ErrHistoryRefused is a cutoff below the retained coverage: an obsolete lookup, refused rather than answered differently.
	ErrHistoryRefused = errors.New("leader history below the retained coverage")
	// ErrLeaderState is a leader-state leaf that breaks the transition rule's invariants.
	ErrLeaderState = errors.New("invalid leader state")
)

// LeaderRecord is one committed carrier's participation sample: the block's round and the voters of the QC it carries, as a bitmap over
// the committee's canonical order. Voters is empty for a block with no ordinary QC to sample: the epoch's coverage floor and its first
// ordinary block.
type LeaderRecord struct {
	_      struct{} `cbor:",toarray"`
	Round  uint64
	Voters []byte
}

// LeaderState is the bounded ring of the authenticated leader-state leaf (#886 S1). Execution derives it, the state root binds it, and
// every root reads the committed head's ring, so compatible committed heads answer the same for every covered cutoff.
type LeaderState struct {
	_       struct{} `cbor:",toarray"`
	Genesis []byte
	Epoch   uint64
	Start   uint64 // A, the epoch's first ordinary round
	Lag     uint64 // D, the history lag; the transition rule's eviction distance
	Members uint64 // n, the committee's size; a bitmap has exactly this many meaningful bits
	Records []LeaderRecord
}

// LeaderLag is D = 4n+4, checked. It must exceed the recovery run, which holds for every n >= 1.
func LeaderLag(members uint64) (uint64, error) {
	if members == 0 || members > (math.MaxUint64-4)/4 {
		return 0, fmt.Errorf("%w: %d members", ErrLeaderState, members)
	}
	return 4*members + 4, nil
}

// NewLeaderState is the ring of the epoch's first ordinary block, whose round is first: the floor at the anchor slot and the block's own
// record, neither with a sample. Rounds timed out between them leave no record, so identical genesis after different old suffixes and
// different first-child rounds still gives one bootstrap.
func NewLeaderState(genesis []byte, epoch, start, members, first uint64) (*LeaderState, error) {
	lag, err := LeaderLag(members)
	if err != nil {
		return nil, err
	}
	if len(genesis) != sha256.Size || start == 0 || first < start {
		return nil, fmt.Errorf("%w: genesis of %d bytes, start %d, first block %d", ErrLeaderState, len(genesis), start, first)
	}
	return &LeaderState{Genesis: bytes.Clone(genesis), Epoch: epoch, Start: start, Lag: lag, Members: members,
		Records: []LeaderRecord{{Round: start - 1}, {Round: first}}}, nil
}

// Clone is an independent copy: a child's ring never shares records with its parent's, which forks and the frozen suffix read.
func (s *LeaderState) Clone() *LeaderState {
	if s == nil {
		return nil
	}
	c := *s
	c.Genesis = bytes.Clone(s.Genesis)
	c.Records = make([]LeaderRecord, len(s.Records))
	for i, r := range s.Records {
		c.Records[i] = LeaderRecord{Round: r.Round, Voters: bytes.Clone(r.Voters)}
	}
	return &c
}

// Next is the ring of a child block executed at round: the parent's, the child's record appended, then everything older than the newest
// record at or below round-Lag evicted. It leaves the parent untouched. The frozen suffix of a closed epoch does not call it (see
// extendWithAuthority): those blocks must keep the closing block's root.
func (s *LeaderState) Next(round uint64, voters []byte) (*LeaderState, error) {
	if err := s.Valid(); err != nil {
		return nil, err
	}
	if round <= s.Records[len(s.Records)-1].Round {
		return nil, fmt.Errorf("%w: round %d does not follow %d", ErrLeaderState, round, s.Records[len(s.Records)-1].Round)
	}
	if err := checkLeaderBitmap(voters, s.Members); err != nil {
		return nil, err
	}
	next := s.Clone()
	next.Records = append(next.Records, LeaderRecord{Round: round, Voters: bytes.Clone(voters)})
	if round >= s.Lag {
		keep := 0
		for i, r := range next.Records {
			if r.Round <= round-s.Lag {
				keep = i
			}
		}
		next.Records = slices.Delete(next.Records, 0, keep)
	}
	return next, nil
}

// Valid checks what no transition can produce: rounds strictly increasing from a floor, no more than D+2 records (one per numeric round
// above the newest record at or below head-D), and canonical bitmaps. A sample in the floor record is allowed: eviction makes any record
// the floor. Quorum needs the committee, so the selector checks it.
func (s *LeaderState) Valid() error {
	if s == nil || len(s.Genesis) != sha256.Size || s.Start == 0 || len(s.Records) == 0 {
		return ErrLeaderState
	}
	lag, err := LeaderLag(s.Members)
	if err != nil || lag != s.Lag {
		return fmt.Errorf("%w: lag %d of %d members", ErrLeaderState, s.Lag, s.Members)
	}
	if uint64(len(s.Records)) > s.Lag+2 {
		return fmt.Errorf("%w: %d records, limit %d", ErrLeaderState, len(s.Records), s.Lag+2)
	}
	for i, r := range s.Records {
		if i > 0 && r.Round <= s.Records[i-1].Round {
			return fmt.Errorf("%w: rounds not increasing at %d", ErrLeaderState, r.Round)
		}
		if err := checkLeaderBitmap(r.Voters, s.Members); err != nil {
			return err
		}
	}
	return nil
}

func checkLeaderBitmap(voters []byte, members uint64) error {
	if len(voters) == 0 {
		return nil
	}
	if uint64(len(voters)) != (members+7)/8 {
		return fmt.Errorf("%w: bitmap of %d bytes for %d members", ErrLeaderState, len(voters), members)
	}
	if extra := members % 8; extra != 0 && voters[len(voters)-1]>>extra != 0 {
		return fmt.Errorf("%w: bitmap bits above the committee", ErrLeaderState)
	}
	return nil
}

// Select returns the voters of the newest sample at or before cutoff in this ring, read as the committed head at head: nil voters with no
// error is a covered prefix with no sample (the full committee). A ring of a sealed epoch (sealed: the closing block's control state is
// terminal, so no further sample can exist) answers every cutoff at or above its last record from that record; an unsealed one answers
// only up to its head, ErrHistoryUnavailable above it. Below the floor it is ErrHistoryRefused.
func (s *LeaderState) Select(cutoff, head uint64, sealed bool) ([]byte, error) {
	if err := s.Valid(); err != nil {
		return nil, err
	}
	if !sealed && cutoff > head {
		return nil, fmt.Errorf("%w: cutoff %d, committed head %d", ErrHistoryUnavailable, cutoff, head)
	}
	if cutoff < s.Records[0].Round {
		return nil, fmt.Errorf("%w: cutoff %d, floor %d", ErrHistoryRefused, cutoff, s.Records[0].Round)
	}
	for i := len(s.Records) - 1; i >= 0; i-- {
		if s.Records[i].Round <= cutoff && len(s.Records[i].Voters) != 0 {
			return s.Records[i].Voters, nil
		}
	}
	return nil, nil
}

// Digest is the leaf's value in the unicity tree.
func (s *LeaderState) Digest() ([]byte, error) {
	if err := s.Valid(); err != nil {
		return nil, err
	}
	data, err := types.Cbor.Marshal([]any{LeaderStateDomain, s})
	if err != nil {
		return nil, fmt.Errorf("encoding the leader state: %w", err)
	}
	sum := sha256.Sum256(data)
	return sum[:], nil
}

// LeaderBitmap maps a verified QC's signers to a bitmap over the committee, given in canonical order. A signer outside the committee
// cannot pass QC verification, so it is refused rather than dropped, and an empty signer set is not a sample.
func LeaderBitmap(committee []string, signers []string) ([]byte, error) {
	if len(signers) == 0 {
		return nil, fmt.Errorf("%w: a QC with no signers", ErrLeaderState)
	}
	bitmap := make([]byte, (len(committee)+7)/8)
	for _, signer := range signers {
		i, found := slices.BinarySearch(committee, signer)
		if !found {
			return nil, fmt.Errorf("%w: signer %q is not a member", ErrLeaderState, signer)
		}
		bitmap[i/8] |= 1 << (i % 8)
	}
	return bitmap, nil
}
