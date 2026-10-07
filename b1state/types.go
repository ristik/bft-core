// Package b1state specifies the inactive B1 authenticated registry projection.
// Pure projection and storage fixtures do not authorize a block. Admission must
// derive entries from verified root history and bind them to a proven parent.
package b1state

import (
	"bytes"
	"errors"
	"math"
	"unicode/utf8"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

const (
	MaxMembers     = 64
	MaxNodeIDBytes = 128
	MaxEntryBytes  = 16384
	EntryWords     = 11
	MemberWords    = 8
)

var (
	ErrProfile  = errors.New("b1state: invalid or unpinned profile")
	ErrOverflow = errors.New("b1state: arithmetic overflow")
	ErrMembers  = errors.New("b1state: invalid members")
	ErrInterval = errors.New("b1state: invalid interval or coverage")
	ErrHistory  = errors.New("b1state: history or parent identity mismatch")
	ErrClock    = errors.New("b1state: nonmonotone origin")
	ErrEncoding = errors.New("b1state: noncanonical or malformed update")
	ErrBinding  = errors.New("b1state: update binding mismatch")
	ErrBudget   = errors.New("b1state: insufficient system gas")
)

type Member struct {
	NodeID string
	Key    [33]byte
	Weight uint64
}
type Entry struct {
	Epoch, BodyKind            uint64
	BodyID, ActivationCommitID [32]byte
	Start                      uint64
	End                        *uint64
	SigningScheme              uint64
	SigningConfigHash          [32]byte
	Members                    []Member
}

func (e Entry) TotalWeight() (uint64, error) {
	if len(e.Members) == 0 || len(e.Members) > MaxMembers {
		return 0, ErrMembers
	}
	var total uint64
	seen := make(map[[33]byte]bool, len(e.Members))
	for i, m := range e.Members {
		if len(m.NodeID) == 0 || len(m.NodeID) > MaxNodeIDBytes || !utf8.ValidString(m.NodeID) || (i > 0 && bytes.Compare([]byte(e.Members[i-1].NodeID), []byte(m.NodeID)) >= 0) || seen[m.Key] || m.Weight == 0 {
			return 0, ErrMembers
		}
		if _, err := ethcrypto.DecompressPubkey(m.Key[:]); err != nil {
			return 0, ErrMembers
		}
		seen[m.Key] = true
		if math.MaxUint64-total < m.Weight {
			return 0, ErrOverflow
		}
		total += m.Weight
	}
	return total, nil
}
func (e Entry) Validate() error {
	if e.BodyKind < 1 || e.BodyKind > 3 || e.BodyID == ([32]byte{}) || e.SigningConfigHash == ([32]byte{}) || (e.SigningScheme != 1 && e.SigningScheme != 2) {
		return ErrHistory
	}
	if (e.BodyKind == 1 && e.ActivationCommitID != ([32]byte{})) || (e.BodyKind != 1 && e.ActivationCommitID == ([32]byte{})) {
		return ErrHistory
	}
	if e.End != nil && *e.End <= e.Start {
		return ErrInterval
	}
	_, err := e.TotalWeight()
	return err
}
func clone(e Entry) Entry {
	e.Members = append([]Member(nil), e.Members...)
	if e.End != nil {
		v := *e.End
		e.End = &v
	}
	return e
}
func lower(origin, w uint64) uint64 {
	if origin < w {
		return 0
	}
	return origin - w
}
func Threshold(total uint64) (uint64, error) {
	if total == 0 {
		return 0, ErrMembers
	}
	return total - (total-1)/3, nil
}

// Binding names a candidate independently of Update. These are explicit model
// bindings, not an authenticated origin or a peer assertion of authority.
type Binding struct {
	ParentHash                            [32]byte
	BlockNumber, OriginEpoch, OriginRound uint64
	OriginIdentity                        [32]byte
}

func (u Update) CheckBindings(b Binding) error {
	if u.ParentHash != b.ParentHash || u.BlockNumber != b.BlockNumber || u.OriginEpoch != b.OriginEpoch || u.OriginRound != b.OriginRound || u.OriginIdentity != b.OriginIdentity {
		return ErrBinding
	}
	return nil
}
