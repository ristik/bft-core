package vrschema

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-go-base/types"
)

// The certified handoff-PoP miss (#1319, astra ruling option (a)). The predecessor roots commit a PoPRequest for one intent (control op 6):
// it binds the network, the predecessor, the result, the attempt, the frozen roster and a cutoff in root progress. After the cutoff each old
// root may sign, per requested member whose valid PoP it lacked then, a domain-separated MissStatement. A MissCertificate gathers the
// statements of one member; it counts when its signers reach the ordinary commit quorum by weight of the entire predecessor committee.
// Certificates ride on an Expired RejectResult v2 and project record kind 9 (PoPMissed). They attest quorum non-receipt by a deadline, never
// misconduct: network delay can still certify an honest member, so the only consequence is a fixed election park.

// Domains of the request digest and the miss statement.
const (
	PoPRequestDomain = "UNICITY_VR_POP_REQUEST"
	PoPMissDomain    = "UNICITY_VR_POP_MISS"
)

// MaxMissCertificates bounds the certificates of one RejectResult: one per roster member.
const MaxMissCertificates = MaxCommittee

// ErrPoPMiss reports a request, statement or certificate that is malformed or does not verify.
var ErrPoPMiss = errors.New("vrschema: invalid handoff-PoP miss")

// PoPRequest is the committed request of one intent: the roster is the intent's successor members by ascending staking id (VR's member
// order), Deadline the cutoff in root canonical progress, Epoch the root epoch that committed it.
type PoPRequest struct {
	_           struct{} `cbor:",toarray"`
	Epoch       uint64
	Network     uint64
	Predecessor []byte // 32 bytes: the authority's body identity
	ResultID    []byte // 32 bytes
	Attempt     uint64
	Roster      []uint64 // strictly ascending staking ids, 1..16
	Deadline    uint64
	Intent      []byte // 32 bytes: the intent digest the PoPs name
}

// Check is the request's shape.
func (r PoPRequest) Check() error {
	if !len32(r.Predecessor, r.ResultID, r.Intent) || isZero(r.ResultID) || isZero(r.Intent) || len(r.Roster) == 0 || len(r.Roster) > MaxCommittee {
		return fmt.Errorf("%w: request shape", ErrPoPMiss)
	}
	for i := 1; i < len(r.Roster); i++ {
		if r.Roster[i-1] >= r.Roster[i] {
			return fmt.Errorf("%w: the roster is not strictly ascending", ErrPoPMiss)
		}
	}
	return nil
}

// Digest is SHA-256(CBOR(["UNICITY_VR_POP_REQUEST", 1, network, predecessor, resultID, attempt, roster, deadline, intentDigest])): what every
// miss statement names. The epoch is bound through the predecessor.
func (r PoPRequest) Digest() ([32]byte, error) {
	if err := r.Check(); err != nil {
		return [32]byte{}, err
	}
	b, err := types.Cbor.Marshal([]any{PoPRequestDomain, uint64(1), r.Network, r.Predecessor, r.ResultID, r.Attempt, r.Roster, r.Deadline, r.Intent})
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(b), nil
}

// Index is the roster position of a staking id.
func (r PoPRequest) Index(id uint64) (int, bool) {
	for i, x := range r.Roster {
		if x == id {
			return i, true
		}
	}
	return 0, false
}

// StakingIDU64 is a 32-byte big-endian staking id as the u64 the contracts and records name it by.
func StakingIDU64(b []byte) (uint64, bool) {
	if len(b) != 32 || !isZero(b[:24]) {
		return 0, false
	}
	var v uint64
	for _, x := range b[24:] {
		v = v<<8 | uint64(x)
	}
	return v, true
}

// RosterOf is the request roster of a candidate's identities (ascending staking id): their u64 ids.
func RosterOf(stakingIDs [][]byte) ([]uint64, error) {
	out := make([]uint64, 0, len(stakingIDs))
	for _, b := range stakingIDs {
		v, ok := StakingIDU64(b)
		if !ok {
			return nil, fmt.Errorf("%w: a staking id beyond 64 bits", ErrPoPMiss)
		}
		out = append(out, v)
	}
	return out, nil
}

// MissStatementBytes is CBOR(["UNICITY_VR_POP_MISS", 1, requestDigest, stakingID]), signed by an old root's root key.
func MissStatementBytes(request [32]byte, stakingID uint64) ([]byte, error) {
	return types.Cbor.Marshal([]any{PoPMissDomain, uint64(1), request[:], stakingID})
}

// MissStatement is one root's signed statement that it lacked a requested member's valid PoP at the request's cutoff.
type MissStatement struct {
	_         struct{} `cbor:",toarray"`
	Request   []byte   `json:"request"` // the request digest
	StakingID uint64   `json:"stakingId"`
	Signer    string   `json:"signer"` // the root node id
	Sig       []byte   `json:"sig"`
}

// SignedBytes is the statement's signed message.
func (m MissStatement) SignedBytes() ([]byte, error) {
	if !len32(m.Request) || m.Signer == "" {
		return nil, fmt.Errorf("%w: statement shape", ErrPoPMiss)
	}
	return MissStatementBytes([32]byte(m.Request), m.StakingID)
}

// MissSig is one signer's signature in a certificate.
type MissSig struct {
	_      struct{} `cbor:",toarray"`
	NodeID string
	Sig    []byte
}

// MissCertificate is the statements of one member: [stakingID, [[nodeID, sig]]], the signatures strictly ascending by node id.
type MissCertificate struct {
	_         struct{} `cbor:",toarray"`
	StakingID uint64
	Sigs      []MissSig
}

// CheckMissCertificates is the stateless shape of a certificate list: 1..16 certificates strictly ascending by staking id, each with at least
// one signature, strictly ascending by node id, each 65 bytes.
func CheckMissCertificates(cs []MissCertificate) error {
	if len(cs) == 0 || len(cs) > MaxMissCertificates {
		return fmt.Errorf("%w: %d certificates", ErrPoPMiss, len(cs))
	}
	for i, c := range cs {
		if i > 0 && cs[i-1].StakingID >= c.StakingID {
			return fmt.Errorf("%w: certificates not strictly ascending by staking id", ErrPoPMiss)
		}
		if len(c.Sigs) == 0 || len(c.Sigs) > 64 {
			return fmt.Errorf("%w: certificate %d carries %d signatures", ErrPoPMiss, i, len(c.Sigs))
		}
		for k, s := range c.Sigs {
			if s.NodeID == "" || len(s.Sig) != 65 {
				return fmt.Errorf("%w: certificate %d signature %d shape", ErrPoPMiss, i, k)
			}
			if k > 0 && c.Sigs[k-1].NodeID >= s.NodeID {
				return fmt.Errorf("%w: certificate %d signatures not strictly ascending by node id", ErrPoPMiss, i)
			}
		}
	}
	return nil
}

// CommitteeMember is one member of the predecessor root committee: its node id, root key and weight.
type CommitteeMember struct {
	NodeID string
	Key    []byte
	Weight uint64
}

// VerifyMissCertificates judges certificates against a committed request and the entire predecessor committee: every staking id is in
// the roster, every signer a distinct committee member whose signature over this request's statement verifies, and each certificate's
// signer weight reaches threshold (the ordinary commit quorum of the whole committee). It returns the missed bitmap, bit i the i-th roster
// member. Each certificate stands alone: a member without one is simply not certified.
func VerifyMissCertificates(r PoPRequest, cs []MissCertificate, committee []CommitteeMember, threshold uint64) (uint16, error) {
	if err := CheckMissCertificates(cs); err != nil {
		return 0, err
	}
	digest, err := r.Digest()
	if err != nil {
		return 0, err
	}
	if threshold == 0 {
		return 0, fmt.Errorf("%w: no quorum threshold", ErrPoPMiss)
	}
	byID := map[string]CommitteeMember{}
	for _, m := range committee {
		byID[m.NodeID] = m
	}
	var bitmap uint16
	for _, c := range cs {
		i, ok := r.Index(c.StakingID)
		if !ok {
			return 0, fmt.Errorf("%w: staking id %d is not in the request's roster", ErrPoPMiss, c.StakingID)
		}
		msg, err := MissStatementBytes(digest, c.StakingID)
		if err != nil {
			return 0, err
		}
		var weight uint64
		for _, s := range c.Sigs {
			m, ok := byID[s.NodeID]
			if !ok {
				return 0, fmt.Errorf("%w: %s is not a member of the predecessor committee", ErrPoPMiss, s.NodeID)
			}
			if err := Verify(m.Key, s.Sig, msg); err != nil {
				return 0, fmt.Errorf("%w: %s's statement on %d: %w", ErrPoPMiss, s.NodeID, c.StakingID, err)
			}
			if weight+m.Weight < weight {
				return 0, fmt.Errorf("%w: weight overflow", ErrPoPMiss)
			}
			weight += m.Weight
		}
		if weight < threshold {
			return 0, fmt.Errorf("%w: the miss of %d is signed by weight %d, below the quorum %d", ErrPoPMiss, c.StakingID, weight, threshold)
		}
		bitmap |= 1 << i
	}
	return bitmap, nil
}

// EncodeMissCertificates is the canonical CBOR of a certificate list.
func EncodeMissCertificates(cs []MissCertificate) ([]byte, error) {
	if err := CheckMissCertificates(cs); err != nil {
		return nil, err
	}
	return types.Cbor.Marshal(cs)
}

// DecodeMissCertificates accepts exactly the canonical encoding.
func DecodeMissCertificates(b []byte) ([]MissCertificate, error) {
	var cs []MissCertificate
	if err := types.Cbor.Unmarshal(b, &cs); err != nil {
		return nil, fmt.Errorf("%w: certificates encoding", ErrPoPMiss)
	}
	again, err := EncodeMissCertificates(cs)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(again, b) {
		return nil, fmt.Errorf("%w: certificates not canonical", ErrPoPMiss)
	}
	return cs, nil
}
