package vrschema

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-go-base/types"
)

// CandidateV6Version is the candidate version in VR mode.
const CandidateV6Version uint64 = 6

// candidateDomain is evmassign's candidate domain, unchanged.
const candidateDomain = "UNICITY_H3_EVM_ASSIGNMENT_CANDIDATE"

// RegistryChange is one bound VR change in candidate v6, with the root-derived verdict.
type RegistryChange struct {
	_       struct{} `cbor:",toarray"`
	ID      uint64   `json:"id"`
	Kind    uint64   `json:"kind"`
	Payload []byte   `json:"payload"`
	Verdict uint64   `json:"verdict"`
}

// CandidateV6 is candidate v5 (evmassign.Candidate, field for field and in the same order) with Version 6, SourceRef the 32-byte VR
// resultId, Changes empty (encoded as CBOR null: the aggregator changes are derived from the Accepted RegistryChanges at verification,
// so payloads appear only once), and RegistryChanges appended as the twentieth field.
type CandidateV6 struct {
	_                  struct{} `cbor:",toarray"`
	Version            uint64
	Kind               uint64
	Network            uint64
	Predecessor        []byte
	Attempt            uint64
	RootMembers        []evmassign.RootMember
	OldShardEpoch      uint64
	OldActiveHash      []byte
	Assignment         []byte
	PoPs               []evmassign.PoP
	Supersedes         *evmassign.Supersession
	Bindings           []evmassign.Binding
	Identities         []evmassign.Identity
	Authorization      *evmassign.Authorization
	ReplacedAssignment []byte
	Changes            []evmassign.Change
	SourceRef          []byte
	RegistryChanges    []RegistryChange
}

// DerivedChangeKind maps a VR root-side kind to the evmassign candidate change kind it is derived into.
var DerivedChangeKind = map[uint8]uint64{KindReplaceAggregator: 1, KindAddPartition: 2, KindUpdatePartition: 3}

// CheckRegistryChanges is the stateless shape of the RegistryChanges list: strictly ascending ids, at most 16 entries, at most 8
// root-side, total payload at most 64 KiB, each payload at most 16 KiB, a bindable kind (never ModuleAction), a defined root verdict,
// at most one entry of each singleton kind, and EVM-side and membership kinds (1, 3, 4, 5, 10) Accepted.
func CheckRegistryChanges(rc []RegistryChange) error {
	if len(rc) > MaxBoundTotal {
		return fmt.Errorf("%w: %d registry changes", ErrOversize, len(rc))
	}
	root, total := 0, 0
	seen := map[uint64]bool{}
	for i, c := range rc {
		if i > 0 && rc[i-1].ID >= c.ID {
			return ErrOrder
		}
		if c.ID == 0 || c.Kind == 0 || c.Kind > uint64(KindForceRemove) || c.Kind == uint64(KindModuleAction) {
			return fmt.Errorf("%w: change kind %d", ErrUnknownKind, c.Kind)
		}
		k := uint8(c.Kind)
		if c.Verdict > uint64(VerdictCeiling) {
			return fmt.Errorf("%w: verdict %d", ErrRange, c.Verdict)
		}
		switch k {
		case KindSetModule, KindSetGovernor, KindCommitteeLimits, KindFeeParams, KindForceRemove:
			if c.Verdict != uint64(VerdictAccepted) {
				return fmt.Errorf("%w: kind %d must be Accepted", ErrRange, k)
			}
		}
		if Singleton(k) {
			if seen[c.Kind] {
				return fmt.Errorf("%w: second singleton kind %d", ErrRange, k)
			}
			seen[c.Kind] = true
		}
		if len(c.Payload) > MaxChangePayload {
			return ErrOversize
		}
		total += len(c.Payload)
		if RootSide(k) {
			root++
		}
	}
	if root > MaxBoundRootSide || total > MaxBoundPayload {
		return fmt.Errorf("%w: binding bounds", ErrOversize)
	}
	return nil
}

// RejectedBitmap is the Boundary bitmap: bit i set iff the i-th entry is not Accepted.
func RejectedBitmap(rc []RegistryChange) uint16 {
	var b uint16
	for i, c := range rc {
		if c.Verdict != uint64(VerdictAccepted) {
			b |= 1 << uint(i)
		}
	}
	return b
}

// ChangesDigestOf is the VR changesDigest of the list (id, kind, keccak256(payload)).
func ChangesDigestOf(rc []RegistryChange) (Word, error) {
	bc := make([]BoundChange, 0, len(rc))
	for _, c := range rc {
		bc = append(bc, BoundChange{ID: c.ID, Kind: uint8(c.Kind), PayloadHash: PayloadHash(c.Payload)})
	}
	return ChangesDigest(bc)
}

// Encode is the canonical CBOR [domain, candidate]; only the v6-specific shape is checked here (VT-05a adds the v5 lifecycle checks).
func (c CandidateV6) Encode() ([]byte, error) {
	if c.Version != CandidateV6Version || len(c.SourceRef) != 32 || isZero(c.SourceRef) || c.Changes != nil {
		return nil, fmt.Errorf("%w: candidate v6 shape", ErrCanonical)
	}
	if err := CheckRegistryChanges(c.RegistryChanges); err != nil {
		return nil, err
	}
	if c.RegistryChanges == nil {
		c.RegistryChanges = []RegistryChange{}
	}
	b, err := types.Cbor.Marshal([]any{candidateDomain, c})
	if err != nil {
		return nil, err
	}
	if len(b) > MaxCandidateBytes {
		return nil, ErrOversize
	}
	return b, nil
}

// Digest is SHA-256 of Encode, the candidate digest.
func (c CandidateV6) Digest() ([32]byte, error) {
	b, err := c.Encode()
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(b), nil
}

// DecodeCandidateV6 accepts exactly the canonical encoding.
func DecodeCandidateV6(data []byte) (CandidateV6, error) {
	var w struct {
		_      struct{} `cbor:",toarray"`
		Domain string
		Body   CandidateV6
	}
	if len(data) == 0 || len(data) > MaxCandidateBytes {
		return CandidateV6{}, ErrLength
	}
	if err := types.Cbor.Unmarshal(data, &w); err != nil || w.Domain != candidateDomain {
		return CandidateV6{}, ErrCanonical
	}
	again, err := w.Body.Encode()
	if err != nil {
		return CandidateV6{}, err
	}
	if !bytes.Equal(again, data) {
		return CandidateV6{}, ErrCanonical
	}
	return w.Body, nil
}
