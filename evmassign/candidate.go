package evmassign

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	"github.com/unicitynetwork/bft-go-base/types"
)

// CandidateVersion is the only encoding of an assignment-bearing candidate.
// The legacy root-only operator candidate (version 1) is unchanged.
const CandidateVersion uint64 = 2

// MaxCandidateBytes bounds the retained preimage: it is carried once in the
// freeze companion and the handoff bundle, never in the root-input D[] payload.
const MaxCandidateBytes = 256 * 1024

const candidateDomain = "UNICITY_H3_EVM_ASSIGNMENT_CANDIDATE"

// RootMember is one successor root-chain member, bound so a candidate names
// both halves of an operation even though M3 supports only one changing at a time.
type RootMember struct {
	_      struct{} `cbor:",toarray"`
	NodeID string
	Key    []byte
	Weight uint64
}

// Supersession binds a replacement of an installed, still unacknowledged
// assignment on the same frozen parent. The base is the registry assignment
// authenticated from P; the chain commits the already committed steps from
// the base up to and including SupersededH.
type Supersession struct {
	_               struct{} `cbor:",toarray"`
	SupersededH     []byte   // record ID of the latest committed H being replaced
	BaseRootEpoch   uint64   // registry assignment.rootEpoch at P
	BaseShardEpoch  uint64   // registry assignment.epoch at P
	BaseActiveHash  []byte   // registry assignment.activeConfHash at P
	ChainLen        uint64   // committed steps from the base through SupersededH
	ChainCommitment []byte   // ChainCommit over those steps
}

// Candidate is the one byte sequence fixed before root endorsements are
// collected. Its digest is the existing 32-byte candidate hash that D4's
// candidate context, and so TrustBaseBodyV2.ChangeRecordHash, binds.
type Candidate struct {
	_             struct{} `cbor:",toarray"`
	Version       uint64
	Network       uint64
	Predecessor   []byte // predecessor root BodyID
	Attempt       uint64
	Parent        []byte // frozen certified EVM block P
	RootMembers   []RootMember
	OldShardEpoch uint64
	OldActiveHash []byte // full hash of the installed configuration being replaced
	Assignment    []byte // canonical CBOR of the successor PDR, EpochStart zero
	PoPs          []PoP
	Supersedes    *Supersession
}

func (c Candidate) Encode() ([]byte, error) {
	if c.Version != CandidateVersion {
		return nil, ErrCandidate
	}
	b, err := types.Cbor.Marshal([]any{candidateDomain, c})
	if err != nil || len(b) > MaxCandidateBytes {
		return nil, ErrCandidate
	}
	return b, nil
}

// Digest is the candidate hash carried in the approval, the freeze companion
// and the D3 body's change-record context.
func (c Candidate) Digest() ([32]byte, error) {
	b, err := c.Encode()
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(b), nil
}

// DecodeCandidate accepts exactly one canonical encoding.
func DecodeCandidate(data []byte) (Candidate, error) {
	var c Candidate
	if len(data) == 0 || len(data) > MaxCandidateBytes {
		return c, ErrCandidate
	}
	var wrapper struct {
		_      struct{} `cbor:",toarray"`
		Domain string
		Body   Candidate
	}
	if err := types.Cbor.Unmarshal(data, &wrapper); err != nil || wrapper.Domain != candidateDomain {
		return c, ErrCandidate
	}
	canonical, err := wrapper.Body.Encode()
	if err != nil || !bytes.Equal(canonical, data) {
		return c, ErrCandidate
	}
	return wrapper.Body, nil
}

// Successor decodes and canonically checks the carried successor PDR.
func (c Candidate) Successor() (*types.PartitionDescriptionRecord, error) {
	var pdr types.PartitionDescriptionRecord
	if len(c.Assignment) == 0 || types.Cbor.Unmarshal(c.Assignment, &pdr) != nil {
		return nil, ErrAssignment
	}
	again, err := types.Cbor.Marshal(&pdr)
	if err != nil || !bytes.Equal(again, c.Assignment) {
		return nil, ErrAssignment
	}
	return &pdr, nil
}

// NewCandidate assembles the candidate. PoPs must already be collected: every
// successor key signs PoPMessage for this context before propose.
func NewCandidate(c PoPContext, root []RootMember, current, succ *types.PartitionDescriptionRecord,
	pops []PoP, supersedes *Supersession) (Candidate, error) {
	if err := ValidateSuccessor(current, succ); err != nil {
		return Candidate{}, err
	}
	if err := VerifyPoPs(c, succ, pops); err != nil {
		return Candidate{}, err
	}
	old, err := PDRHash(current)
	if err != nil {
		return Candidate{}, err
	}
	raw, err := types.Cbor.Marshal(succ)
	if err != nil {
		return Candidate{}, err
	}
	out := Candidate{Version: CandidateVersion, Network: c.Network, Predecessor: bytes.Clone(c.Predecessor[:]),
		Attempt: c.Attempt, Parent: bytes.Clone(c.Parent[:]), RootMembers: root, OldShardEpoch: current.Epoch,
		OldActiveHash: old[:], Assignment: raw, PoPs: pops, Supersedes: supersedes}
	if _, err := out.Encode(); err != nil {
		return Candidate{}, err
	}
	return out, nil
}

// BindingContext is what a verifier knows independently of the candidate and
// of the installed EVM configuration.
type BindingContext struct {
	PoPContext
	// CurrentRoot is the old root membership; the successor body's members must
	// equal it, because M3 refuses a combined root and EVM change.
	CurrentRoot []RootMember
	// SuccessorRoot is the member list of the successor trust-base body.
	SuccessorRoot []RootMember
	// Digest is the candidate hash the approval, companion and D3 context carry.
	Digest []byte
}

// VerifyContext adds the authenticated installed EVM configuration.
type VerifyContext struct {
	BindingContext
	// Current is the authenticated installed EVM configuration.
	Current *types.PartitionDescriptionRecord
}

func sameRoot(a, b []RootMember) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].NodeID != b[i].NodeID || a[i].Weight != b[i].Weight || !bytes.Equal(a[i].Key, b[i].Key) {
			return false
		}
	}
	return true
}

// VerifyBinding decodes the preimage and checks every binding that needs no
// EVM state: digest, root/attempt/parent context, no combined change, the
// successor assignment and a possession proof for every successor key.
func VerifyBinding(data []byte, v BindingContext) (Candidate, *types.PartitionDescriptionRecord, error) {
	c, err := DecodeCandidate(data)
	if err != nil {
		return Candidate{}, nil, err
	}
	digest := sha256.Sum256(data)
	if !bytes.Equal(digest[:], v.Digest) {
		return Candidate{}, nil, fmt.Errorf("%w: candidate digest", ErrContext)
	}
	for _, check := range []struct {
		ok   bool
		what string
	}{
		{c.Network == v.Network, "network"},
		{bytes.Equal(c.Predecessor, v.Predecessor[:]), "predecessor"},
		{c.Attempt == v.Attempt, "attempt"},
		{bytes.Equal(c.Parent, v.Parent[:]), "parent"},
	} {
		if !check.ok {
			return Candidate{}, nil, fmt.Errorf("%w: %s", ErrContext, check.what)
		}
	}
	if !sameRoot(c.RootMembers, v.SuccessorRoot) {
		return Candidate{}, nil, fmt.Errorf("%w: successor root members", ErrContext)
	}
	if !sameRoot(v.SuccessorRoot, v.CurrentRoot) {
		return Candidate{}, nil, ErrCombined
	}
	succ, err := c.Successor()
	if err != nil {
		return Candidate{}, nil, err
	}
	if err := ValidateAssignment(succ); err != nil {
		return Candidate{}, nil, err
	}
	if err := VerifyPoPs(v.PoPContext, succ, c.PoPs); err != nil {
		return Candidate{}, nil, err
	}
	if s := c.Supersedes; s != nil {
		if len(s.SupersededH) != 32 || len(s.BaseActiveHash) != 32 || len(s.ChainCommitment) != 32 ||
			s.ChainLen == 0 || s.BaseRootEpoch == 0 || s.BaseShardEpoch >= succ.Epoch-1 {
			return Candidate{}, nil, fmt.Errorf("%w: supersession shape", ErrContext)
		}
	}
	return c, succ, nil
}

// VerifyInstalled checks a bound candidate against the authenticated installed
// configuration it replaces.
func VerifyInstalled(c Candidate, succ, current *types.PartitionDescriptionRecord) error {
	if err := ValidateSuccessor(current, succ); err != nil {
		return err
	}
	old, err := PDRHash(current)
	if err != nil {
		return err
	}
	if c.OldShardEpoch != current.Epoch {
		return fmt.Errorf("%w: installed assignment epoch", ErrContext)
	}
	if !bytes.Equal(c.OldActiveHash, old[:]) {
		return fmt.Errorf("%w: installed assignment hash", ErrContext)
	}
	return nil
}

// Verify is VerifyBinding followed by VerifyInstalled.
func Verify(data []byte, v VerifyContext) (Candidate, *types.PartitionDescriptionRecord, error) {
	c, succ, err := VerifyBinding(data, v.BindingContext)
	if err != nil {
		return Candidate{}, nil, err
	}
	if err := VerifyInstalled(c, succ, v.Current); err != nil {
		return Candidate{}, nil, err
	}
	return c, succ, nil
}

// ChainCommit folds the committed handoff record IDs of a supersession chain,
// base first, into one commitment. BFT verifies every step from retained
// history before it issues the folded acknowledgement.
func ChainCommit(baseRootEpoch, baseShardEpoch uint64, baseActive []byte, steps [][]byte) ([32]byte, error) {
	if len(baseActive) != 32 || len(steps) == 0 {
		return [32]byte{}, ErrContext
	}
	acc, err := hashCBOR("UNICITY_H3_SUPERSESSION_CHAIN", uint64(1), baseRootEpoch, baseShardEpoch, baseActive)
	if err != nil {
		return acc, err
	}
	for _, id := range steps {
		if len(id) != 32 {
			return [32]byte{}, ErrContext
		}
		if acc, err = hashCBOR("UNICITY_H3_SUPERSESSION_STEP", acc[:], id); err != nil {
			return acc, err
		}
	}
	return acc, nil
}

// Provenance is what the orchestration records beside a derived configuration:
// the committed record that activated it and the candidate it came from. It is
// an index entry, never an authority; supersession verification re-reads it only
// to name the committed chain a replacement is built on.
type Provenance struct {
	_               struct{} `cbor:",toarray"`
	RecordID        []byte   // committed H record id
	CandidateDigest []byte
	RootEpoch       uint64 // successor root epoch H activates
}

func (p Provenance) Bytes() ([]byte, error) {
	if len(p.RecordID) != 32 || len(p.CandidateDigest) != 32 || p.RootEpoch < 2 {
		return nil, ErrContext
	}
	return types.Cbor.Marshal(p)
}

func DecodeProvenance(raw []byte) (Provenance, error) {
	var p Provenance
	if err := types.Cbor.Unmarshal(raw, &p); err != nil {
		return p, ErrContext
	}
	if canonical, err := p.Bytes(); err != nil || !bytes.Equal(canonical, raw) {
		return Provenance{}, ErrContext
	}
	return p, nil
}

// Chain describes the committed, still unacknowledged assignment steps of one
// shard, oldest first, and the acknowledged base they extend.
type Chain struct {
	BaseRootEpoch  uint64
	BaseShardEpoch uint64
	BaseActiveHash []byte
	Steps          []ChainStep
}

// ChainStep is one committed handoff in a Chain.
type ChainStep struct {
	ShardEpoch      uint64
	ConfHash        []byte
	RecordID        []byte
	CandidateDigest []byte
	RootEpoch       uint64
}

// Commitment is ChainCommit over the steps' record identifiers.
func (c Chain) Commitment() ([32]byte, error) {
	ids := make([][]byte, 0, len(c.Steps))
	for _, s := range c.Steps {
		ids = append(ids, s.RecordID)
	}
	return ChainCommit(c.BaseRootEpoch, c.BaseShardEpoch, c.BaseActiveHash, ids)
}

// Supersession returns the candidate field binding this chain: the latest
// committed H it replaces and the acknowledged base it extends.
func (c Chain) Supersession() (*Supersession, error) {
	if len(c.Steps) == 0 {
		return nil, ErrContext
	}
	commit, err := c.Commitment()
	if err != nil {
		return nil, err
	}
	return &Supersession{SupersededH: bytes.Clone(c.Steps[len(c.Steps)-1].RecordID), BaseRootEpoch: c.BaseRootEpoch,
		BaseShardEpoch: c.BaseShardEpoch, BaseActiveHash: bytes.Clone(c.BaseActiveHash), ChainLen: uint64(len(c.Steps)),
		ChainCommitment: commit[:]}, nil
}

// VerifyChain checks a candidate's supersession binding against the chain read
// from the verifier's own committed history.
func VerifyChain(s *Supersession, c Chain) error {
	want, err := c.Supersession()
	if err != nil {
		return err
	}
	if s == nil || !bytes.Equal(s.SupersededH, want.SupersededH) || s.BaseRootEpoch != want.BaseRootEpoch ||
		s.BaseShardEpoch != want.BaseShardEpoch || !bytes.Equal(s.BaseActiveHash, want.BaseActiveHash) ||
		s.ChainLen != want.ChainLen || !bytes.Equal(s.ChainCommitment, want.ChainCommitment) {
		return fmt.Errorf("%w: supersession differs from the committed chain", ErrContext)
	}
	return nil
}
