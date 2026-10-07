// Package evmassign defines the H3 successor EVM assignment carried by a root
// handoff candidate: the canonical assignment, proof of possession (PoP) for
// every successor signing key, and the candidate byte sequence that the root
// endorsement binds through D4CandidateContextHash.
//
// Hash order is assignment hash -> PoPs -> candidate digest -> change-record
// hash. No preimage contains its enclosing BodyID, FrozenID or a regenerated
// genesis identity. Design: docs/design/h3-evm-assignment.md.
package evmassign

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"sort"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"
)

var (
	ErrAssignment = errors.New("evmassign: invalid successor assignment")
	ErrConfig     = errors.New("evmassign: non-membership configuration changed")
	ErrEpoch      = errors.New("evmassign: invalid assignment epoch")
	ErrValidators = errors.New("evmassign: invalid validator set")
	ErrPoP        = errors.New("evmassign: invalid proof of possession")
	ErrCandidate  = errors.New("evmassign: invalid candidate")
	// ErrCoupling reports a candidate whose root entities and EVM participants are not one coupled set: validator-set
	// changes are always coupled, one root committee member to one delegated EVM key with the same weight.
	ErrCoupling = errors.New("evmassign: root entities and EVM participants are not a coupled set")
	// ErrEVMOnly refuses an EVM validator-set change while the root committee is unchanged. A configuration-only boundary
	// that keeps both halves identical stays valid.
	ErrEVMOnly = errors.New("evmassign: EVM-only validator change is unsupported; root and EVM change together")
	ErrContext = errors.New("evmassign: candidate context mismatch")
)

// CouplingParam is the EVM shard configuration parameter that makes validator-set changes always coupled: with
// validator_coupling=true no handoff may change the root committee without the matching delegated EVM assignment. It is part of
// the committed (hashed) configuration, so every root validator evaluates the same rule, and it survives assignment changes.
const CouplingParam = "validator_coupling"

// CouplingRequired reports whether the installed EVM configuration demands coupled committee changes.
func CouplingRequired(pdr *types.PartitionDescriptionRecord) bool {
	return pdr != nil && pdr.PartitionParams[CouplingParam] == "true"
}

// SameCommittee reports whether two root committees are identical (ids, keys, weights; both in candidate order).
func SameCommittee(a, b []RootMember) bool { return sameRoot(a, b) }

// EVMPartitionTypeID identifies the designated EVM partition type. Its
// configuration changes only through a committed root handoff.
const EVMPartitionTypeID types.PartitionTypeID = 8

const (
	// MaxValidators bounds the successor set so the candidate stays far below
	// the 1 MiB freeze companion limit.
	MaxValidators = 64
	// KeyLen is the compressed secp256k1 signing key width.
	KeyLen = 33

	assignmentDomain = "UNICITY_H3_EVM_ASSIGNMENT"
	popDomain        = "UNICITY_H3_EVM_ASSIGNMENT_POP"
	// PoPDomain is the domain tag of the possession message. Signers that refuse generic signing (the signing authority) require
	// a request to name it before they sign exactly this message for their own key.
	PoPDomain = popDomain
)

func hashCBOR(v ...any) ([32]byte, error) {
	b, err := types.Cbor.Marshal(v)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(b), nil
}

// ConfigHash commits to every non-membership setting of the shard
// configuration, including the immutable seal_registry_genesis section. It
// ignores exactly the validator list, the shard epoch and the activation round.
func ConfigHash(pdr *types.PartitionDescriptionRecord) ([32]byte, error) {
	if pdr == nil {
		return [32]byte{}, ErrAssignment
	}
	c := *pdr
	c.Validators, c.Epoch, c.EpochStart = nil, 0, 0
	h, err := c.Hash(crypto.SHA256)
	if err != nil || len(h) != 32 {
		return [32]byte{}, ErrAssignment
	}
	var out [32]byte
	copy(out[:], h)
	return out, nil
}

// PDRHash is the full configuration hash a certificate commits to.
func PDRHash(pdr *types.PartitionDescriptionRecord) ([32]byte, error) {
	var out [32]byte
	if pdr == nil {
		return out, ErrAssignment
	}
	h, err := pdr.Hash(crypto.SHA256)
	if err != nil || len(h) != 32 {
		return out, ErrAssignment
	}
	copy(out[:], h)
	return out, nil
}

// NewSuccessor builds the canonical successor of current: every setting is
// copied, the epoch advances by one, the validators are replaced and sorted.
// EpochStart is zero until the committed activation boundary is known.
func NewSuccessor(current *types.PartitionDescriptionRecord, validators []*types.NodeInfo) (*types.PartitionDescriptionRecord, error) {
	if current == nil || current.Epoch == math.MaxUint64 {
		return nil, ErrEpoch
	}
	raw, err := types.Cbor.Marshal(current)
	if err != nil {
		return nil, err
	}
	var next types.PartitionDescriptionRecord
	if err := types.Cbor.Unmarshal(raw, &next); err != nil {
		return nil, err
	}
	next.Epoch, next.EpochStart = current.Epoch+1, 0
	next.Validators = make([]*types.NodeInfo, 0, len(validators))
	for _, v := range validators {
		if v == nil {
			return nil, ErrValidators
		}
		next.Validators = append(next.Validators, &types.NodeInfo{NodeID: v.NodeID, SigKey: bytes.Clone(v.SigKey), Stake: v.Stake})
	}
	sort.Slice(next.Validators, func(i, j int) bool { return next.Validators[i].NodeID < next.Validators[j].NodeID })
	return &next, nil
}

// ValidateSet checks the successor validator set: strictly ordered unique node
// identities, unique valid 33-byte keys, unit weights, bounded size.
func ValidateSet(validators []*types.NodeInfo) error {
	if len(validators) == 0 || len(validators) > MaxValidators {
		return fmt.Errorf("%w: %d validators", ErrValidators, len(validators))
	}
	keys := make(map[string]struct{}, len(validators))
	for i, v := range validators {
		if v == nil || v.NodeID == "" || v.Stake != 1 || len(v.SigKey) != KeyLen {
			return fmt.Errorf("%w: validator %d", ErrValidators, i)
		}
		if _, err := abcrypto.NewVerifierSecp256k1(v.SigKey); err != nil {
			return fmt.Errorf("%w: validator %q key: %v", ErrValidators, v.NodeID, err)
		}
		if i > 0 && validators[i-1].NodeID >= v.NodeID {
			return fmt.Errorf("%w: validators are not strictly ordered by node identity", ErrValidators)
		}
		if _, dup := keys[string(v.SigKey)]; dup {
			return fmt.Errorf("%w: key shared by two validators", ErrValidators)
		}
		keys[string(v.SigKey)] = struct{}{}
	}
	return nil
}

// Rules is the validator weight rule set a successor EVM assignment is checked under. The zero choice, UnitRules, is the legacy
// unit-weight world; a coupled Q3 activation passes the weighted rules (weightvalidation.EVMRules), which this package cannot
// import. Aggregator replacements never take weights and always use UnitRules.
type Rules interface {
	// PDR is the validity of the whole partition description, its validator set included.
	PDR(*types.PartitionDescriptionRecord) error
	// Set is the validity of the validator set alone: bounded size, strict order, valid unique keys and the weight rule.
	Set([]*types.NodeInfo) error
}

type unitRules struct{}

func (unitRules) PDR(p *types.PartitionDescriptionRecord) error { return p.IsValid() }
func (unitRules) Set(v []*types.NodeInfo) error                 { return ValidateSet(v) }

// UnitRules is the unit-weight rule set.
var UnitRules Rules = unitRules{}

// ValidateAssignment checks what depends on the successor alone: a valid PDR
// with no activation round and a well-formed unit-weight validator set.
func ValidateAssignment(succ *types.PartitionDescriptionRecord) error {
	return ValidateAssignmentWith(UnitRules, succ)
}

// ValidateAssignmentWith is ValidateAssignment under the rules r.
func ValidateAssignmentWith(r Rules, succ *types.PartitionDescriptionRecord) error {
	if succ == nil {
		return ErrAssignment
	}
	if err := r.PDR(succ); err != nil {
		return fmt.Errorf("%w: %w", ErrAssignment, err)
	}
	if succ.EpochStart != 0 {
		return fmt.Errorf("%w: activation round is set before commit", ErrEpoch)
	}
	return r.Set(succ.Validators)
}

// ValidateSuccessor checks succ against the currently installed configuration:
// identical in every non-membership setting, epoch+1, EpochStart unset.
func ValidateSuccessor(current, succ *types.PartitionDescriptionRecord) error {
	return ValidateSuccessorWith(UnitRules, current, succ)
}

// ValidateSuccessorWith is ValidateSuccessor under the rules r.
func ValidateSuccessorWith(r Rules, current, succ *types.PartitionDescriptionRecord) error {
	if current == nil || succ == nil {
		return ErrAssignment
	}
	if err := r.PDR(succ); err != nil {
		return fmt.Errorf("%w: %w", ErrAssignment, err)
	}
	if current.Epoch == math.MaxUint64 || succ.Epoch != current.Epoch+1 || succ.EpochStart != 0 {
		return ErrEpoch
	}
	a, err := ConfigHash(current)
	if err != nil {
		return err
	}
	b, err := ConfigHash(succ)
	if err != nil || a != b {
		return ErrConfig
	}
	return r.Set(succ.Validators)
}

// AssignmentHash binds network/partition/shard, the new shard epoch, the sorted
// validator identities with keys and unit weights, and the non-membership
// configuration hash. PoPs are outside it, avoiding a cycle.
func AssignmentHash(succ *types.PartitionDescriptionRecord) ([32]byte, error) {
	if succ == nil {
		return [32]byte{}, ErrAssignment
	}
	cfg, err := ConfigHash(succ)
	if err != nil {
		return [32]byte{}, err
	}
	set := make([]any, 0, len(succ.Validators))
	for _, v := range succ.Validators {
		set = append(set, []any{v.NodeID, []byte(v.SigKey), v.Stake})
	}
	return hashCBOR(assignmentDomain, uint64(1), uint64(succ.NetworkID), uint64(succ.PartitionID),
		succ.ShardID.Bytes(), succ.Epoch, set, cfg[:])
}

// Activate returns the configuration the root installs at the committed
// activation boundary: the assignment with EpochStart set to that round.
func Activate(succ *types.PartitionDescriptionRecord, activation uint64) (*types.PartitionDescriptionRecord, error) {
	if succ == nil || succ.EpochStart != 0 || activation == 0 {
		return nil, ErrAssignment
	}
	raw, err := types.Cbor.Marshal(succ)
	if err != nil {
		return nil, err
	}
	var out types.PartitionDescriptionRecord
	if err := types.Cbor.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	out.EpochStart = activation
	return &out, nil
}

// PoPContext is everything a possession signature is bound to besides the
// assignment itself: the root predecessor and the attempt. The frozen EVM parent is deliberately NOT part of it: the root binds the
// parent at the Prepare record, after possession proofs are collected, and the Freeze record's FrozenID commits to it.
type PoPContext struct {
	Network     uint64
	Predecessor [32]byte
	Attempt     uint64
}

// PoPMessage is the domain-separated canonical message signed by one successor key.
func PoPMessage(c PoPContext, succ *types.PartitionDescriptionRecord, nodeID string) ([]byte, error) {
	h, err := AssignmentHash(succ)
	if err != nil {
		return nil, err
	}
	return types.Cbor.Marshal([]any{popDomain, uint64(1), c.Network, uint64(succ.PartitionID), succ.ShardID.Bytes(),
		h[:], c.Predecessor[:], c.Attempt, nodeID})
}

// PoP is the possession evidence for one successor validator.
type PoP struct {
	_         struct{}  `cbor:",toarray"`
	NodeID    string    `json:"nodeId"`
	Key       hex.Bytes `json:"key"`
	Signature hex.Bytes `json:"signature"`
}

// Proposal is the operator's input for an EVM-only rotation: the successor
// validators and one possession proof per successor key. Local configuration
// confers no authority; every field is re-verified by each endorser and again
// at block admission.
type Proposal struct {
	Validators []*types.NodeInfo `json:"validators"`
	PoPs       []PoP             `json:"pops"`
	// Supersede asks to replace the installed assignment, which has no
	// certified acknowledgement, on the same frozen parent.
	Supersede bool `json:"supersede,omitempty"`
	// Bindings couple each successor root member to its delegated EVM validator (same weight, distinct keys).
	Bindings []Binding `json:"bindings"`
	// Changes are aggregator validator (node-key) replacements committed in the same handoff; each is a ReplaceShardValidators.
	Changes []Change `json:"changes,omitempty"`
}

// SignPoP signs the possession message with the successor key itself.
func SignPoP(signer abcrypto.Signer, c PoPContext, succ *types.PartitionDescriptionRecord, nodeID string) (PoP, error) {
	v, err := signer.Verifier()
	if err != nil {
		return PoP{}, err
	}
	key, err := v.MarshalPublicKey()
	if err != nil {
		return PoP{}, err
	}
	msg, err := PoPMessage(c, succ, nodeID)
	if err != nil {
		return PoP{}, err
	}
	sig, err := signer.SignBytes(msg)
	if err != nil {
		return PoP{}, err
	}
	return PoP{NodeID: nodeID, Key: key, Signature: sig}, nil
}

// VerifyPoPs requires exactly one valid possession proof per successor
// validator, in validator order, by the validator's own key. Retained keys are
// not exempt.
func VerifyPoPs(c PoPContext, succ *types.PartitionDescriptionRecord, pops []PoP) error {
	if succ == nil || len(pops) != len(succ.Validators) {
		return fmt.Errorf("%w: %d proofs for %d validators", ErrPoP, len(pops), lenValidators(succ))
	}
	for i, v := range succ.Validators {
		p := pops[i]
		if p.NodeID != v.NodeID || !bytes.Equal(p.Key, v.SigKey) || len(p.Signature) != ethcrypto.SignatureLength {
			return fmt.Errorf("%w: proof %d does not name validator %q", ErrPoP, i, v.NodeID)
		}
		ver, err := abcrypto.NewVerifierSecp256k1(v.SigKey)
		if err != nil {
			return fmt.Errorf("%w: validator %q key", ErrPoP, v.NodeID)
		}
		msg, err := PoPMessage(c, succ, v.NodeID)
		if err != nil {
			return err
		}
		if err := ver.VerifyBytes(p.Signature, msg); err != nil {
			return fmt.Errorf("%w: validator %q: %v", ErrPoP, v.NodeID, err)
		}
		// The recovery byte is ignored by verification; require it to recover the
		// key so a signature has exactly one accepted encoding.
		digest := sha256.Sum256(msg)
		if pub, err := ethcrypto.SigToPub(digest[:], p.Signature); err != nil ||
			!bytes.Equal(ethcrypto.CompressPubkey(pub), v.SigKey) {
			return fmt.Errorf("%w: validator %q: non-canonical recovery byte", ErrPoP, v.NodeID)
		}
	}
	return nil
}

func lenValidators(p *types.PartitionDescriptionRecord) int {
	if p == nil {
		return 0
	}
	return len(p.Validators)
}
