package storage

import (
	"bytes"
	"crypto"
	"errors"
	"math"
	"sort"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/internal/quorumweight"
	"github.com/unicitynetwork/bft-core/trustactivation"
	"github.com/unicitynetwork/bft-core/trusthistorystore"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"
)

// FreezeAuthorization is a block-local companion to an ordered freeze record.
// It is outside the record ID, but inside the signed proposal and block hash.
type FreezeAuthorization struct {
	_          struct{} `cbor:",toarray"`
	Version    uint64
	Body       []byte // canonical D3 TrustBaseBodyV2 encoding
	Parent     []byte // frozen certified EVM block hash
	Candidate  []byte // candidate hash used by the D3 context and FrozenID
	Signatures map[string]hex.Bytes
}

func (a FreezeAuthorization) Bytes() ([]byte, error) { return types.Cbor.Marshal(a) }

// FreezeAssignmentAuthorization is the version-2 freeze companion. It carries
// the H3 candidate preimage once, so every voter and the retained handoff
// bundle can verify the successor EVM assignment and its possession proofs.
type FreezeAssignmentAuthorization struct {
	_          struct{} `cbor:",toarray"`
	Version    uint64
	Body       []byte
	Parent     []byte
	Candidate  []byte // digest of Preimage
	Preimage   []byte // canonical evmassign.Candidate
	Signatures map[string]hex.Bytes
}

func (a FreezeAssignmentAuthorization) Bytes() ([]byte, error) { return types.Cbor.Marshal(a) }

// FreezeCompanion is the decoded form of either companion version.
type FreezeCompanion struct {
	Version    uint64
	Body       []byte
	Parent     []byte
	Candidate  []byte
	Preimage   []byte // nil for the legacy root-only companion
	Signatures map[string]hex.Bytes
}

// ParseFreezeCompanion accepts exactly one canonical encoding of version 1
// (root-only) or version 2 (assignment-bearing).
func ParseFreezeCompanion(raw []byte) (FreezeCompanion, error) {
	var out FreezeCompanion
	if !validFreezeCompanionSize(len(raw)) {
		return out, ErrHandoffRecord
	}
	var shape []any
	if err := types.Cbor.Unmarshal(raw, &shape); err != nil || len(shape) == 0 {
		return out, ErrHandoffRecord
	}
	switch version, _ := shape[0].(uint64); version {
	case 1:
		var v FreezeAuthorization
		if err := types.Cbor.Unmarshal(raw, &v); err != nil || len(v.Signatures) == 0 {
			return out, ErrHandoffRecord
		}
		if canonical, err := v.Bytes(); err != nil || !bytes.Equal(canonical, raw) {
			return out, ErrHandoffRecord
		}
		return FreezeCompanion{Version: 1, Body: v.Body, Parent: v.Parent, Candidate: v.Candidate, Signatures: v.Signatures}, nil
	case 2:
		var v FreezeAssignmentAuthorization
		if err := types.Cbor.Unmarshal(raw, &v); err != nil || len(v.Signatures) == 0 || len(v.Preimage) == 0 {
			return out, ErrHandoffRecord
		}
		if canonical, err := v.Bytes(); err != nil || !bytes.Equal(canonical, raw) {
			return out, ErrHandoffRecord
		}
		return FreezeCompanion{Version: 2, Body: v.Body, Parent: v.Parent, Candidate: v.Candidate, Preimage: v.Preimage, Signatures: v.Signatures}, nil
	}
	return out, ErrHandoffRecord
}

// AbortAuthorization is the block-local old-set quorum proof for an abort.
type AbortAuthorization struct {
	_          struct{} `cbor:",toarray"`
	Version    uint64
	Signatures map[string]hex.Bytes
}

func (a AbortAuthorization) Bytes() ([]byte, error) { return types.Cbor.Marshal(a) }

// EndorsementBytes uses D4's old-set endorsement domain and fixes all fields
// known at freeze. The signatures do not enter the ordered record ID.
func EndorsementBytes(r evmroot.OrderedHandoffRecord) ([]byte, error) {
	return types.Cbor.Marshal([]any{"UNICITY_D4_ENDORSEMENT", uint64(1), r.Network, r.Epoch,
		r.PredecessorBodyID, r.Attempt, r.NextBodyID, r.FrozenID})
}

// AbortEndorsementBytes binds an abort quorum to its authority and attempt.
func AbortEndorsementBytes(r evmroot.OrderedHandoffRecord) ([]byte, error) {
	return types.Cbor.Marshal([]any{"UNICITY_D4_ENDORSEMENT", uint64(1), r.Network, r.Epoch,
		r.PredecessorBodyID, r.Attempt, "abort"})
}

type v1HandoffAuthority struct {
	trust       *types.RootTrustBaseV1
	predecessor []byte
	link        []byte
}

// ConfigureHandoffAuthority installs the independently authenticated old v1
// body before profile-2 records can execute.
func (x *BlockStore) ConfigureHandoffAuthority(tb *types.RootTrustBaseV1) error {
	if x.profile != ProfileHandoff || tb == nil || tb.Epoch != 1 {
		return ErrHandoffRecord
	}
	raw, err := types.Cbor.Marshal(tb)
	if err != nil {
		return err
	}
	var owned types.RootTrustBaseV1
	if err := types.Cbor.Unmarshal(raw, &owned); err != nil {
		return err
	}
	if err := owned.Verify(nil); err != nil {
		return errors.Join(ErrHandoffRecord, err)
	}
	predecessor, err := owned.Hash(crypto.SHA256)
	if err != nil {
		return err
	}
	link, err := evmroot.FirstV2PredecessorHash(evmroot.V1Anchor{Version: 1,
		NetworkID: uint64(owned.NetworkID), Epoch: owned.Epoch, HashIncludingSigs: predecessor})
	if err != nil {
		return err
	}
	x.handoffAuth = &v1HandoffAuthority{trust: &owned, predecessor: predecessor, link: link}
	return nil
}

// ConfigureHandoffV2Authority takes the predecessor from verified trust
// history. A runtime projection is only a signature-verification view; its
// hash is never the D4 predecessor identity for a later handoff.
func (x *BlockStore) ConfigureHandoffV2Authority(tb *types.RootTrustBaseV1, prior trusthistorystore.Record) error {
	if x.profile != ProfileHandoff || tb == nil || prior.V2 == nil || prior.V1 != nil ||
		prior.Epoch < 2 || prior.Epoch != tb.Epoch || prior.V2.Epoch != prior.Epoch ||
		prior.V2.NetworkID != uint64(tb.NetworkID) || prior.BodyID != prior.V2.Identity() {
		return ErrHandoffRecord
	}
	projection, err := trustactivation.Project(prior)
	if err != nil || projection.EpochStart != tb.EpochStart || projection.QuorumThreshold != tb.QuorumThreshold ||
		len(projection.RootNodes) != len(tb.RootNodes) {
		return ErrHandoffRecord
	}
	for _, node := range projection.RootNodes {
		if node == nil {
			return ErrHandoffRecord
		}
		found := false
		for _, actual := range tb.RootNodes {
			if actual != nil && actual.NodeID == node.NodeID && actual.Stake == node.Stake && bytes.Equal(actual.SigKey, node.SigKey) {
				found = true
				break
			}
		}
		if !found {
			return ErrHandoffRecord
		}
	}
	predecessor := bytes.Clone(prior.BodyID[:])
	x.handoffAuth = &v1HandoffAuthority{trust: projection, predecessor: predecessor, link: predecessor}
	return nil
}

func (a *v1HandoffAuthority) Predecessor() []byte { return a.predecessor }

func validFreezeCompanionSize(n int) bool { return n > 0 && n <= 1<<20 }

func (a *v1HandoffAuthority) VerifyFreeze(r evmroot.OrderedHandoffRecord, companion []byte) ([]byte, error) {
	if !validFreezeCompanionSize(len(companion)) || r.Epoch != a.trust.Epoch ||
		r.Network != uint64(a.trust.NetworkID) || len(r.FrozenID) != 32 || bytes.Equal(r.FrozenID, make([]byte, 32)) ||
		!bytes.Equal(r.PredecessorBodyID, a.predecessor) {
		return nil, ErrHandoffRecord
	}
	proof, err := ParseFreezeCompanion(companion)
	if err != nil {
		return nil, ErrHandoffRecord
	}
	body, err := decodeD3Body(proof.Body)
	if err != nil || r.Epoch == math.MaxUint64 || body.NetworkID != r.Network || body.Epoch != r.Epoch+1 ||
		body.EarliestActivation == 0 || body.EarliestActivation > r.ActivationRound || !bytes.Equal(body.PredecessorHash, a.link) {
		return nil, ErrHandoffRecord
	}
	if len(proof.Parent) != 32 || bytes.Equal(proof.Parent, make([]byte, 32)) || len(proof.Candidate) != 32 ||
		!bytes.Equal(body.ChangeRecordHash, evmroot.D4CandidateContextHash(r.Network, r.PredecessorBodyID, r.Attempt, proof.Candidate, body.EarliestActivation)) ||
		!bytes.Equal(r.FrozenID, evmroot.D4FrozenID(r.NextBodyID, body.StateSummary, proof.Parent, proof.Candidate, r.Attempt, r.PredecessorBodyID)) {
		return nil, ErrHandoffRecord
	}
	for _, member := range body.Members {
		if member.Weight != 1 {
			return nil, ErrHandoffRecord
		}
	}
	if proof.Version == 2 {
		if err := a.verifyAssignmentBinding(r, proof, body); err != nil {
			return nil, err
		}
	}
	id := body.Identity()
	if !bytes.Equal(id[:], r.NextBodyID) {
		return nil, ErrHandoffRecord
	}
	message, err := EndorsementBytes(r)
	if err != nil {
		return nil, ErrHandoffRecord
	}
	if err := a.verifyQuorum(message, proof.Signatures); err != nil {
		return nil, ErrHandoffRecord
	}
	return bytes.Clone(proof.Parent), nil
}

// verifyAssignmentBinding checks everything about an H3 candidate that needs
// no EVM state: its digest, the exact root/attempt/parent context, that the
// root entities and EVM participants form one coupled set, and a possession
// proof for every successor key. State-dependent checks run in block execution.
func (a *v1HandoffAuthority) verifyAssignmentBinding(r evmroot.OrderedHandoffRecord, proof FreezeCompanion, body evmroot.TrustBaseBodyV2) error {
	ctx := evmassign.BindingContext{Digest: proof.Candidate, ControlPartition: evmroot.D4ControlPartition,
		PoPContext: evmassign.PoPContext{Network: r.Network, Attempt: r.Attempt}}
	if len(r.PredecessorBodyID) != 32 {
		return ErrHandoffRecord
	}
	copy(ctx.Predecessor[:], r.PredecessorBodyID)
	for _, m := range body.Members {
		ctx.SuccessorRoot = append(ctx.SuccessorRoot, evmassign.RootMember{NodeID: m.NodeID, Key: m.ConsensusKey, Weight: m.Weight})
	}
	if _, _, err := evmassign.VerifyBinding(proof.Preimage, ctx); err != nil {
		return errors.Join(ErrHandoffRecord, err)
	}
	return nil
}

// CurrentRoot is the old root committee in candidate order, for the EVM-only refusal at freeze admission.
func (a *v1HandoffAuthority) CurrentRoot() []evmassign.RootMember {
	out := make([]evmassign.RootMember, 0, len(a.trust.RootNodes))
	for _, n := range a.trust.RootNodes {
		if n == nil {
			return nil // fail closed: the callers refuse a missing committee
		}
		out = append(out, evmassign.RootMember{NodeID: n.NodeID, Key: n.SigKey, Weight: n.Stake})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NodeID < out[j].NodeID })
	return out
}

func (a *v1HandoffAuthority) VerifyAbort(r evmroot.OrderedHandoffRecord, companion []byte) error {
	if len(companion) == 0 || len(companion) > 1<<20 || r.Epoch != a.trust.Epoch ||
		r.Network != uint64(a.trust.NetworkID) || !bytes.Equal(r.PredecessorBodyID, a.predecessor) {
		return ErrHandoffRecord
	}
	var proof AbortAuthorization
	if err := types.Cbor.Unmarshal(companion, &proof); err != nil || proof.Version != 1 || len(proof.Signatures) == 0 {
		return ErrHandoffRecord
	}
	canonical, err := proof.Bytes()
	if err != nil || !bytes.Equal(canonical, companion) {
		return ErrHandoffRecord
	}
	message, err := AbortEndorsementBytes(r)
	if err != nil || a.verifyQuorum(message, proof.Signatures) != nil {
		return ErrHandoffRecord
	}
	return nil
}

func (a *v1HandoffAuthority) verifyQuorum(message []byte, signatures map[string]hex.Bytes) error {
	if _, err := quorumweight.VerifySigned(a.trust, message, signatures); err != nil {
		return ErrHandoffRecord
	}
	return nil
}

func decodeD3Body(raw []byte) (evmroot.TrustBaseBodyV2, error) {
	var body evmroot.TrustBaseBodyV2
	if len(raw) == 0 || len(raw) > 1<<20 {
		return body, ErrHandoffRecord
	}
	var fields []any
	if err := types.Cbor.Unmarshal(raw, &fields); err != nil || len(fields) != 9 {
		return body, ErrHandoffRecord
	}
	var ok bool
	if body.Version, ok = fields[0].(uint64); !ok {
		return body, ErrHandoffRecord
	}
	if body.NetworkID, ok = fields[1].(uint64); !ok {
		return body, ErrHandoffRecord
	}
	if body.Epoch, ok = fields[2].(uint64); !ok {
		return body, ErrHandoffRecord
	}
	if body.EarliestActivation, ok = fields[3].(uint64); !ok {
		return body, ErrHandoffRecord
	}
	members, ok := fields[4].([]any)
	if !ok {
		return body, ErrHandoffRecord
	}
	for _, value := range members {
		entry, ok := value.([]any)
		if !ok || len(entry) != 4 {
			return body, ErrHandoffRecord
		}
		staking, sOK := entry[0].(string)
		node, nOK := entry[1].(string)
		key, kOK := entry[2].([]byte)
		weight, wOK := entry[3].(uint64)
		if !sOK || !nOK || !kOK || !wOK {
			return body, ErrHandoffRecord
		}
		body.Members = append(body.Members, evmroot.Member{StakingID: staking, NodeID: node, ConsensusKey: key, Weight: weight})
	}
	if body.RootThreshold, ok = fields[5].(uint64); !ok {
		return body, ErrHandoffRecord
	}
	if body.StateSummary, ok = optionalD3Bytes(fields[6]); !ok {
		return body, ErrHandoffRecord
	}
	if body.ChangeRecordHash, ok = optionalD3Bytes(fields[7]); !ok {
		return body, ErrHandoffRecord
	}
	if body.PredecessorHash, ok = optionalD3Bytes(fields[8]); !ok {
		return body, ErrHandoffRecord
	}
	if err := body.Validate(); err != nil || !bytes.Equal(body.Encode(), raw) {
		return body, ErrHandoffRecord
	}
	return body, nil
}

// DecodeHandoffBody checks the exact canonical body retained from Freeze.
func DecodeHandoffBody(raw []byte) (evmroot.TrustBaseBodyV2, error) { return decodeD3Body(raw) }

func optionalD3Bytes(value any) ([]byte, bool) {
	if value == nil {
		return nil, true
	}
	b, ok := value.([]byte)
	return b, ok
}
