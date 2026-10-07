package storage

import (
	"bytes"
	"math"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/internal/weightvalidation"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"
)

// freezeV3Version is the Freeze companion of a V3 (weighted, coupled) successor body. It carries what the V2 companion carries and
// the readiness receipts of every successor member, so each voter checks them before the old committee's endorsement is accepted
// and the retained handoff evidence holds them for the activation.
const freezeV3Version = 3

// FreezeV3Authorization is the version-3 freeze companion. Preimage is the canonical evmassign.Candidate of a coupled change and is
// empty for a root-only V3 change, whose candidate is then the operator digest of the members.
type FreezeV3Authorization struct {
	_          struct{} `cbor:",toarray"`
	Version    uint64
	Body       []byte // canonical V3 body encoding
	Parent     []byte
	Candidate  []byte
	Preimage   []byte
	Receipts   []byte // canonical readiness receipts of every successor member
	Signatures map[string]hex.Bytes
}

func (a FreezeV3Authorization) Bytes() ([]byte, error) { return types.Cbor.Marshal(a) }

// V3Body is what Freeze admission needs of a verified V3 body. The format lives in q3format, whose own tests build on this package, so
// the body is decoded and validated by the V3FreezeRules the consensus package injects and this package sees only these facts.
type V3Body struct {
	ID                 [32]byte
	Network, Epoch     uint64
	EarliestActivation uint64
	Members            []evmassign.RootMember
	StateSummary       []byte
	ChangeRecordHash   []byte
	PredecessorHash    []byte
}

// V3FreezeRules is the V3 rule set the old committee applies at Freeze.
type V3FreezeRules interface {
	// VerifyBody decodes one canonical V3 body and validates it in full (tuple, weights, threshold, members).
	VerifyBody(raw []byte) (V3Body, error)
	// Prior is the predecessor hash a successor body of the epoch after (network, epoch) carries when that epoch's body has the given
	// version and identity.
	Prior(network, epoch, version uint64, identity []byte) ([]byte, error)
	// VerifyReceipts checks that receipts is the canonical, complete set of valid readiness receipts of the body's members for the
	// attempt and candidate digest.
	VerifyReceipts(body, receipts []byte, attempt uint64, candidate []byte) error
}

// ConfigureHandoffV3Authority makes the epoch of a verified V3 activation the old committee of a further handoff: its signature view
// is the history's exact-weight projection and its predecessor identity is the activation's body identity.
func (x *BlockStore) ConfigureHandoffV3Authority(tb *types.RootTrustBaseV1, bodyID []byte, rules V3FreezeRules) error {
	if x.profile != ProfileHandoff || tb == nil || tb.Epoch < 2 || len(bodyID) != 32 || rules == nil {
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
	x.handoffAuth = &v1HandoffAuthority{trust: &owned, predecessor: bytes.Clone(bodyID), priorVersion: freezeV3Version, v3: rules}
	return nil
}

// EnableV3Freeze lets the configured genesis authority also verify V3 freezes: the first activation of a Q3 history, whose predecessor
// is the version-1 genesis body.
func (x *BlockStore) EnableV3Freeze(rules V3FreezeRules) error {
	a, ok := x.handoffAuth.(*v1HandoffAuthority)
	if !ok || rules == nil || a.priorVersion != 1 {
		return ErrHandoffRecord
	}
	a.v3 = rules
	return nil
}

// verifyFreezeV3 is VerifyFreeze for a version-3 companion: the same chain record <- body <- change-record hash <- candidate <- preimage,
// under the weighted rules, with the readiness receipts of every successor member required.
func (a *v1HandoffAuthority) verifyFreezeV3(r evmroot.OrderedHandoffRecord, proof FreezeCompanion) ([]byte, error) {
	if a.v3 == nil || r.Epoch == math.MaxUint64 {
		return nil, ErrHandoffRecord
	}
	body, err := a.v3.VerifyBody(proof.Body)
	if err != nil {
		return nil, ErrHandoffRecord
	}
	link, err := a.v3.Prior(r.Network, r.Epoch, a.priorVersion, a.predecessor)
	if err != nil || body.Network != r.Network || body.Epoch != r.Epoch+1 || body.EarliestActivation == 0 ||
		body.EarliestActivation > r.ActivationRound || !bytes.Equal(body.PredecessorHash, link) {
		return nil, ErrHandoffRecord
	}
	if len(proof.Parent) != 32 || bytes.Equal(proof.Parent, make([]byte, 32)) || len(proof.Candidate) != 32 ||
		!bytes.Equal(body.ChangeRecordHash, evmroot.D4CandidateContextHash(r.Network, r.PredecessorBodyID, r.Attempt, proof.Candidate, body.EarliestActivation)) ||
		!bytes.Equal(r.FrozenID, evmroot.D4FrozenID(r.NextBodyID, body.StateSummary, proof.Parent, proof.Candidate, r.Attempt, r.PredecessorBodyID)) ||
		!bytes.Equal(body.ID[:], r.NextBodyID) {
		return nil, ErrHandoffRecord
	}
	if len(proof.Preimage) != 0 {
		ctx := evmassign.BindingContext{Digest: proof.Candidate, ControlPartition: evmroot.D4ControlPartition,
			PoPContext: evmassign.PoPContext{Network: r.Network, Attempt: r.Attempt}, Rules: weightvalidation.EVMRules(weightvalidation.ModeWeighted)}
		copy(ctx.Predecessor[:], r.PredecessorBodyID)
		ctx.SuccessorRoot = append(ctx.SuccessorRoot, body.Members...)
		if _, _, err := evmassign.VerifyBinding(proof.Preimage, ctx); err != nil {
			return nil, ErrHandoffRecord
		}
	}
	if a.v3.VerifyReceipts(proof.Body, proof.Receipts, r.Attempt, proof.Candidate) != nil {
		return nil, ErrHandoffRecord
	}
	message, err := EndorsementBytes(r)
	if err != nil || a.verifyQuorum(message, proof.Signatures) != nil {
		return nil, ErrHandoffRecord
	}
	return bytes.Clone(proof.Parent), nil
}
