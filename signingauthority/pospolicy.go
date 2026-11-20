package signingauthority

import (
	"errors"
	"fmt"
	"slices"

	"github.com/unicitynetwork/bft-core/evmassign"
)

// The P85 election's possession proofs under a signing authority (#1216). The proof-of-stake module (the PosElectionAdapter over P85) takes
// two EVM possession signatures from each elected member's key: the delegation possession of ElectionPolicy.admitDelegation and the
// assignment possession of ElectionPolicy.submitAssignmentPoPs (Election.popDigest). The first is SignDelegationPossession; the second is
// SignPosPoP, which unlike SignElectionPoP does not need a candidate: the proof-of-stake relayer reads the frozen result's fields from the
// election itself, so the request is those fields.
//
// What the operator pins, once, is the scope both signatures are valid in: the election's network word, the chain id and the ElectionPolicy
// address (the digest domain), and the identity ids this authority's key may prove for. A request outside the pin is refused. The pin
// cannot be changed in the authority's lifetime (the same pin again is a no-op): it is the operator's statement of which election this key
// takes part in, made before any proof. The authority cannot read the chain, so it cannot check that the result is real; that is
// the contract's check (the key's hash must be the frozen member's, and a proof for a result nobody reserved verifies nowhere). The key
// signs only evmassign.PoPDigest, a keccak digest under its own domain tag that a certification preimage cannot equal. Operator channel only.

// ErrPosPolicy is a P85 possession request that the authority's pin does not allow: no pin, another deployment, or an identity the pin does
// not list.
var ErrPosPolicy = errors.New("signing-pos-policy-refused")

// ErrPosPolicyConflict is an attempt to pin a different election than the one already pinned.
var ErrPosPolicyConflict = errors.New("signing-pos-policy-conflict")

// PosPolicy is the pinned scope of the P85 possession signatures.
type PosPolicy struct {
	Network  [32]byte
	ChainID  [32]byte
	Election [20]byte
	// IDs are the identity ids (custody StakingIDs) this authority's key may prove for.
	IDs []uint64
}

func (p PosPolicy) valid() error {
	switch {
	case p.Network == [32]byte{} || p.ChainID == [32]byte{} || p.Election == [20]byte{}:
		return fmt.Errorf("%w: the pin is incomplete: network word, chain id and election are all required", ErrPosPolicy)
	case len(p.IDs) == 0:
		return fmt.Errorf("%w: the pin lists no identity", ErrPosPolicy)
	}
	for _, id := range p.IDs {
		if id == 0 {
			return fmt.Errorf("%w: identity 0", ErrPosPolicy)
		}
	}
	return nil
}

func (p PosPolicy) same(q PosPolicy) bool {
	a, b := slices.Clone(p.IDs), slices.Clone(q.IDs)
	slices.Sort(a)
	slices.Sort(b)
	return p.Network == q.Network && p.ChainID == q.ChainID && p.Election == q.Election && slices.Equal(a, b)
}

// WithRequirePosPolicy makes every P85 possession signature (SignElectionPoP, SignDelegationPossession, SignPosPoP) refused until the pin is
// set: the production profile, in which the deployment arrives by startup configuration (WithPosPolicy) and nothing is signed for an election the
// operator has not stated. Without it an unpinned authority keeps the earlier behavior of the first two (the deployment from the request).
func WithRequirePosPolicy() Option {
	return func(a *Authority) error { a.requirePos = true; return nil }
}

// WithLatePosPolicy lets the operator channel pin the election on a running authority (SetPosPolicy). It is a DEVELOPMENT opt-in: the
// first pin then comes from the same credential that asks for signatures, so it is no restriction against a compromised operator
// credential. A production authority gets its pin from startup configuration (WithPosPolicy) and refuses SetPosPolicy.
func WithLatePosPolicy() Option {
	return func(a *Authority) error { a.latePos = true; return nil }
}

// checkPosScope is the one check of all three P85 possession signatures against the pin. The caller holds a.mu.
func (a *Authority) checkPosScope(network, chain [32]byte, election [20]byte, id uint64) error {
	if a.pos == nil {
		if a.requirePos {
			return fmt.Errorf("%w: this authority requires a P85 election pin and has none", ErrPosPolicy)
		}
		return nil
	}
	if network != a.pos.Network || chain != a.pos.ChainID || election != a.pos.Election || !slices.Contains(a.pos.IDs, id) {
		return fmt.Errorf("%w: another election, chain, network word or identity than this authority's pin", ErrPosPolicy)
	}
	return nil
}

// WithPosPolicy pins the P85 possession scope at startup.
func WithPosPolicy(p PosPolicy) Option {
	return func(a *Authority) error {
		if err := p.valid(); err != nil {
			return err
		}
		p.IDs = slices.Clone(p.IDs)
		a.pos = &p
		return nil
	}
}

// SetPosPolicy pins the P85 possession scope of a running authority, for an operator that only knows the election after the authority
// started (it is deployed in the genesis). Once pinned it never changes: the same pin again succeeds, another is ErrPosPolicyConflict.
func (a *Authority) SetPosPolicy(p PosPolicy) error {
	// a startup pin and a later pin go through the same equality and conflict rule below
	if err := p.valid(); err != nil {
		return err
	}
	p.IDs = slices.Clone(p.IDs)
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.latePos && a.pos == nil {
		return fmt.Errorf("%w: this authority takes its P85 pin from startup configuration only (--pos-policy), not from the operator channel", ErrPosPolicy)
	}
	if a.pos != nil {
		if !a.pos.same(p) {
			return fmt.Errorf("%w: this authority is pinned to another election or identity set", ErrPosPolicyConflict)
		}
		return nil
	}
	a.pos = &p
	return nil
}

// PosPoPRequest asks for the assignment possession proof this authority's key owes one frozen member of a reserved result: the fields of
// Election.popDigest other than the pinned deployment and the key. ID is the member's identity; Generation its generation in the result.
type PosPoPRequest struct {
	ResultID, AssignmentID, Snapshot [32]byte
	Attempt, ID, Generation          uint64
}

// SignPosPoP signs evmassign.PoPDigest for this authority's own key under the pinned election, for a pinned identity, and nothing else.
func (a *Authority) SignPosPoP(req PosPoPRequest) (evmassign.EVMPoP, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.pos == nil {
		return evmassign.EVMPoP{}, fmt.Errorf("%w: this authority has no P85 election pin", ErrPosPolicy)
	}
	if err := a.checkPosScope(a.pos.Network, a.pos.ChainID, a.pos.Election, req.ID); err != nil {
		return evmassign.EVMPoP{}, err
	}
	if req.ResultID == [32]byte{} || req.AssignmentID == [32]byte{} || req.Snapshot == [32]byte{} || req.Generation == 0 {
		return evmassign.EVMPoP{}, fmt.Errorf("%w: the request names no result, assignment, snapshot or generation", ErrContextMismatch)
	}
	hs, pub, err := a.ethSigner()
	if err != nil {
		return evmassign.EVMPoP{}, err
	}
	var d evmassign.ElectionDeployment
	d.NetworkWord, d.ChainID, d.Election = a.pos.Network, a.pos.ChainID, a.pos.Election
	digest := evmassign.PoPDigest(d, req.ResultID, req.AssignmentID, req.Snapshot, req.Attempt, req.ID, req.Generation, pub)
	sig, err := ethSign(hs, digest)
	if err != nil {
		return evmassign.EVMPoP{}, err
	}
	return evmassign.EVMPoP{ID: req.ID, EVMKey: pub, Signature: sig}, nil
}
