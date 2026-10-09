package signingauthority

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-core/evmassign"
)

// The authority's key is the validator's EVM key in the P85 election as well: the contracts take a signature by it over two typed messages,
// the assignment possession proof (P85 v5 section 5: Election.popDigest) and the delegation possession (section 2:
// ElectionPolicy.delegationDigest). Both are Ethereum-style signatures over a keccak digest. A signing operation that took a digest from the
// caller would let the operator channel obtain the key's signature over any 32-byte value, among them the hash of a certification preimage.
// So neither method takes a digest: each takes the typed inputs, recomputes the digest here with evmassign (the functions the root's
// verifier and the contracts' vectors pin) and signs only that, for this authority's own key and node. Operator channel only.

type hashSigner interface {
	SignHash(hash []byte) ([]byte, error)
}

// ElectionPoPRequest asks for the EVM possession proof this authority's key owes a primary candidate.
type ElectionPoPRequest struct {
	Candidate  evmassign.Candidate
	Deployment evmassign.ElectionDeployment
	// Attempt is the attempt the election reserved the result under.
	Attempt uint64
}

// DelegationPossessionRequest asks for the possession signature this authority's key owes an admitDelegation payload.
type DelegationPossessionRequest struct {
	// Network is the election's network word, Chain the chain id, Election its address.
	Network, Chain [32]byte
	Election       [20]byte
	Request        evmassign.DelegationRequest
}

func (a *Authority) ethSigner() (hashSigner, []byte, error) {
	if a.signer == nil {
		return nil, nil, ErrKeyLost
	}
	if a.state != healthActive {
		return nil, nil, ErrStateUntrusted
	}
	hs, ok := a.signer.(hashSigner)
	if !ok {
		return nil, nil, ErrNoHashSigner
	}
	pub, err := publicKeyOf(a.signer)
	if err != nil {
		return nil, nil, err
	}
	return hs, pub, nil
}

func ethSign(hs hashSigner, digest [32]byte) ([]byte, error) {
	sig, err := hs.SignHash(digest[:])
	if err != nil {
		return nil, err
	}
	if len(sig) != 65 {
		return nil, fmt.Errorf("signing: a %d-byte recoverable signature", len(sig))
	}
	out := append([]byte(nil), sig...)
	out[64] += 27 // the contracts' v
	return out, nil
}

// SignElectionPoP signs Election.popDigest for this authority's own key: the candidate must be a primary candidate of the enrolled
// network whose successor binding names this node with this key (the same binding checks as SignHandoffPoP, which also bound the epoch),
// and the member that carries the key must name this node as its EVM validator.
func (a *Authority) SignElectionPoP(req ElectionPoPRequest) (evmassign.EVMPoP, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	hs, pub, err := a.ethSigner()
	if err != nil {
		return evmassign.EVMPoP{}, err
	}
	pop, err := req.Candidate.PoPContext()
	if err != nil {
		return evmassign.EVMPoP{}, fmt.Errorf("%w: %v", ErrContextMismatch, err)
	}
	succ, err := req.Candidate.Successor()
	if err != nil {
		return evmassign.EVMPoP{}, fmt.Errorf("%w: %v", ErrContextMismatch, err)
	}
	if err := a.checkPoPBinding(succ, a.enroll.NodeID, pop); err != nil {
		return evmassign.EVMPoP{}, err
	}
	digest, id, err := evmassign.ElectionPoPDigest(req.Candidate, req.Deployment, req.Attempt, pub, a.enroll.NodeID)
	if err != nil {
		return evmassign.EVMPoP{}, fmt.Errorf("%w: %v", ErrContextMismatch, err)
	}
	sig, err := ethSign(hs, digest)
	if err != nil {
		return evmassign.EVMPoP{}, err
	}
	return evmassign.EVMPoP{ID: id, EVMKey: pub, Signature: sig}, nil
}

// SignDelegationPossession signs ElectionPolicy.delegationDigest for this authority's own key: the payload must nominate this key as the
// identity's EVM key and this node as its EVM validator, and nothing else is signed.
func (a *Authority) SignDelegationPossession(req DelegationPossessionRequest) ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	hs, pub, err := a.ethSigner()
	if err != nil {
		return nil, err
	}
	word, err := evmassign.NodeIDWord(a.enroll.NodeID)
	if err != nil {
		return nil, errors.Join(ErrContextMismatch, err)
	}
	b := req.Request.Binding
	switch {
	case !bytes.Equal(b.EvmKey, pub):
		return nil, fmt.Errorf("%w: the delegation nominates another EVM key", ErrContextMismatch)
	case b.EvmNodeID != word:
		return nil, fmt.Errorf("%w: the delegation nominates another EVM validator", ErrContextMismatch)
	}
	return ethSign(hs, evmassign.DelegationDigest(req.Network, req.Chain, req.Election, req.Request))
}
