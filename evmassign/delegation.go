package evmassign

import (
	"bytes"
	"errors"
	"fmt"

	ethcommon "github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

// delegationDomain is ElectionPolicy.DELEGATION_DOMAIN.
var delegationDomain = ethcrypto.Keccak256Hash([]byte("unicity.p85.admitDelegation"))

// DelegationBinding is the election's Delegation: the root entity, the EVM validator it nominates and the operator payee.
type DelegationBinding struct {
	RootNodeID    [32]byte
	RootKey       []byte
	EvmNodeID     [32]byte
	EvmKey        []byte
	OperatorPayee ethcommon.Address
}

// DelegationRequest is the payload ElectionPolicy.admitDelegation takes (P85 v5 section 2).
type DelegationRequest struct {
	Id              uint64
	Generation      uint64
	Binding         DelegationBinding
	RoleNonce       uint64
	DelegationNonce uint64
	Expiry          uint64
}

// DelegationDigest is ElectionPolicy.delegationDigest: what both the identity's owner and its EVM key sign to admit a delegation. network is
// the election's network word, chain the chain id and election the election's address.
func DelegationDigest(network [32]byte, chain [32]byte, election [20]byte, r DelegationRequest) [32]byte {
	return keccak(delegationDomain[:], network[:], chain[:], wAddr(election[:]), w64(r.Id), w64(r.Generation), r.Binding.RootNodeID[:],
		keccak256Bytes(r.Binding.RootKey), r.Binding.EvmNodeID[:], keccak256Bytes(r.Binding.EvmKey), wAddr(r.Binding.OperatorPayee[:]),
		w64(r.RoleNonce), w64(r.DelegationNonce), w64(r.Expiry))
}

// ElectionPoPDigest is the digest the EVM key evmKey owes a primary candidate (Election.popDigest over what the candidate names for the
// member that carries that key and the attempt the election reserved the result under), with the member's custody id. The key must be a
// member's EVM key in the candidate, and the candidate must name node evmNodeID for it.
func ElectionPoPDigest(c Candidate, d ElectionDeployment, attempt uint64, evmKey []byte, evmNodeID string) ([32]byte, uint64, error) {
	for _, m := range c.Identities {
		if !bytes.Equal(m.EVMKey, evmKey) {
			continue
		}
		if evmNodeID != "" && m.EVMNodeID != evmNodeID {
			return [32]byte{}, 0, fmt.Errorf("%w: the candidate names this key for validator %q, not %q", ErrPoPSigning, m.EVMNodeID, evmNodeID)
		}
		return popDigestFor(c, d, attempt, m)
	}
	return [32]byte{}, 0, errors.Join(ErrPoPSigning, errors.New("the key is not a member's EVM key in this candidate"))
}
