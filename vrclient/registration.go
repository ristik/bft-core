package vrclient

import (
	"bytes"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"

	ethcommon "github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	"github.com/unicitynetwork/bft-core/vrschema"
)

// NodeKeys is one service's identity as VR binds it: the node id (libp2p peer id of the service's authentication key) and its signing
// key, which signs the registration proof of possession.
type NodeKeys struct {
	NodeID string
	Key    *ecdsa.PrivateKey
}

// Public is the 33-byte compressed signing key.
func (k NodeKeys) Public() []byte { return ethcrypto.CompressPubkey(&k.Key.PublicKey) }

// Signed is a registration with both proofs of possession.
type Signed struct {
	Registration Registration
	RootPoP      []byte
	EvmPoP       []byte
	Digest       [32]byte
}

// Domain is the chain context every registration digest binds: VR's network word, the chain id and VR's address.
type Domain struct {
	Network  [32]byte
	ChainID  *big.Int
	Registry ethcommon.Address
}

// NewRegistration builds a registration of the root node and the EVM shard node with payee and nonce, checked as VR checks its shape.
func NewRegistration(root, evm NodeKeys, payee ethcommon.Address, nonce uint64) (Registration, error) {
	r := Registration{RootNodeID: root.NodeID, RootKey: root.Public(), EvmNodeID: evm.NodeID, EvmKey: evm.Public(), Payee: payee, Nonce: nonce}
	if err := toSchema(r).ValidShape(); err != nil {
		return r, fmt.Errorf("%w: %v", ErrVR, err)
	}
	return r, nil
}

func toSchema(r Registration) vrschema.Registration {
	return vrschema.Registration{RootNodeID: r.RootNodeID, RootKey: r.RootKey, EVMNodeID: r.EvmNodeID, EVMKey: r.EvmKey, Payee: r.Payee, Nonce: r.Nonce}
}

// Sign signs the registration digest (design 3.1; vrschema.RegistrationDigest) with both keys: for VR.register when id is 0 and binding
// false, for VR.proposeBinding(id) when binding is true. sender is the owner account that sends the transaction (msg.sender).
func Sign(d Domain, sender ethcommon.Address, binding bool, id uint64, r Registration, root, evm NodeKeys) (Signed, error) {
	if !bytes.Equal(root.Public(), r.RootKey) || !bytes.Equal(evm.Public(), r.EvmKey) {
		return Signed{}, fmt.Errorf("%w: the signing keys are not the registration's keys", ErrVR)
	}
	if d.ChainID == nil || d.ChainID.Sign() < 0 || d.ChainID.BitLen() > 256 {
		return Signed{}, fmt.Errorf("%w: chain id", ErrVR)
	}
	var chain vrschema.Word
	d.ChainID.FillBytes(chain[:])
	digest := vrschema.RegistrationDigest(binding, d.Network, chain, d.Registry, sender, id, toSchema(r))
	rp, err1 := SignDigest(root.Key, digest)
	ep, err2 := SignDigest(evm.Key, digest)
	if err := errors.Join(err1, err2); err != nil {
		return Signed{}, err
	}
	return Signed{Registration: r, RootPoP: rp, EvmPoP: ep, Digest: digest}, nil
}

// SignDigest is the contracts' signature format (KeyLib.verify): r || s || v over the digest itself, v = 27/28, low s.
func SignDigest(key *ecdsa.PrivateKey, digest [32]byte) ([]byte, error) {
	sig, err := ethcrypto.Sign(digest[:], key)
	if err != nil {
		return nil, err
	}
	sig[64] += 27
	return sig, nil
}

// RegisterCalldata is VR.register(r, rootPoP, evmPoP).
func RegisterCalldata(s Signed) ([]byte, error) {
	return VRABI.Pack("register", s.Registration, s.RootPoP, s.EvmPoP)
}

// ProposeBindingCalldata is VR.proposeBinding(id, r, rootPoP, evmPoP).
func ProposeBindingCalldata(id uint64, s Signed) ([]byte, error) {
	return VRABI.Pack("proposeBinding", id, s.Registration, s.RootPoP, s.EvmPoP)
}

// PoA owner actions.
const (
	MethodSubmitApplication   = "submitApplication"
	MethodWithdrawApplication = "withdrawApplication"
	MethodRequestExit         = "requestExit"
	MethodRejoin              = "rejoin"
)

// PoaCalldata is one of the PoA owner actions on id.
func PoaCalldata(method string, id uint64) ([]byte, error) {
	switch method {
	case MethodSubmitApplication, MethodWithdrawApplication, MethodRequestExit, MethodRejoin:
		return PoaABI.Pack(method, id)
	}
	return nil, fmt.Errorf("%w: %s is not a PoA owner action", ErrVR, method)
}

// BindingMatches reports whether a stored binding is exactly this registration's keys, node ids and payee.
func BindingMatches(b Binding, r Registration) bool {
	return b.RootNodeID == r.RootNodeID && bytes.Equal(b.RootKey, r.RootKey) && b.EvmNodeID == r.EvmNodeID && bytes.Equal(b.EvmKey, r.EvmKey) &&
		b.Payee == r.Payee
}
