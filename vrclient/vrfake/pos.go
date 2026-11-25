package vrfake

import (
	"bytes"

	"github.com/ethereum/go-ethereum/accounts/abi"
	ethcommon "github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/vrclient"
	"github.com/unicitynetwork/bft-core/vrschema"
)

// Pos models the P85 side a PoS key change reads and writes (#1286): custody's positions, Evidence's exclusions, the election's
// delegations (admitDelegation checks the generation, the role and delegation nonces, the owner's signature and the EVM key's possession
// over evmassign.DelegationDigest) and its open result with the frozen members.
type Pos struct {
	Positions   map[uint64]*Position
	Delegations map[[2]uint64]*Delegated
	OpenResult  [32]byte
	Frozen      []vrclient.FrozenMember
	// Admitted counts the accepted admitDelegation transactions.
	Admitted int
}

// Position is custody's position of one identity; the owner is the VR identity's unless Owner is set.
type Position struct {
	Owner               ethcommon.Address
	RootKeyHash         [32]byte
	Generation          uint64
	RoleNonce           uint64
	OpenLots            uint32
	RetirementRequested bool
	Excluded            bool
}

// Delegated is the election's staged binding of (id, generation) and its next delegation nonce.
type Delegated struct {
	Binding   vrclient.Delegation
	NextNonce uint64
}

// NewPos is an empty P85 model.
func NewPos() *Pos {
	return &Pos{Positions: map[uint64]*Position{}, Delegations: map[[2]uint64]*Delegated{}}
}

func (c *Chain) position(id uint64) []byte {
	p := c.Pos.Positions[id]
	idn := c.Identities[id]
	if p == nil || idn == nil {
		return pack(vrclient.CustodyABI, "positions", ethcommon.Address{}, ethcommon.Address{}, [32]byte{}, [32]byte{}, uint64(0), uint64(0), uint32(0), uint32(0), false)
	}
	owner := idn.Owner
	if p.Owner != (ethcommon.Address{}) {
		owner = p.Owner
	}
	return pack(vrclient.CustodyABI, "positions", owner, owner, p.RootKeyHash, [32]byte{}, p.Generation, p.RoleNonce, p.OpenLots, p.OpenLots,
		p.RetirementRequested)
}

func (c *Chain) evidence(data []byte) ([]byte, *rpcError) {
	a := vrclient.EvidenceABI
	m, err := a.MethodById(data[:4])
	if err != nil {
		return nil, &rpcError{Code: 3, Message: "execution reverted"}
	}
	in, err := m.Inputs.Unpack(data[4:])
	if err != nil {
		return nil, &rpcError{Code: 3, Message: "execution reverted"}
	}
	p := c.Pos.Positions[in[0].(uint64)]
	return pack(a, "excluded", p != nil && p.Excluded), nil
}

func (c *Chain) election(from ethcommon.Address, data []byte, write bool) ([]byte, *rpcError) {
	if m, err := vrclient.PosPublishABI.MethodById(data[:4]); err == nil {
		in, err := m.Inputs.Unpack(data[4:])
		if err != nil {
			return nil, &rpcError{Code: 3, Message: "execution reverted"}
		}
		switch m.Name {
		case "openResult":
			return pack(vrclient.PosPublishABI, "openResult", c.Pos.OpenResult), nil
		case "frozenMembers":
			if in[0].([32]byte) != c.Pos.OpenResult {
				return pack(vrclient.PosPublishABI, "frozenMembers", []vrclient.FrozenMember{}), nil
			}
			return pack(vrclient.PosPublishABI, "frozenMembers", c.Pos.Frozen), nil
		}
		return nil, &rpcError{Code: 3, Message: "execution reverted (vrfake: " + m.Name + " not modelled)"}
	}
	a := vrclient.PosElectionABI
	m, err := a.MethodById(data[:4])
	if err != nil {
		return nil, &rpcError{Code: 3, Message: "execution reverted"}
	}
	in, err := m.Inputs.Unpack(data[4:])
	if err != nil {
		return nil, &rpcError{Code: 3, Message: "execution reverted"}
	}
	switch m.Name {
	case "delegation":
		d := c.Pos.Delegations[[2]uint64{in[0].(uint64), in[1].(uint64)}]
		if d == nil {
			d = &Delegated{Binding: vrclient.Delegation{RootKey: []byte{}, EvmKey: []byte{}}}
		}
		var h [32]byte
		if d.Binding.OperatorPayee != (ethcommon.Address{}) {
			h = c.bindingHash(in[0].(uint64), in[1].(uint64), d.Binding)
		}
		return pack(a, "delegation", d.Binding, h, d.NextNonce), nil
	case "delegationDigest":
		var r vrclient.DelegationRequest
		convert(in[0], &r)
		d := c.delegationDigest(r)
		return pack(a, "delegationDigest", d), nil
	case "admitDelegation":
		var r vrclient.DelegationRequest
		convert(in[0], &r)
		idn, p := c.Identities[r.Id], c.Pos.Positions[r.Id]
		if idn == nil || p == nil {
			return nil, &rpcError{Code: 3, Message: "execution reverted: UnknownIdentity"}
		}
		if r.Generation != p.Generation {
			return nil, &rpcError{Code: 3, Message: "execution reverted: StaleGeneration"}
		}
		if r.RoleNonce != p.RoleNonce {
			return nil, &rpcError{Code: 3, Message: "execution reverted: RoleNonceMismatch"}
		}
		key := [2]uint64{r.Id, r.Generation}
		cur := c.Pos.Delegations[key]
		next := uint64(0)
		if cur != nil {
			next = cur.NextNonce
		}
		if r.DelegationNonce != next {
			return nil, &rpcError{Code: 3, Message: "execution reverted: DelegationNonceMismatch"}
		}
		if [32]byte(ethcrypto.Keccak256(r.Binding.RootKey)) != p.RootKeyHash {
			return nil, &rpcError{Code: 3, Message: "execution reverted: WrongRootKey"}
		}
		d := c.delegationDigest(r)
		owner, ok := recoverAddr(d, in[1].([]byte))
		if !ok || (owner != idn.Owner && owner != p.Owner) {
			return nil, &rpcError{Code: 3, Message: "execution reverted: BadOwnerAuthorization"}
		}
		if !verifyPoP(r.Binding.EvmKey, d, in[2].([]byte)) {
			return nil, &rpcError{Code: 3, Message: "execution reverted: BadEvmPossession"}
		}
		if write {
			c.Pos.Delegations[key] = &Delegated{Binding: r.Binding, NextNonce: next + 1}
			c.Pos.Admitted++
		}
		return nil, nil
	}
	return nil, &rpcError{Code: 3, Message: "execution reverted (vrfake: " + m.Name + " not modelled)"}
}

func (c *Chain) delegationDigest(r vrclient.DelegationRequest) [32]byte {
	var chain [32]byte
	c.ChainID.FillBytes(chain[:])
	return evmassign.DelegationDigest(c.Network, chain, c.Election, evmassign.DelegationRequest{Id: r.Id, Generation: r.Generation, RoleNonce: r.RoleNonce,
		DelegationNonce: r.DelegationNonce, Expiry: r.Expiry, Binding: evmassign.DelegationBinding{RootNodeID: r.Binding.RootNodeID, RootKey: r.Binding.RootKey,
			EvmNodeID: r.Binding.EvmNodeID, EvmKey: r.Binding.EvmKey, OperatorPayee: r.Binding.OperatorPayee}})
}

// bindingHash is ElectionPolicy's binding hash of (id, generation, binding).
func (c *Chain) bindingHash(id, generation uint64, d vrclient.Delegation) [32]byte {
	return BindingHash(id, generation, d)
}

// BindingHash is ElectionPolicy's binding hash of (id, generation, binding): what a frozen member records.
func BindingHash(id, generation uint64, d vrclient.Delegation) [32]byte {
	wid, wgen := vrschema.U64(id), vrschema.U64(generation)
	dom := vrschema.Keccak([]byte("unicity.p85.delegation-binding"))
	return [32]byte(ethcrypto.Keccak256(dom[:], wid[:], wgen[:], d.RootNodeID[:], ethcrypto.Keccak256(d.RootKey), d.EvmNodeID[:],
		ethcrypto.Keccak256(d.EvmKey), ethcommon.LeftPadBytes(d.OperatorPayee[:], 32)))
}

func convert(v any, out any) { abi.ConvertType(v, out) }

// recoverAddr is the signer address of a contracts-form (v 27/28) signature over digest.
func recoverAddr(digest [32]byte, sig []byte) (ethcommon.Address, bool) {
	if len(sig) != 65 || (sig[64] != 27 && sig[64] != 28) {
		return ethcommon.Address{}, false
	}
	rec := bytes.Clone(sig)
	rec[64] -= 27
	pub, err := ethcrypto.SigToPub(digest[:], rec)
	if err != nil {
		return ethcommon.Address{}, false
	}
	return ethcrypto.PubkeyToAddress(*pub), true
}
