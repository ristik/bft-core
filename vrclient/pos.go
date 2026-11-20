package vrclient

// The PoS prototype's owner calls (VT-04, design 3.5.6): the P85 custody and election an operator drives on a PoS generation, behind the
// PosElectionAdapter. VR ids equal custody StakingIDs; the operator registers in VR, registers and bonds in custody and admits its
// delegation in the election.

import (
	"context"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi"
	ethcommon "github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	"github.com/unicitynetwork/bft-core/vrschema"
)

// ModuleTagPoS is the PosElectionAdapter's moduleTag, keccak256("unicity.vr.pos-p85.v1").
var ModuleTagPoS = vrschema.Keccak([]byte("unicity.vr.pos-p85.v1"))

const delegationRequestType = `"components":[{"name":"id","type":"uint64"},{"name":"generation","type":"uint64"},` +
	`{"name":"binding","type":"tuple","components":[{"name":"rootNodeID","type":"bytes32"},{"name":"rootKey","type":"bytes"},` +
	`{"name":"evmNodeID","type":"bytes32"},{"name":"evmKey","type":"bytes"},{"name":"operatorPayee","type":"address"}]},` +
	`{"name":"roleNonce","type":"uint64"},{"name":"delegationNonce","type":"uint64"},{"name":"expiry","type":"uint64"}]`

// CustodyABI is StakeCustody's owner functions and the views the CLI reads.
var CustodyABI = mustABI(`[
 {"type":"function","name":"register","stateMutability":"nonpayable","inputs":[{"name":"rootKey","type":"bytes"},{"name":"pop","type":"bytes"},{"name":"withdrawal","type":"address"}],"outputs":[{"name":"id","type":"uint64"}]},
 {"type":"function","name":"bond","stateMutability":"payable","inputs":[{"name":"id","type":"uint64"}],"outputs":[{"name":"lotID","type":"uint256"}]},
 {"type":"function","name":"requestRetirement","stateMutability":"nonpayable","inputs":[{"name":"id","type":"uint64"}],"outputs":[]},
 {"type":"function","name":"mature","stateMutability":"nonpayable","inputs":[{"name":"lotIDs","type":"uint256[]"}],"outputs":[]},
 {"type":"function","name":"claim","stateMutability":"nonpayable","inputs":[{"name":"amount","type":"uint256"},{"name":"to","type":"address"}],"outputs":[]},
 {"type":"function","name":"election","stateMutability":"view","inputs":[],"outputs":[{"name":"","type":"address"}]},
 {"type":"function","name":"network","stateMutability":"view","inputs":[],"outputs":[{"name":"","type":"bytes32"}]},
 {"type":"function","name":"registerNonce","stateMutability":"view","inputs":[{"name":"","type":"address"}],"outputs":[{"name":"","type":"uint64"}]},
 {"type":"function","name":"bondUnit","stateMutability":"view","inputs":[],"outputs":[{"name":"","type":"uint128"}]},
 {"type":"function","name":"credit","stateMutability":"view","inputs":[{"name":"","type":"address"}],"outputs":[{"name":"","type":"uint256"}]},
 {"type":"function","name":"generationLots","stateMutability":"view","inputs":[{"name":"id","type":"uint64"},{"name":"generation","type":"uint64"}],"outputs":[{"name":"","type":"uint256[]"}]},
 {"type":"function","name":"positions","stateMutability":"view","inputs":[{"name":"","type":"uint64"}],"outputs":[{"name":"owner","type":"address"},{"name":"withdrawal","type":"address"},{"name":"rootKeyHash","type":"bytes32"},{"name":"stagedRootKeyHash","type":"bytes32"},{"name":"generation","type":"uint64"},{"name":"roleNonce","type":"uint64"},{"name":"openLots","type":"uint32"},{"name":"lotCount","type":"uint32"},{"name":"retirementRequested","type":"bool"}]},
 {"type":"event","name":"Registered","anonymous":false,"inputs":[{"name":"id","type":"uint64","indexed":true},{"name":"owner","type":"address","indexed":true},{"name":"rootKeyHash","type":"bytes32","indexed":false},{"name":"withdrawal","type":"address","indexed":false}]}]`)

// PosElectionABI is ElectionPolicy's admitDelegation and the views the CLI reads.
var PosElectionABI = mustABI(`[
 {"type":"function","name":"admitDelegation","stateMutability":"nonpayable","inputs":[{"name":"r","type":"tuple",` + delegationRequestType +
	`},{"name":"ownerSignature","type":"bytes"},{"name":"evmPossession","type":"bytes"}],"outputs":[]},
 {"type":"function","name":"delegationDigest","stateMutability":"view","inputs":[{"name":"r","type":"tuple",` + delegationRequestType +
	`}],"outputs":[{"name":"","type":"bytes32"}]},
 {"type":"function","name":"delegation","stateMutability":"view","inputs":[{"name":"id","type":"uint64"},{"name":"generation","type":"uint64"}],"outputs":[{"name":"binding","type":"tuple","components":[{"name":"rootNodeID","type":"bytes32"},{"name":"rootKey","type":"bytes"},{"name":"evmNodeID","type":"bytes32"},{"name":"evmKey","type":"bytes"},{"name":"operatorPayee","type":"address"}]},{"name":"bindingHash","type":"bytes32"},{"name":"nextNonce","type":"uint64"}]}]`)

// Delegation is the P85 staged binding.
type Delegation struct {
	RootNodeID    [32]byte
	RootKey       []byte
	EvmNodeID     [32]byte
	EvmKey        []byte
	OperatorPayee ethcommon.Address
}

// DelegationRequest is the admitDelegation payload (design v5 section 2).
type DelegationRequest struct {
	Id              uint64
	Generation      uint64
	Binding         Delegation
	RoleNonce       uint64
	DelegationNonce uint64
	Expiry          uint64
}

// NodeIDWord is keccak256(utf8(nodeID)), the word VR and the election keep for a node id.
func NodeIDWord(nodeID string) [32]byte { return [32]byte(ethcrypto.Keccak256([]byte(nodeID))) }

// CustodyRegisterDigest is the digest the root key signs to register in custody.
func CustodyRegisterDigest(network [32]byte, chainID *big.Int, custody, owner, withdrawal ethcommon.Address, rootKey []byte, nonce uint64) ([32]byte, error) {
	args := abi.Arguments{{Type: mustT("bytes32")}, {Type: mustT("bytes32")}, {Type: mustT("uint256")}, {Type: mustT("address")}, {Type: mustT("address")},
		{Type: mustT("address")}, {Type: mustT("bytes32")}, {Type: mustT("uint64")}}
	b, err := args.Pack([32]byte(ethcrypto.Keccak256([]byte("unicity.p85.pop.register"))), network, chainID, custody, owner, withdrawal,
		[32]byte(ethcrypto.Keccak256(rootKey)), nonce)
	if err != nil {
		return [32]byte{}, err
	}
	return [32]byte(ethcrypto.Keccak256(b)), nil
}

func mustT(t string) abi.Type {
	ty, err := abi.NewType(t, "", nil)
	if err != nil {
		panic(err)
	}
	return ty
}

// PosCalldata packs a custody or election call.
func PosCalldata(a abi.ABI, method string, args ...any) ([]byte, error) {
	return a.Pack(method, args...)
}

// CallPos is an eth_call of a custody or election view at the client's block.
func (c *Client) CallPos(ctx context.Context, to ethcommon.Address, a abi.ABI, method string, out any, args ...any) error {
	return c.call(ctx, to, a, method, out, args...)
}

// PosContracts reads the generation's custody (the liability holder of the active module) and its election.
func (c *Client) PosContracts(ctx context.Context, m ModuleView) (custody, election ethcommon.Address, err error) {
	custody = m.Meta.LiabilityHolder
	if custody == (ethcommon.Address{}) {
		return custody, election, fmt.Errorf("%w: the active module names no liability holder", ErrVR)
	}
	err = c.call(ctx, custody, CustodyABI, "election", &election)
	return custody, election, err
}

// CustodyRegisteredID reads the id from a custody register receipt's Registered log.
func CustodyRegisteredID(r *Receipt, custody ethcommon.Address) (uint64, bool) {
	ev := CustodyABI.Events["Registered"]
	for _, l := range r.Logs {
		if l.Address == custody && len(l.Topics) == 3 && l.Topics[0] == ev.ID {
			return new(big.Int).SetBytes(l.Topics[1].Bytes()).Uint64(), true
		}
	}
	return 0, false
}
