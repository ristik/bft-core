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
 {"type":"function","name":"evidence","stateMutability":"view","inputs":[],"outputs":[{"name":"","type":"address"}]},
 {"type":"function","name":"network","stateMutability":"view","inputs":[],"outputs":[{"name":"","type":"bytes32"}]},
 {"type":"function","name":"registerNonce","stateMutability":"view","inputs":[{"name":"","type":"address"}],"outputs":[{"name":"","type":"uint64"}]},
 {"type":"function","name":"bondUnit","stateMutability":"view","inputs":[],"outputs":[{"name":"","type":"uint128"}]},
 {"type":"function","name":"credit","stateMutability":"view","inputs":[{"name":"","type":"address"}],"outputs":[{"name":"","type":"uint256"}]},
 {"type":"function","name":"generationLots","stateMutability":"view","inputs":[{"name":"id","type":"uint64"},{"name":"generation","type":"uint64"}],"outputs":[{"name":"","type":"uint256[]"}]},
 {"type":"function","name":"positions","stateMutability":"view","inputs":[{"name":"","type":"uint64"}],"outputs":[{"name":"owner","type":"address"},{"name":"withdrawal","type":"address"},{"name":"rootKeyHash","type":"bytes32"},{"name":"stagedRootKeyHash","type":"bytes32"},{"name":"generation","type":"uint64"},{"name":"roleNonce","type":"uint64"},{"name":"openLots","type":"uint32"},{"name":"lotCount","type":"uint32"},{"name":"retirementRequested","type":"bool"}]},
 {"type":"event","name":"CreditClaimed","anonymous":false,"inputs":[{"name":"creditor","type":"address","indexed":true},{"name":"to","type":"address","indexed":true},{"name":"amount","type":"uint256","indexed":false}]},
 {"type":"event","name":"Registered","anonymous":false,"inputs":[{"name":"id","type":"uint64","indexed":true},{"name":"owner","type":"address","indexed":true},{"name":"rootKeyHash","type":"bytes32","indexed":false},{"name":"withdrawal","type":"address","indexed":false}]}]`)

// EvidenceABI is the Evidence view a key change reads (#1286): an identity excluded by evidence takes the exit path.
var EvidenceABI = mustABI(`[
 {"type":"function","name":"excluded","stateMutability":"view","inputs":[{"name":"id","type":"uint64"}],"outputs":[{"name":"","type":"bool"}]}]`)

// PosElectionABI is ElectionPolicy's admitDelegation and the views the CLI reads.
var PosElectionABI = mustABI(`[
 {"type":"function","name":"admitDelegation","stateMutability":"nonpayable","inputs":[{"name":"r","type":"tuple",` + delegationRequestType +
	`},{"name":"ownerSignature","type":"bytes"},{"name":"evmPossession","type":"bytes"}],"outputs":[]},
 {"type":"function","name":"delegationDigest","stateMutability":"view","inputs":[{"name":"r","type":"tuple",` + delegationRequestType +
	`}],"outputs":[{"name":"","type":"bytes32"}]},
 {"type":"function","name":"delegation","stateMutability":"view","inputs":[{"name":"id","type":"uint64"},{"name":"generation","type":"uint64"}],"outputs":[{"name":"binding","type":"tuple","components":[{"name":"rootNodeID","type":"bytes32"},{"name":"rootKey","type":"bytes"},{"name":"evmNodeID","type":"bytes32"},{"name":"evmKey","type":"bytes"},{"name":"operatorPayee","type":"address"}]},{"name":"bindingHash","type":"bytes32"},{"name":"nextNonce","type":"uint64"}]}]`)

// PosPublishABI is the election's publication path: the result a hook reserved, its frozen members, the possession proofs and
// finalizeCandidate. The proofs are permissionless to relay; a lane relayer that holds the members' EVM keys submits them all.
var PosPublishABI = mustABI(`[
 {"type":"function","name":"openResult","stateMutability":"view","inputs":[],"outputs":[{"name":"","type":"bytes32"}]},
 {"type":"function","name":"publication","stateMutability":"view","inputs":[{"name":"resultID","type":"bytes32"}],"outputs":[{"name":"","type":"tuple","components":[{"name":"primaryHash","type":"bytes32"},{"name":"kCommit","type":"bytes32"},{"name":"incumbent","type":"bytes32"},{"name":"incumbentExposureDigest","type":"bytes32"},{"name":"incumbentKeyDigest","type":"bytes32"},{"name":"policyDigest","type":"bytes32"},{"name":"contractsDigest","type":"bytes32"},{"name":"snapshotDigest","type":"bytes32"},{"name":"assignmentID","type":"bytes32"},{"name":"popSetDigest","type":"bytes32"},{"name":"published","type":"bool"},{"name":"popCount","type":"uint32"},{"name":"attempt","type":"uint64"},{"name":"lost","type":"bool"}]}]},
 {"type":"function","name":"result","stateMutability":"view","inputs":[{"name":"resultID","type":"bytes32"}],"outputs":[{"name":"","type":"tuple","components":[{"name":"state","type":"uint8"},{"name":"reason","type":"uint8"},{"name":"attempt","type":"uint64"},{"name":"progress","type":"uint64"},{"name":"ucTime","type":"uint64"},{"name":"policyID","type":"uint32"},{"name":"origin","type":"bytes32"},{"name":"predecessor","type":"bytes32"},{"name":"assignmentID","type":"bytes32"},{"name":"snapshotDigest","type":"bytes32"}]}]},
 {"type":"function","name":"popDigest","stateMutability":"view","inputs":[{"name":"resultID","type":"bytes32"},{"name":"id","type":"uint64"},{"name":"evmKeyHash","type":"bytes32"}],"outputs":[{"name":"","type":"bytes32"}]},
 {"type":"function","name":"popHash","stateMutability":"view","inputs":[{"name":"resultID","type":"bytes32"},{"name":"id","type":"uint64"}],"outputs":[{"name":"","type":"bytes32"}]},
 {"type":"function","name":"frozenMembers","stateMutability":"view","inputs":[{"name":"resultID","type":"bytes32"}],"outputs":[{"name":"","type":"tuple[]","components":[{"name":"id","type":"uint64"},{"name":"generation","type":"uint64"},{"name":"weight","type":"uint64"},{"name":"raw","type":"uint64"},{"name":"bindingHash","type":"bytes32"}]}]},
 {"type":"function","name":"submitAssignmentPoPs","stateMutability":"nonpayable","inputs":[{"name":"resultID","type":"bytes32"},{"name":"pops","type":"tuple[]","components":[{"name":"id","type":"uint64"},{"name":"evmKey","type":"bytes"},{"name":"signature","type":"bytes"}]}],"outputs":[]},
 {"type":"function","name":"finalizeCandidate","stateMutability":"nonpayable","inputs":[{"name":"resultID","type":"bytes32"}],"outputs":[]},
 {"type":"function","name":"publish","stateMutability":"nonpayable","inputs":[{"name":"resultId","type":"bytes32"}],"outputs":[{"name":"status","type":"uint8"}]}]`)

// PoPInput is one member's possession proof (ElectionPolicy.PoPInput).
type PoPInput struct {
	Id        uint64
	EvmKey    []byte
	Signature []byte
}

// FrozenMember is one member of a reserved result (ElectionPolicy.Frozen).
type FrozenMember struct {
	Id          uint64
	Generation  uint64
	Weight      uint64
	Raw         uint64
	BindingHash [32]byte
}

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
func (c *Client) posPublishCall(ctx context.Context, to ethcommon.Address, method string, out any, args ...any) error {
	return c.call(ctx, to, PosPublishABI, method, out, args...)
}

// CallPosMulti is an eth_call of a view with several return values, copied into out (a pointer to a struct whose exported fields carry the
// return names).
func (c *Client) CallPosMulti(ctx context.Context, to ethcommon.Address, a abi.ABI, method string, out any, args ...any) error {
	data, err := a.Pack(method, args...)
	if err != nil {
		return fmt.Errorf("%w: packing %s: %v", ErrVR, method, err)
	}
	ret, err := c.CallRaw(ctx, to, data)
	if err != nil {
		return fmt.Errorf("%s: %w", method, err)
	}
	if len(ret) == 0 {
		return fmt.Errorf("%w: %s at %s returned nothing", ErrVR, method, to.Hex())
	}
	vals, err := a.Methods[method].Outputs.Unpack(ret)
	if err != nil {
		return fmt.Errorf("%w: decoding %s: %v", ErrVR, method, err)
	}
	return a.Methods[method].Outputs.Copy(out, vals)
}

// OpenResult is the election's unresolved result, zero when none; FrozenMembers its members; PopDigest what a member's EVM key signs.
func (c *Client) OpenResult(ctx context.Context, election ethcommon.Address) (rid [32]byte, err error) {
	return rid, c.posPublishCall(ctx, election, "openResult", &rid)
}

func (c *Client) FrozenMembers(ctx context.Context, election ethcommon.Address, rid [32]byte) (out []FrozenMember, err error) {
	return out, c.posPublishCall(ctx, election, "frozenMembers", &out, rid)
}

// PublicationRecord is the part of ElectionPolicy.Publication a relayer resumes from: whether the candidate is published in P85, how many
// possession proofs are stored, and whether the result lost its coverage.
type PublicationRecord struct {
	PrimaryHash             [32]byte
	KCommit                 [32]byte
	Incumbent               [32]byte
	IncumbentExposureDigest [32]byte
	IncumbentKeyDigest      [32]byte
	PolicyDigest            [32]byte
	ContractsDigest         [32]byte
	SnapshotDigest          [32]byte
	AssignmentID            [32]byte
	PopSetDigest            [32]byte
	Published               bool
	PopCount                uint32
	Attempt                 uint64
	Lost                    bool
}

// Publication reads a result's publication record from the election.
func (c *Client) Publication(ctx context.Context, election ethcommon.Address, rid [32]byte) (p PublicationRecord, err error) {
	data, err := PosPublishABI.Pack("publication", rid)
	if err != nil {
		return p, fmt.Errorf("%w: packing publication: %v", ErrVR, err)
	}
	ret, err := c.CallRaw(ctx, election, data)
	if err != nil {
		return p, fmt.Errorf("publication: %w", err)
	}
	vals, err := PosPublishABI.Methods["publication"].Outputs.Unpack(ret)
	if err != nil || len(vals) != 1 {
		return p, fmt.Errorf("%w: decoding publication: %v", ErrVR, err)
	}
	return *abi.ConvertType(vals[0], new(PublicationRecord)).(*PublicationRecord), nil
}

// ResultRecord is the part of ElectionPolicy.Result the possession digest binds.
type ResultRecord struct {
	State          uint8
	Reason         uint8
	Attempt        uint64
	Progress       uint64
	UcTime         uint64
	PolicyID       uint32
	Origin         [32]byte
	Predecessor    [32]byte
	AssignmentID   [32]byte
	SnapshotDigest [32]byte
}

// Result reads a reserved result's record: the attempt, assignment and snapshot a possession proof binds.
func (c *Client) Result(ctx context.Context, election ethcommon.Address, rid [32]byte) (r ResultRecord, err error) {
	data, err := PosPublishABI.Pack("result", rid)
	if err != nil {
		return r, fmt.Errorf("%w: packing result: %v", ErrVR, err)
	}
	ret, err := c.CallRaw(ctx, election, data)
	if err != nil {
		return r, fmt.Errorf("result: %w", err)
	}
	return decodeResultRecord(ret)
}

func decodeResultRecord(ret []byte) (r ResultRecord, err error) {
	vals, err := PosPublishABI.Methods["result"].Outputs.Unpack(ret)
	if err != nil || len(vals) != 1 {
		return r, fmt.Errorf("%w: decoding result: %v", ErrVR, err)
	}
	return *abi.ConvertType(vals[0], new(ResultRecord)).(*ResultRecord), nil
}

func (c *Client) PopDigest(ctx context.Context, election ethcommon.Address, rid [32]byte, id uint64, evmKeyHash [32]byte) (d [32]byte, err error) {
	return d, c.posPublishCall(ctx, election, "popDigest", &d, rid, id, evmKeyHash)
}

func (c *Client) PosContracts(ctx context.Context, m ModuleView) (custody, election ethcommon.Address, err error) {
	custody = m.Meta.LiabilityHolder
	if custody == (ethcommon.Address{}) {
		return custody, election, fmt.Errorf("%w: the active module names no liability holder", ErrVR)
	}
	if err = c.call(ctx, custody, CustodyABI, "election", &election); err != nil {
		return custody, election, err
	}
	if election == (ethcommon.Address{}) {
		return custody, election, fmt.Errorf("%w: custody %s names no P85 election", ErrVR, custody.Hex())
	}
	return custody, election, nil
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

// CustodyClaimedAmount reads a single valid CreditClaimed event for this withdrawal.
func CustodyClaimedAmount(r *Receipt, custody, creditor, recipient ethcommon.Address) (*big.Int, bool) {
	event := CustodyABI.Events["CreditClaimed"]
	creditorTopic, recipientTopic := ethcommon.BytesToHash(creditor[:]), ethcommon.BytesToHash(recipient[:])
	var amount *big.Int
	for _, l := range r.Logs {
		if l.Address != custody || len(l.Topics) != 3 || l.Topics[0] != event.ID ||
			l.Topics[1] != creditorTopic || l.Topics[2] != recipientTopic {
			continue
		}
		if amount != nil || len(l.Data) != 32 {
			return nil, false
		}
		amount = new(big.Int).SetBytes(l.Data)
	}
	return amount, amount != nil && amount.Sign() > 0
}
