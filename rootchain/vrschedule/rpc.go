package vrschedule

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/unicitynetwork/bft-core/vrclient"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	gethtypes "github.com/ethereum/go-ethereum/core/types"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/rootchain/evmstate"
	"github.com/unicitynetwork/bft-core/rootchain/vrstate"
	"github.com/unicitynetwork/bft-core/vrhandoff"
	"github.com/unicitynetwork/bft-core/vrschema"
)

// vrABI is the part of VR's view ABI the roots read (unicity-pos-contracts src/vr: output, binding, change). Nothing it returns is
// trusted: the members and payloads are hash-verified against the output record proven at the same block (schema FD-16).
const vrABI = `[
{"name":"output","type":"function","stateMutability":"view","inputs":[{"name":"resultId","type":"bytes32"}],"outputs":[{"name":"v","type":"tuple","components":[
 {"name":"state","type":"uint8"},{"name":"attempt","type":"uint64"},{"name":"reservedProgress","type":"uint64"},{"name":"expiresAtProgress","type":"uint64"},
 {"name":"predecessor","type":"bytes32"},{"name":"sourceModule","type":"address"},{"name":"native","type":"bool"},{"name":"moduleTag","type":"bytes32"},
 {"name":"membersDigest","type":"bytes32"},{"name":"kDigest","type":"bytes32"},{"name":"changesDigest","type":"bytes32"},{"name":"snapshotDigest","type":"bytes32"},
 {"name":"policyDigest","type":"bytes32"},{"name":"outputCommit","type":"bytes32"},{"name":"invalidReason","type":"uint8"},{"name":"invalidAtProgress","type":"uint64"},
 {"name":"members","type":"tuple[]","components":[{"name":"id","type":"uint64"},{"name":"generation","type":"uint64"},{"name":"weight","type":"uint64"},
  {"name":"rawWeight","type":"uint64"},{"name":"rootNodeWord","type":"bytes32"},{"name":"rootKeyHash","type":"bytes32"},{"name":"evmNodeWord","type":"bytes32"},
  {"name":"evmKeyHash","type":"bytes32"},{"name":"payee","type":"address"},{"name":"exposureDigest","type":"bytes32"}]},
 {"name":"changes","type":"uint64[]"}]}]},
{"name":"binding","type":"function","stateMutability":"view","inputs":[{"name":"ref","type":"bytes32"}],"outputs":[{"name":"b","type":"tuple","components":[
 {"name":"rootNodeWord","type":"bytes32"},{"name":"rootKeyHash","type":"bytes32"},{"name":"evmNodeWord","type":"bytes32"},{"name":"evmKeyHash","type":"bytes32"},
 {"name":"payee","type":"address"},{"name":"rootNodeID","type":"string"},{"name":"rootKey","type":"bytes"},{"name":"evmNodeID","type":"string"},{"name":"evmKey","type":"bytes"}]}]},
{"name":"change","type":"function","stateMutability":"view","inputs":[{"name":"changeId","type":"uint64"}],"outputs":[{"name":"v","type":"tuple","components":[
 {"name":"kind","type":"uint8"},{"name":"state","type":"uint8"},{"name":"rejectReason","type":"uint8"},{"name":"notBeforeProgress","type":"uint64"},
 {"name":"notBeforeTime","type":"uint64"},{"name":"activeRootEpoch","type":"uint64"},{"name":"scheduledAt","type":"uint64"},{"name":"payloadHash","type":"bytes32"},
 {"name":"boundTo","type":"bytes32"},{"name":"payload","type":"bytes"}]}]}
]`

var parsedABI = func() abi.ABI {
	a, err := abi.JSON(strings.NewReader(vrABI))
	if err != nil {
		panic(err)
	}
	return a
}()

type abiMember struct {
	Id             uint64
	Generation     uint64
	Weight         uint64
	RawWeight      uint64
	RootNodeWord   [32]byte
	RootKeyHash    [32]byte
	EvmNodeWord    [32]byte
	EvmKeyHash     [32]byte
	Payee          common.Address
	ExposureDigest [32]byte
}

type abiOutput struct {
	State             uint8
	Attempt           uint64
	ReservedProgress  uint64
	ExpiresAtProgress uint64
	Predecessor       [32]byte
	SourceModule      common.Address
	Native            bool
	ModuleTag         [32]byte
	MembersDigest     [32]byte
	KDigest           [32]byte
	ChangesDigest     [32]byte
	SnapshotDigest    [32]byte
	PolicyDigest      [32]byte
	OutputCommit      [32]byte
	InvalidReason     uint8
	InvalidAtProgress uint64
	Members           []abiMember
	Changes           []uint64
}

type abiBinding struct {
	RootNodeWord [32]byte
	RootKeyHash  [32]byte
	EvmNodeWord  [32]byte
	EvmKeyHash   [32]byte
	Payee        common.Address
	RootNodeID   string
	RootKey      []byte
	EvmNodeID    string
	EvmKey       []byte
}

type abiChange struct {
	Kind              uint8
	State             uint8
	RejectReason      uint8
	NotBeforeProgress uint64
	NotBeforeTime     uint64
	ActiveRootEpoch   uint64
	ScheduledAt       uint64
	PayloadHash       [32]byte
	BoundTo           [32]byte
	Payload           []byte
}

// RPC reads VR through an execution client: eth_getProof for the output state (verified against the certified state root) and eth_call
// for the served preimages, both at the certified block's hash.
type RPC struct {
	Client  *rpc.Client
	Pins    vrstate.Pins
	Timeout time.Duration
}

// ErrRead reports a VR read that failed.
var ErrRead = errors.New("vrschedule: reading VR")

func (r RPC) timeout() time.Duration {
	if r.Timeout > 0 {
		return r.Timeout
	}
	return 10 * time.Second
}

// OutputState is R's output state at a certified block, proven against its state root.
func (r RPC) OutputState(ctx context.Context, blockHash, stateRoot [32]byte, result vrschema.Word) ([]byte, error) {
	w, _, err := vrstate.BuildOutputWitness(ctx, evmstate.RPCProofSource{Client: r.Client, BlockHash: blockHash}, r.Pins, result)
	if err != nil {
		return nil, errors.Join(ErrRead, err)
	}
	if _, err := vrstate.VerifyOutput(w, stateRoot, r.Pins, result); err != nil {
		return nil, errors.Join(ErrRead, err)
	}
	return w, nil
}

func (r RPC) OpenOutput(ctx context.Context, blockHash, stateRoot [32]byte) (*vrhandoff.Output, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout())
	defer cancel()
	w, err := r.OutputState(ctx, blockHash, stateRoot, vrschema.Word{})
	if err != nil {
		return nil, err
	}
	s, err := vrstate.VerifyOutput(w, stateRoot, r.Pins, vrschema.Word{})
	if err != nil || s.OpenOutput == (vrschema.Word{}) {
		return nil, errors.Join(err)
	}
	res := s.OpenOutput
	if w, err = r.OutputState(ctx, blockHash, stateRoot, res); err != nil {
		return nil, err
	}
	if s, err = vrstate.VerifyOutput(w, stateRoot, r.Pins, res); err != nil {
		return nil, errors.Join(ErrRead, err)
	}
	if s.Output.State != vrschema.OutPublished {
		return nil, nil
	}
	members, changes, err := r.Served(ctx, blockHash, res)
	if err != nil {
		return nil, err
	}
	return &vrhandoff.Output{State: s, Members: members, Changes: changes}, nil
}

// Served reads R's served preimages at a block through VR's views: the captured members with their binding preimages and the bound
// changes with their payloads. Nothing here is verified; NewIntent hash-verifies it against the proven output record.
func (r RPC) Served(ctx context.Context, blockHash [32]byte, res vrschema.Word) ([]evmassign.Identity, []vrschema.RegistryChange, error) {
	var members []evmassign.Identity
	var changes []vrschema.RegistryChange
	ret, err := r.call(ctx, blockHash, "output", [32]byte(res))
	if err != nil {
		return nil, nil, err
	}
	v := abi.ConvertType(ret[0], new(abiOutput)).(*abiOutput)
	for _, m := range v.Members {
		ref := ethcrypto.Keccak256Hash(m.RootNodeWord[:], m.RootKeyHash[:], m.EvmNodeWord[:], m.EvmKeyHash[:], common.LeftPadBytes(m.Payee[:], 32))
		bret, err := r.call(ctx, blockHash, "binding", [32]byte(ref))
		if err != nil {
			return nil, nil, err
		}
		b := abi.ConvertType(bret[0], new(abiBinding)).(*abiBinding)
		id := vrschema.U64(m.Id)
		members = append(members, evmassign.Identity{StakingID: id[:], Generation: m.Generation, RootNodeID: b.RootNodeID, RootKey: bytes.Clone(b.RootKey),
			EVMNodeID: b.EvmNodeID, EVMKey: bytes.Clone(b.EvmKey), Weight: m.Weight, RawWeight: m.RawWeight, OperatorPayee: bytes.Clone(m.Payee[:]),
			ExposureDigest: bytes.Clone(m.ExposureDigest[:])})
	}
	for _, id := range v.Changes {
		cret, err := r.call(ctx, blockHash, "change", id)
		if err != nil {
			return nil, nil, err
		}
		c := abi.ConvertType(cret[0], new(abiChange)).(*abiChange)
		changes = append(changes, vrschema.RegistryChange{ID: id, Kind: uint64(c.Kind), Payload: bytes.Clone(c.Payload)})
	}
	return members, changes, nil
}

func (r RPC) call(ctx context.Context, blockHash [32]byte, method string, args ...any) ([]any, error) {
	data, err := parsedABI.Pack(method, args...)
	if err != nil {
		return nil, errors.Join(ErrRead, err)
	}
	var ret hexutil.Bytes
	to := common.Address(r.Pins.Registry)
	if err := r.Client.CallContext(ctx, &ret, "eth_call", map[string]any{"to": to, "data": hexutil.Bytes(data)},
		map[string]string{"blockHash": hexutil.Encode(blockHash[:])}); err != nil {
		return nil, errors.Join(ErrRead, fmt.Errorf("eth_call %s: %w", method, err))
	}
	out, err := parsedABI.Unpack(method, ret)
	if err != nil || len(out) != 1 {
		return nil, errors.Join(ErrRead, fmt.Errorf("decoding %s: %w", method, err))
	}
	return out, nil
}

// QueuedSchedules are the ScheduleActivation changes VR still holds (Queued, Scheduled or Bound) at the certified block (by hash), from its
// pendingChanges and change views by an eth_call at that block: the root's early warning before a change is bound into any output
// (design section 7.4). It is telemetry: nothing here is verified or enforced, and a failed read is simply no warning this time.
func (r RPC) QueuedSchedules(ctx context.Context, blockHash [32]byte) ([]vrschema.Activation, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout())
	defer cancel()
	c := vrclient.New(r.Client, common.Address(r.Pins.Registry))
	c.Block = hexutil.Encode(blockHash[:]) // the certified block by hash (EIP-1898), never by a number
	ids, err := c.PendingChanges(ctx)
	if err != nil {
		return nil, errors.Join(ErrRead, err)
	}
	var out []vrschema.Activation
	for _, id := range ids {
		ch, err := c.Change(ctx, id)
		if err != nil {
			return nil, errors.Join(ErrRead, err)
		}
		if ch.Kind != vrclient.KindScheduleActivation {
			continue
		}
		sc, err := vrschema.DecodeSchedule(ch.Payload)
		if err != nil {
			continue
		}
		out = append(out, vrschema.Activation{RuleID: sc.RuleID, ReleaseDigest: sc.ReleaseDigest, RootEpoch: sc.RootEpoch, NotBeforeUcTime: sc.NotBeforeUcTime,
			State: vrschema.ActActive, ChangeID: id})
	}
	return out, nil
}

// HeaderNumber is the EVM block number of the certified block: the execution header resolved by the certified block hash (eth_getBlockByHash),
// its hash recomputed from the header fields and required to equal the certified hash, and its number returned. It is the true height the
// freshness proof is compared with (design section 5.3: P at or after source.evmBlockNumber), never the shard round, which differs after a
// skipped round.
func (r RPC) HeaderNumber(ctx context.Context, blockHash [32]byte) (uint64, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout())
	defer cancel()
	var raw json.RawMessage
	if err := r.Client.CallContext(ctx, &raw, "eth_getBlockByHash", hexutil.Encode(blockHash[:]), false); err != nil {
		return 0, errors.Join(ErrRead, fmt.Errorf("eth_getBlockByHash: %w", err))
	}
	return VerifiedHeaderNumber(raw, blockHash)
}

// VerifiedHeaderNumber decodes an execution header (as eth_getBlockByHash serves it), recomputes its hash and returns its number only if the
// hash is the expected one: a client that serves another block, or altered fields, is refused.
func VerifiedHeaderNumber(raw json.RawMessage, want [32]byte) (uint64, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return 0, errors.Join(ErrRead, errors.New("the execution client does not hold the certified block"))
	}
	var h gethtypes.Header
	if err := json.Unmarshal(raw, &h); err != nil {
		return 0, errors.Join(ErrRead, fmt.Errorf("decoding the header: %w", err))
	}
	if h.Number == nil || !h.Number.IsUint64() {
		return 0, errors.Join(ErrRead, errors.New("the header carries no block number"))
	}
	if h.Hash() != common.Hash(want) {
		return 0, errors.Join(ErrRead, fmt.Errorf("the header's hash %x is not the certified block %x", h.Hash(), want))
	}
	return h.Number.Uint64(), nil
}
