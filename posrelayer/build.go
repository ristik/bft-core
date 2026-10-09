// Package posrelayer builds, from the election and custody modules' getters, the inputs of the existing handoff pipeline for a published
// primary result: the identity records, the recovery authorization (K), the successor validators and the root/EVM bindings. It adds no
// format: the outputs are the files `root handoff evm-pop` and `evm-assemble` already read, and the storage proofs and possession proofs
// that evmassign.VerifyPrimary already judges are produced elsewhere (rootchain/evmstate). The builder is an untrusted tool: the root
// re-verifies every word at the last certified EVM state, so a wrong answer here is a refused Freeze, never an accepted one.
package posrelayer

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"

	"github.com/ethereum/go-ethereum/accounts/abi"
	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/evmassign"
)

var (
	// ErrBuild reports a result the builder cannot turn into a proposal, with the reason.
	ErrBuild = errors.New("posrelayer: cannot build the proposal")
	// ErrUnknownNode reports a node-id word no known peer id hashes to: the contracts hold only keccak256(peer id), so the operator names the
	// peer ids the committees are made of.
	ErrUnknownNode = errors.New("posrelayer: a node id word matches no known peer id")
)

// Reader performs the read-only calls (eth_call at one block; the caller pins it).
type Reader interface {
	Call(ctx context.Context, to [20]byte, data []byte) ([]byte, error)
}

// Modules are the deployed modules the builder reads.
type Modules struct {
	Election, Custody [20]byte
}

// Names resolves the opaque node-id words of the contracts back to peer ids.
type Names map[[32]byte]string

// NewNames indexes peer ids by evmassign.NodeIDWord.
func NewNames(peerIDs []string) (Names, error) {
	n := Names{}
	for _, id := range peerIDs {
		w, err := evmassign.NodeIDWord(id)
		if err != nil {
			return nil, err
		}
		n[w] = id
	}
	return n, nil
}

// RootContext is what the root reports for the attempt (`root handoff evm-context`) plus the EVM chain id.
type RootContext struct {
	Network      uint64
	Chain        uint64
	Predecessor  []byte                            // the root body id the authorization is based on
	Acknowledged *types.PartitionDescriptionRecord // the configuration of the last acknowledged assignment
}

// Output is the proposal's inputs.
type Output struct {
	ResultID      [32]byte
	Attempt       uint64
	Identities    []evmassign.Identity
	Authorization *evmassign.Authorization
	Validators    []*types.NodeInfo
	Bindings      []evmassign.Binding
	PopHashes     map[uint64][32]byte // custody id -> keccak256 of the stored possession signature
}

type frozen struct {
	ID, Generation, Weight, Raw uint64
	BindingHash                 [32]byte
}

type resultView struct {
	State, Reason                uint8
	Attempt, Progress, UcTime    uint64
	PolicyID                     uint32
	Origin, Predecessor          [32]byte
	AssignmentID, SnapshotDigest [32]byte
}

type publicationView struct {
	PrimaryHash, KCommit, Incumbent, IncumbentExposureDigest, IncumbentKeyDigest [32]byte
	PolicyDigest, ContractsDigest, SnapshotDigest, AssignmentID, PopSetDigest    [32]byte
	Published                                                                    bool
	PopCount                                                                     uint32
	Attempt                                                                      uint64
	Lost                                                                         bool
}

type delegationView struct {
	RootNodeID    [32]byte
	RootKey       []byte
	EvmNodeID     [32]byte
	EvmKey        []byte
	OperatorPayee ethcommon.Address
}

type exposureView struct {
	AssignmentID                      [32]byte
	ID, Generation, Weight, RawWeight uint64
	RootKeyHash, EvmKeyHash           [32]byte
	OperatorPayee                     ethcommon.Address
	ReferencesReleased                bool
	SessionLocks                      uint32
}

type builder struct {
	rd Reader
	m  Modules
}

func (b builder) call(ctx context.Context, to [20]byte, a abi.ABI, method string, args ...any) ([]any, error) {
	data, err := a.Pack(method, args...)
	if err != nil {
		return nil, err
	}
	ret, err := b.rd.Call(ctx, to, data)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrBuild, method, err)
	}
	out, err := a.Unpack(method, ret)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrBuild, method, err)
	}
	return out, nil
}

// decode converts an unpacked ABI value to T (a struct whose field names match the ABI components).
func decode[T any](v any) (T, error) {
	var zero T
	p, ok := abi.ConvertType(v, new(T)).(*T)
	if !ok || p == nil {
		return zero, errors.New("unexpected shape")
	}
	return *p, nil
}

func read[T any](ctx context.Context, b builder, to [20]byte, a abi.ABI, method string, args ...any) (T, error) {
	var zero T
	out, err := b.call(ctx, to, a, method, args...)
	if err != nil {
		return zero, err
	}
	if len(out) == 0 {
		return zero, fmt.Errorf("%w: %s returned nothing", ErrBuild, method)
	}
	v, err := decode[T](out[0])
	if err != nil {
		return zero, fmt.Errorf("%w: %s: %v", ErrBuild, method, err)
	}
	return v, nil
}

// OpenResult reads the election's unresolved result (zero when there is none).
func OpenResult(ctx context.Context, rd Reader, m Modules) ([32]byte, error) {
	b := builder{rd, m}
	out, err := b.call(ctx, m.Election, election, "openResult")
	if err != nil {
		return [32]byte{}, err
	}
	id, ok := out[0].([32]byte)
	if !ok {
		return [32]byte{}, fmt.Errorf("%w: openResult", ErrBuild)
	}
	return id, nil
}

// Build reads the published result and assembles the pipeline inputs. It refuses a result that is not published, or whose coverage was lost.
func Build(ctx context.Context, rd Reader, m Modules, resultID [32]byte, root RootContext, names Names) (*Output, error) {
	b := builder{rd, m}
	res, err := read[resultView](ctx, b, m.Election, election, "result", resultID)
	if err != nil {
		return nil, err
	}
	pub, err := read[publicationView](ctx, b, m.Election, election, "publication", resultID)
	if err != nil {
		return nil, err
	}
	switch {
	case !pub.Published:
		return nil, fmt.Errorf("%w: result %x is not published (its possession proofs are not complete)", ErrBuild, resultID)
	case pub.Lost:
		return nil, fmt.Errorf("%w: result %x lost a member's coverage", ErrBuild, resultID)
	case pub.AssignmentID != res.AssignmentID || pub.Incumbent != res.Predecessor:
		return nil, fmt.Errorf("%w: the publication does not describe the result", ErrBuild)
	case len(root.Predecessor) != evmassign.DigestLen || root.Acknowledged == nil:
		return nil, fmt.Errorf("%w: the root context is incomplete", ErrBuild)
	}
	members, err := read[[]frozen](ctx, b, m.Election, election, "frozenMembers", resultID)
	if err != nil {
		return nil, err
	}
	jIDs, err := b.identities(ctx, res.AssignmentID, names, false)
	if err != nil {
		return nil, fmt.Errorf("the primary: %w", err)
	}
	if len(jIDs.ids) != len(members) {
		return nil, fmt.Errorf("%w: %d exposures for %d frozen members", ErrBuild, len(jIDs.ids), len(members))
	}
	for i, f := range members {
		x := jIDs.ids[i]
		if cid, _ := evmassign.CustodyID(x.StakingID); cid != f.ID || x.Generation != f.Generation || x.Weight != f.Weight || x.RawWeight != f.Raw {
			return nil, fmt.Errorf("%w: exposure %d is not the election's frozen record", ErrBuild, i)
		}
		if jIDs.bindings[i] != f.BindingHash {
			return nil, fmt.Errorf("%w: member %d: the delegation is not the one the election froze", ErrBuild, f.ID)
		}
	}
	kIDs, err := b.identities(ctx, res.Predecessor, names, true)
	if err != nil {
		return nil, fmt.Errorf("the incumbent committee K: %w", err)
	}
	k := kIDs.ids
	kd, err := evmassign.IdentitiesDigest(k)
	if err != nil {
		return nil, err
	}
	base, err := evmassign.AssignmentHash(root.Acknowledged, kd)
	if err != nil {
		return nil, err
	}
	exposure, err := evmassign.ExposureCommit(k)
	if err != nil {
		return nil, err
	}
	auth := &evmassign.Authorization{Network: root.Network, Chain: root.Chain, Contracts: bytes.Clone(pub.ContractsDigest[:]), ResultID: bytes.Clone(resultID[:]),
		SnapshotDigest: bytes.Clone(pub.SnapshotDigest[:]), BaseRootBodyID: bytes.Clone(root.Predecessor), BaseAssignmentHash: base[:], K: k,
		ExposureDigest: exposure[:], Policies: bytes.Clone(pub.PolicyDigest[:])}
	if _, err := auth.Digest(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBuild, err)
	}
	out := &Output{ResultID: resultID, Attempt: pub.Attempt, Identities: jIDs.ids, Authorization: auth, PopHashes: map[uint64][32]byte{}}
	for _, x := range jIDs.ids {
		out.Validators = append(out.Validators, &types.NodeInfo{NodeID: x.EVMNodeID, SigKey: bytes.Clone(x.EVMKey), Stake: x.Weight})
		out.Bindings = append(out.Bindings, evmassign.Binding{RootNodeID: x.RootNodeID, EVMNodeID: x.EVMNodeID})
		cid, _ := evmassign.CustodyID(x.StakingID)
		var h [32]byte
		var o []any
		if o, err = b.call(ctx, m.Election, election, "popHash", resultID, cid); err != nil {
			return nil, err
		}
		h, _ = o[0].([32]byte)
		out.PopHashes[cid] = h
	}
	sort.Slice(out.Validators, func(i, j int) bool { return out.Validators[i].NodeID < out.Validators[j].NodeID })
	sort.Slice(out.Bindings, func(i, j int) bool { return out.Bindings[i].RootNodeID < out.Bindings[j].RootNodeID })
	return out, nil
}

// decodeExposure reads the exposures getter's tuple with checked assertions.
func decodeExposure(o []any) (exposureView, error) {
	var e exposureView
	var ok [8]bool
	e.AssignmentID, ok[0] = o[0].([32]byte)
	e.ID, ok[1] = o[1].(uint64)
	e.Generation, ok[2] = o[2].(uint64)
	e.Weight, ok[3] = o[3].(uint64)
	e.RawWeight, ok[4] = o[4].(uint64)
	e.RootKeyHash, ok[5] = o[5].([32]byte)
	e.EvmKeyHash, ok[6] = o[6].([32]byte)
	e.OperatorPayee, ok[7] = o[7].(ethcommon.Address)
	for i, good := range ok {
		if !good {
			return exposureView{}, fmt.Errorf("%w: exposures word %d has an unexpected type", ErrBuild, i)
		}
	}
	return e, nil
}

type committee struct {
	ids      []evmassign.Identity
	bindings [][32]byte
}

// identities reads one assignment's exposures as identity records (ascending by id): custody's weights, payee and lot digest, the keys and
// node ids from the identity's delegation of that generation. A key hash that custody committed and the delegation no longer matches means
// the keys rotated since: they are not recoverable from current state, and the operator takes K from the root instead.
func (b builder) identities(ctx context.Context, assignmentID [32]byte, names Names, rotationHint bool) (committee, error) {
	eids, err := read[[][32]byte](ctx, b, b.m.Custody, custody, "assignmentExposures", assignmentID)
	if err != nil {
		return committee{}, err
	}
	var out committee
	for _, eid := range eids {
		o, err := b.call(ctx, b.m.Custody, custody, "exposures", eid)
		if err != nil {
			return committee{}, err
		}
		if len(o) != 10 {
			return committee{}, fmt.Errorf("%w: exposures returned %d words", ErrBuild, len(o))
		}
		e, err := decodeExposure(o)
		if err != nil {
			return committee{}, err
		}
		if len(out.ids) > 0 {
			if prev, _ := evmassign.CustodyID(out.ids[len(out.ids)-1].StakingID); e.ID <= prev {
				return committee{}, fmt.Errorf("%w: custody reported the exposures of %x out of identity order", ErrBuild, assignmentID)
			}
		}
		if e.AssignmentID != assignmentID {
			return committee{}, fmt.Errorf("%w: exposure %x belongs to another assignment", ErrBuild, eid)
		}
		lo, err := b.call(ctx, b.m.Custody, custody, "exposureLots", eid)
		if err != nil {
			return committee{}, err
		}
		lots := toBig(lo[0])
		lotIDs := make([]uint64, len(lots))
		for i, l := range lots {
			if !l.IsUint64() {
				return committee{}, fmt.Errorf("%w: lot id out of range", ErrBuild)
			}
			lotIDs[i] = l.Uint64()
		}
		do, err := b.call(ctx, b.m.Election, election, "delegation", e.ID, e.Generation)
		if err != nil {
			return committee{}, err
		}
		d, err := decode[delegationView](do[0])
		if err != nil {
			return committee{}, fmt.Errorf("%w: delegation: %v", ErrBuild, err)
		}
		bh, _ := do[1].([32]byte)
		if ethcrypto.Keccak256Hash(d.RootKey) != e.RootKeyHash || ethcrypto.Keccak256Hash(d.EvmKey) != e.EvmKeyHash {
			hint := ""
			if rotationHint {
				hint = " (the keys rotated since this committee was elected; supply K from the root)"
			}
			return committee{}, fmt.Errorf("%w: member %d: the delegation's keys are not the ones custody committed%s", ErrBuild, e.ID, hint)
		}
		rootID, ok1 := names[d.RootNodeID]
		evmID, ok2 := names[d.EvmNodeID]
		if !ok1 || !ok2 {
			return committee{}, fmt.Errorf("%w: member %d", ErrUnknownNode, e.ID)
		}
		var sid [evmassign.StakingIDLen]byte
		binary.BigEndian.PutUint64(sid[evmassign.StakingIDLen-8:], e.ID)
		ld := evmassign.LotsDigest(lotIDs)
		out.ids = append(out.ids, evmassign.Identity{StakingID: sid[:], Generation: e.Generation, RootNodeID: rootID, RootKey: d.RootKey, EVMNodeID: evmID,
			EVMKey: d.EvmKey, Weight: e.Weight, RawWeight: e.RawWeight, OperatorPayee: e.OperatorPayee[:], ExposureDigest: ld[:]})
		out.bindings = append(out.bindings, bh)
	}
	return out, nil
}

// RPCReader is a Reader over an execution client's eth_call. All calls are made at one block: Pin reads the head once and the reader keeps
// it, so a build of ~4N+4 reads describes one state and an operator never sees a refusal that only a block boundary explains.
type RPCReader struct {
	Client *rpc.Client
	// Block is the block every call is made at ("latest" when empty: only for callers that accept a moving head).
	Block string
}

// Pin returns a reader that reads at the current head.
func (r RPCReader) Pin(ctx context.Context) (RPCReader, error) {
	var head hexutil.Uint64
	if err := r.Client.CallContext(ctx, &head, "eth_blockNumber"); err != nil {
		return r, err
	}
	r.Block = hexutil.EncodeUint64(uint64(head))
	return r, nil
}

// Call implements Reader.
func (r RPCReader) Call(ctx context.Context, to [20]byte, data []byte) ([]byte, error) {
	var out hexutil.Bytes
	arg := map[string]any{"to": ethcommon.Address(to), "data": hexutil.Bytes(data)}
	block := r.Block
	if block == "" {
		block = "latest"
	}
	if err := r.Client.CallContext(ctx, &out, "eth_call", arg, block); err != nil {
		return nil, err
	}
	return out, nil
}

// CheckPoPs orders the relayer's collected EVM possession proofs by member and checks them against what the election stored: one proof per
// frozen member, by the member's own key, whose signature hashes to the stored proof hash. (The root checks the signatures themselves.)
func CheckPoPs(out *Output, pops []evmassign.EVMPoP) ([]evmassign.EVMPoP, error) {
	byID := map[uint64]evmassign.EVMPoP{}
	for _, p := range pops {
		if _, dup := byID[p.ID]; dup {
			return nil, fmt.Errorf("%w: two proofs for member %d", ErrBuild, p.ID)
		}
		byID[p.ID] = p
	}
	ordered := make([]evmassign.EVMPoP, 0, len(out.Identities))
	for _, x := range out.Identities {
		cid, err := evmassign.CustodyID(x.StakingID)
		if err != nil {
			return nil, err
		}
		p, ok := byID[cid]
		if !ok {
			return nil, fmt.Errorf("%w: no possession proof for member %d", ErrBuild, cid)
		}
		if !bytes.Equal(p.EVMKey, x.EVMKey) || ethcrypto.Keccak256Hash(p.Signature) != out.PopHashes[cid] {
			return nil, fmt.Errorf("%w: member %d's proof is not the one the election stored", ErrBuild, cid)
		}
		ordered = append(ordered, p)
		delete(byID, cid)
	}
	if len(byID) != 0 {
		return nil, fmt.Errorf("%w: %d proofs for non-members", ErrBuild, len(byID))
	}
	return ordered, nil
}
