package vrclient

// The P85 deployment a signing authority's pin is checked against (#1222). The authority's P85 possession signatures are valid in one
// election, the digest domain being the network word, the chain id and the ElectionPolicy address, and for identity ids its key may
// prove for. The operator does not state these alone: the authority derives them from its own execution client, under the pins
// its activation fence already relies on. Those pins are the execution genesis hash and VR's runtime code hash from the b1 profile, and
// they identify the deployment. Every read is made at one canonical block hash:
//
//   - the network word is VR.config().network;
//   - VR.activeModule() is the PosElectionAdapter at 0xff..07, with the P85 module tag and a runtime that hashes to the code hash VR
//     recorded for it;
//   - the election is the adapter's ELECTION(). The adapter's VR() and the election's registry slot point back to VR, both sides name
//     the same custody (VR's liability holder), the election's hook caller is the adapter, and the election reports VR's network word;
//   - each id is a VR identity whose current or staged binding names the authority's EVM node and key together.
//
// A malicious execution client can still fabricate these replies. The reader trusts it as the fence does; it is not a proof.

import (
	"context"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi"
	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	"github.com/unicitynetwork/bft-core/vrschema"
)

// PosAdapterAddress is the PosElectionAdapter's genesis address (0xff..07), the module of a PoS generation.
var PosAdapterAddress = ethcommon.HexToAddress("0xff00000000000000000000000000000000000007")

// ErrPosUnavailable is a P85 deployment read that could not be made now (the endpoint failed, or an id is not registered at the block
// read): nothing was found wrong, and the read may be retried.
var ErrPosUnavailable = errors.New("vrclient: the P85 deployment cannot be read now")

// electionRegistrySlot is ElectionPolicy's `registry` (an internal address with no getter): the VR the election belongs to.
const electionRegistrySlot = 24

var posAdapterABI = mustABI(`[
 {"type":"function","name":"VR","stateMutability":"view","inputs":[],"outputs":[{"name":"","type":"address"}]},
 {"type":"function","name":"ELECTION","stateMutability":"view","inputs":[],"outputs":[{"name":"","type":"address"}]},
 {"type":"function","name":"CUSTODY","stateMutability":"view","inputs":[],"outputs":[{"name":"","type":"address"}]}]`)

var electionDeploymentABI = mustABI(`[
 {"type":"function","name":"network","stateMutability":"view","inputs":[],"outputs":[{"name":"","type":"bytes32"}]},
 {"type":"function","name":"custody","stateMutability":"view","inputs":[],"outputs":[{"name":"","type":"address"}]},
 {"type":"function","name":"hookCaller","stateMutability":"view","inputs":[],"outputs":[{"name":"","type":"address"}]}]`)

// PosDeploymentReader reads the P85 deployment of one generation through an execution client.
type PosDeploymentReader struct {
	RPC RPC
	// GenesisHash is the deployment's execution genesis hash and RegistryCode VR's pinned runtime code hash: both required.
	GenesisHash, RegistryCode *[32]byte
	// NetworkWord, when set, is the network word the authority's configuration names (the registration policy's or --vr-network-word):
	// VR must report it.
	NetworkWord *[32]byte
}

// PosDeployment is what PosDeploymentReader.Read derived, at Block.
type PosDeployment struct {
	Block    ethcommon.Hash
	Network  [32]byte
	ChainID  *big.Int
	Election ethcommon.Address
	Custody  ethcommon.Address
}

func unavailable(what string, err error) error {
	return fmt.Errorf("%w: %s: %w", ErrPosUnavailable, what, err)
}

// Read derives the deployment and checks that every id's VR binding names evmNodeID with evmKey. A failure wrapped in
// ErrPosUnavailable may be retried; any other failure is a deployment, or an id, that is not this authority's.
func (r PosDeploymentReader) Read(ctx context.Context, evmNodeID string, evmKey []byte, ids []uint64) (PosDeployment, error) {
	var out PosDeployment
	if r.RPC == nil || r.GenesisHash == nil || r.RegistryCode == nil {
		return out, fmt.Errorf("%w: the P85 deployment is read only with the execution genesis hash and VR's code hash pinned", ErrVR)
	}
	var g struct {
		Hash ethcommon.Hash `json:"hash"`
	}
	if err := r.RPC.CallContext(ctx, &g, "eth_getBlockByNumber", "0x0", false); err != nil {
		return out, unavailable("the genesis block", err)
	}
	if g.Hash != ethcommon.Hash(*r.GenesisHash) {
		return out, fmt.Errorf("%w: the endpoint's execution genesis %s is not this deployment's %s", ErrVR, g.Hash.Hex(), ethcommon.Hash(*r.GenesisHash).Hex())
	}
	var head struct {
		Hash ethcommon.Hash `json:"hash"`
	}
	if err := r.RPC.CallContext(ctx, &head, "eth_getBlockByNumber", "latest", false); err != nil {
		return out, unavailable("the head block", err)
	}
	if head.Hash == (ethcommon.Hash{}) {
		return out, unavailable("the head block", errors.New("no hash"))
	}
	out.Block = head.Hash
	c := New(r.RPC, DefaultRegistry)
	c.BlockHash, c.Canonical = head.Hash.Hex(), true
	at := c.blockParam()
	code := func(a ethcommon.Address) ([32]byte, error) {
		var b hexutil.Bytes
		if err := r.RPC.CallContext(ctx, &b, "eth_getCode", a, at); err != nil {
			return [32]byte{}, unavailable("the code at "+a.Hex(), err)
		}
		if len(b) == 0 {
			return [32]byte{}, fmt.Errorf("%w: no code at %s in block %s", ErrVR, a.Hex(), head.Hash.Hex())
		}
		return [32]byte(ethcrypto.Keccak256Hash(b)), nil
	}
	addr := func(to ethcommon.Address, method string) (ethcommon.Address, error) {
		var v ethcommon.Address
		if err := c.call(ctx, to, posAdapterOrElection(method), method, &v); err != nil {
			return v, unavailable(method, err)
		}
		return v, nil
	}

	if h, err := code(DefaultRegistry); err != nil {
		return out, err
	} else if h != *r.RegistryCode {
		return out, fmt.Errorf("%w: the code at %s in block %s is not the pinned VR generation", ErrVR, DefaultRegistry.Hex(), head.Hash.Hex())
	}
	cfg, err := c.Config(ctx)
	if err != nil {
		return out, unavailable("VR config", err)
	}
	if cfg.Network == ([32]byte{}) {
		return out, fmt.Errorf("%w: VR reports no network word", ErrVR)
	}
	if r.NetworkWord != nil && cfg.Network != *r.NetworkWord {
		return out, fmt.Errorf("%w: VR's network word %x is not the configured %x", ErrVR, cfg.Network, *r.NetworkWord)
	}
	out.Network = cfg.Network

	m, err := c.ActiveModule(ctx)
	if err != nil {
		return out, unavailable("VR activeModule", err)
	}
	if m.Module != PosAdapterAddress || m.Meta.ModuleTag != ModuleTagPoS {
		return out, fmt.Errorf("%w: VR's active module is %s with tag %x, not the PoS adapter %s", ErrVR, m.Module.Hex(), m.Meta.ModuleTag, PosAdapterAddress.Hex())
	}
	if h, err := code(PosAdapterAddress); err != nil {
		return out, err
	} else if m.CodeHash == ([32]byte{}) || h != m.CodeHash {
		return out, fmt.Errorf("%w: the adapter's runtime hashes to %x, VR recorded %x", ErrVR, h, m.CodeHash)
	}
	custody := m.Meta.LiabilityHolder
	if custody == (ethcommon.Address{}) {
		return out, fmt.Errorf("%w: the PoS adapter names no liability holder", ErrVR)
	}
	vr, err := addr(PosAdapterAddress, "VR")
	if err != nil {
		return out, err
	}
	election, err := addr(PosAdapterAddress, "ELECTION")
	if err != nil {
		return out, err
	}
	adapterCustody, err := addr(PosAdapterAddress, "CUSTODY")
	if err != nil {
		return out, err
	}
	if vr != DefaultRegistry || election == (ethcommon.Address{}) || adapterCustody != custody {
		return out, fmt.Errorf("%w: the adapter names VR %s, election %s and custody %s (VR's holder %s)", ErrVR, vr.Hex(), election.Hex(), adapterCustody.Hex(), custody.Hex())
	}
	if _, err := code(election); err != nil {
		return out, err
	}
	var network [32]byte
	if err := c.call(ctx, election, electionDeploymentABI, "network", &network); err != nil {
		return out, unavailable("the election's network", err)
	}
	electionCustody, err := addr(election, "custody")
	if err != nil {
		return out, err
	}
	hook, err := addr(election, "hookCaller")
	if err != nil {
		return out, err
	}
	var registry ethcommon.Hash
	if err := r.RPC.CallContext(ctx, &registry, "eth_getStorageAt", election, hexutil.EncodeUint64(electionRegistrySlot), at); err != nil {
		return out, unavailable("the election's registry", err)
	}
	switch {
	case network != cfg.Network:
		return out, fmt.Errorf("%w: the election reports network word %x, VR %x", ErrVR, network, cfg.Network)
	case electionCustody != custody:
		return out, fmt.Errorf("%w: the election names custody %s, VR's holder is %s", ErrVR, electionCustody.Hex(), custody.Hex())
	case hook != PosAdapterAddress:
		return out, fmt.Errorf("%w: the election's hook caller is %s, not the adapter", ErrVR, hook.Hex())
	case [32]byte(registry) != vrschema.AddrWord(DefaultRegistry):
		return out, fmt.Errorf("%w: the election belongs to registry %x, not VR", ErrVR, registry)
	}
	out.Election, out.Custody = election, custody

	var chain hexutil.Big
	if err := r.RPC.CallContext(ctx, &chain, "eth_chainId"); err != nil {
		return out, unavailable("the chain id", err)
	}
	out.ChainID = (*big.Int)(&chain)

	nodeWord, keyHash := NodeIDWord(evmNodeID), [32]byte(ethcrypto.Keccak256Hash(evmKey))
	names := func(b Binding) bool { return b.EvmNodeWord == nodeWord && b.EvmKeyHash == keyHash }
	for _, id := range ids {
		v, err := c.Identity(ctx, id)
		if err != nil {
			return out, unavailable(fmt.Sprintf("VR identity %d", id), err)
		}
		if !v.Known() {
			return out, fmt.Errorf("%w: VR has no identity %d at block %s", ErrPosUnavailable, id, head.Hash.Hex())
		}
		if !names(v.Current) && (v.StagedRef == ([32]byte{}) || !names(v.Staged)) {
			return out, fmt.Errorf("%w: VR identity %d binds neither in its current nor in its staged binding this node with this key", ErrVR, id)
		}
	}
	return out, nil
}

func posAdapterOrElection(method string) abi.ABI {
	if _, ok := posAdapterABI.Methods[method]; ok {
		return posAdapterABI
	}
	return electionDeploymentABI
}
