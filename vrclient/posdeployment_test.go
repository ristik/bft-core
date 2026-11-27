package vrclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/vrschema"
)

// posChain is an execution client serving one PoS generation: VR, the PosElectionAdapter and the ElectionPolicy, at one head.
type posChain struct {
	genesis, head                   common.Hash
	vrCode, adapterCode, electCode  []byte
	recordedAdapterHash             [32]byte
	network, electionNetwork        [32]byte
	module                          common.Address
	tag                             [32]byte
	custody, election               common.Address
	adapterVR, adapterCustody       common.Address
	electionCustody, hook, registry common.Address
	chainID                         int64
	identities                      map[uint64]IdentityView
	fail                            string // a method that fails as an endpoint error
	blocks                          []string
}

func newPosChain() *posChain {
	c := &posChain{genesis: common.Hash{0x01}, head: common.Hash{0x09}, vrCode: []byte{0x60, 0x01}, adapterCode: []byte{0x60, 0x02},
		electCode: []byte{0x60, 0x03}, network: vrschema.DomainWord("pos.network"), module: PosAdapterAddress, tag: ModuleTagPoS,
		custody: common.HexToAddress("0xc0"), election: common.HexToAddress("0xe1"), chainID: 31337, identities: map[uint64]IdentityView{}}
	c.recordedAdapterHash = [32]byte(crypto.Keccak256Hash(c.adapterCode))
	c.electionNetwork, c.adapterVR, c.adapterCustody, c.electionCustody, c.hook, c.registry = c.network, DefaultRegistry, c.custody, c.custody, PosAdapterAddress, DefaultRegistry
	return c
}

var testNode, testKey = "evm-node-1", []byte{0x02, 0xaa}

func boundTo(node string, key []byte) Binding {
	return Binding{EvmNodeWord: NodeIDWord(node), EvmKeyHash: [32]byte(crypto.Keccak256Hash(key)), EvmNodeID: node, EvmKey: key}
}

func (c *posChain) pins() PosDeploymentReader {
	g, code := [32]byte(c.genesis), [32]byte(crypto.Keccak256Hash(c.vrCode))
	return PosDeploymentReader{RPC: posRPC{c}, GenesisHash: &g, RegistryCode: &code}
}

type posRPC struct{ c *posChain }

func (p posRPC) CallContext(_ context.Context, result any, method string, args ...any) error {
	if method == p.c.fail {
		return errors.New("connection refused")
	}
	v, err := p.c.eval(method, args)
	if err != nil {
		return err
	}
	b, _ := json.Marshal(v)
	return json.Unmarshal(b, result)
}

func (c *posChain) eval(method string, params []any) (any, error) {
	at := func(i int) {
		b, _ := json.Marshal(params[i])
		c.blocks = append(c.blocks, string(b))
	}
	switch method {
	case "eth_getBlockByNumber":
		if params[0] == "0x0" {
			return map[string]any{"hash": c.genesis}, nil
		}
		return map[string]any{"hash": c.head}, nil
	case "eth_chainId":
		return (*hexutil.Big)(big.NewInt(c.chainID)), nil
	case "eth_getCode":
		at(1)
		switch params[0].(common.Address) {
		case DefaultRegistry:
			return hexutil.Bytes(c.vrCode), nil
		case PosAdapterAddress:
			return hexutil.Bytes(c.adapterCode), nil
		case c.election:
			return hexutil.Bytes(c.electCode), nil
		}
		return hexutil.Bytes{}, nil
	case "eth_getStorageAt":
		at(2)
		if params[0].(common.Address) != c.election || params[1] != hexutil.EncodeUint64(electionRegistrySlot) {
			return common.Hash{}, nil
		}
		return common.Hash(vrschema.AddrWord(c.registry)), nil
	case "eth_call":
		at(1)
		arg := params[0].(map[string]any)
		to, data := arg["to"].(common.Address), arg["data"].(hexutil.Bytes)
		var a abi.ABI
		switch to {
		case DefaultRegistry:
			a = VRABI
		case PosAdapterAddress:
			a = posAdapterABI
		case c.election:
			a = electionDeploymentABI
		default:
			return hexutil.Bytes{}, nil
		}
		m, err := a.MethodById(data[:4])
		if err != nil {
			return nil, err
		}
		in, err := m.Inputs.Unpack(data[4:])
		if err != nil {
			return nil, err
		}
		var out any
		switch fmt.Sprintf("%s.%s", to.Hex()[38:], m.Name) {
		case DefaultRegistry.Hex()[38:] + ".config":
			out = ConfigView{Network: c.network}
		case DefaultRegistry.Hex()[38:] + ".activeModule":
			out = ModuleView{Module: c.module, CodeHash: c.recordedAdapterHash, Meta: ModuleMeta{ModuleTag: c.tag, LiabilityHolder: c.custody}}
		case DefaultRegistry.Hex()[38:] + ".identity":
			out = c.identities[in[0].(uint64)]
		case PosAdapterAddress.Hex()[38:] + ".VR":
			out = c.adapterVR
		case PosAdapterAddress.Hex()[38:] + ".ELECTION":
			out = c.election
		case PosAdapterAddress.Hex()[38:] + ".CUSTODY":
			out = c.adapterCustody
		case c.election.Hex()[38:] + ".network":
			out = c.electionNetwork
		case c.election.Hex()[38:] + ".custody":
			out = c.electionCustody
		case c.election.Hex()[38:] + ".hookCaller":
			out = c.hook
		default:
			return nil, fmt.Errorf("unexpected %s at %s", m.Name, to.Hex())
		}
		b, err := m.Outputs.Pack(out)
		return hexutil.Bytes(b), err
	}
	return nil, fmt.Errorf("unexpected %s", method)
}

// #1222: the deployment a signing authority's P85 pin is checked against is derived from VR, its active PoS module and that module's
// election, every read at one canonical block hash.
func TestPosDeploymentIsDerivedAtOneCanonicalBlock(t *testing.T) {
	c := newPosChain()
	c.identities[5] = IdentityView{Generation: 1, Current: boundTo(testNode, testKey)}
	d, err := c.pins().Read(context.Background(), testNode, testKey, []uint64{5})
	require.NoError(t, err)
	require.Equal(t, c.network, d.Network)
	require.Equal(t, c.election, d.Election)
	require.Equal(t, c.custody, d.Custody)
	require.Equal(t, int64(31337), d.ChainID.Int64())
	require.Equal(t, c.head, d.Block)
	want := fmt.Sprintf(`{"blockHash":"%s","requireCanonical":true}`, c.head.Hex())
	require.NotEmpty(t, c.blocks)
	for _, b := range c.blocks {
		require.Equal(t, want, b, "every state read names the one head block, canonical")
	}
}

func TestPosDeploymentStagedBindingNamesTheKey(t *testing.T) {
	c := newPosChain()
	c.identities[5] = IdentityView{Generation: 1, Current: boundTo("old-node", []byte{1}), StagedRef: [32]byte{1}, Staged: boundTo(testNode, testKey)}
	_, err := c.pins().Read(context.Background(), testNode, testKey, []uint64{5})
	require.NoError(t, err)
}

// Each link that is not the PoS generation's is refused (ErrVR, not retried); a read that fails, or an id not registered yet, is
// unavailable (ErrPosUnavailable: retry).
func TestPosDeploymentRefusals(t *testing.T) {
	word := [32]byte{0x77}
	for name, tc := range map[string]struct {
		mutate  func(c *posChain, r *PosDeploymentReader)
		pending bool
	}{
		"another genesis":           {mutate: func(c *posChain, _ *PosDeploymentReader) { c.genesis = common.Hash{0x02} }},
		"another VR code":           {mutate: func(c *posChain, _ *PosDeploymentReader) { c.vrCode = []byte{0x61} }},
		"configured word differs":   {mutate: func(_ *posChain, r *PosDeploymentReader) { r.NetworkWord = &word }},
		"module not the adapter":    {mutate: func(c *posChain, _ *PosDeploymentReader) { c.module = common.HexToAddress("0xff08") }},
		"module tag not P85":        {mutate: func(c *posChain, _ *PosDeploymentReader) { c.tag = ModuleTagPoA }},
		"adapter runtime differs":   {mutate: func(c *posChain, _ *PosDeploymentReader) { c.recordedAdapterHash = [32]byte{3} }},
		"adapter names another VR":  {mutate: func(c *posChain, _ *PosDeploymentReader) { c.adapterVR = common.HexToAddress("0xab") }},
		"adapter custody differs":   {mutate: func(c *posChain, _ *PosDeploymentReader) { c.adapterCustody = common.HexToAddress("0xab") }},
		"election network differs":  {mutate: func(c *posChain, _ *PosDeploymentReader) { c.electionNetwork = [32]byte{9} }},
		"election custody differs":  {mutate: func(c *posChain, _ *PosDeploymentReader) { c.electionCustody = common.HexToAddress("0xab") }},
		"election hook not adapter": {mutate: func(c *posChain, _ *PosDeploymentReader) { c.hook = common.HexToAddress("0xab") }},
		"election of another VR":    {mutate: func(c *posChain, _ *PosDeploymentReader) { c.registry = common.HexToAddress("0xab") }},
		"election has no code":      {mutate: func(c *posChain, _ *PosDeploymentReader) { c.electCode = nil }},
		"id bound to another key": {mutate: func(c *posChain, _ *PosDeploymentReader) {
			c.identities[5] = IdentityView{Generation: 1, Current: boundTo(testNode, []byte{9})}
		}},
		"node and key in different bindings": {mutate: func(c *posChain, _ *PosDeploymentReader) {
			c.identities[5] = IdentityView{Generation: 1, Current: boundTo(testNode, []byte{9}), StagedRef: [32]byte{1}, Staged: boundTo("other", testKey)}
		}},
		"id not registered yet": {mutate: func(c *posChain, _ *PosDeploymentReader) { delete(c.identities, 5) }, pending: true},
		"endpoint down":         {mutate: func(c *posChain, _ *PosDeploymentReader) { c.fail = "eth_call" }, pending: true},
		"chain id unavailable":  {mutate: func(c *posChain, _ *PosDeploymentReader) { c.fail = "eth_chainId" }, pending: true},
	} {
		t.Run(name, func(t *testing.T) {
			c := newPosChain()
			c.identities[5] = IdentityView{Generation: 1, Current: boundTo(testNode, testKey)}
			r := c.pins()
			tc.mutate(c, &r)
			_, err := r.Read(context.Background(), testNode, testKey, []uint64{5})
			require.Error(t, err)
			if tc.pending {
				require.ErrorIs(t, err, ErrPosUnavailable)
			} else {
				require.ErrorIs(t, err, ErrVR)
				require.NotErrorIs(t, err, ErrPosUnavailable)
			}
		})
	}
	_, err := PosDeploymentReader{RPC: posRPC{newPosChain()}}.Read(context.Background(), testNode, testKey, []uint64{5})
	require.ErrorIs(t, err, ErrVR, "the genesis and VR code pins are required")
}
