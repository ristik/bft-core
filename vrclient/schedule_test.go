package vrclient

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/vrrules"
	"github.com/unicitynetwork/bft-core/vrschema"
)

// schedChain is a VR that answers the schedule reads and records the block each call named.
type schedChain struct {
	head      common.Hash
	code      []byte
	known     uint64
	acts      []Activation
	pending   []uint64
	changes   map[uint64]ChangeView
	count     uint32 // reported activationCount (len(acts) when zero and acts set)
	genesis   common.Hash
	network   [32]byte
	blocks    []string
	roundTrip int
}

func (c *schedChain) eval(method string, params []any) (any, error) {
	blk := func(v any) string { b, _ := json.Marshal(v); return string(b) }
	switch method {
	case "eth_getBlockByNumber":
		if params[0] == "0x0" {
			return map[string]any{"hash": c.genesis, "number": hexutil.Uint64(0)}, nil
		}
		return map[string]any{"hash": c.head, "number": hexutil.Uint64(9)}, nil
	case "eth_getBlockByHash":
		if params[0].(common.Hash) != c.head {
			return nil, nil
		}
		return map[string]any{"hash": c.head, "number": hexutil.Uint64(9)}, nil
	case "eth_getCode":
		c.blocks = append(c.blocks, blk(params[1]))
		return hexutil.Bytes(c.code), nil
	case "eth_call":
		c.blocks = append(c.blocks, blk(params[1]))
		arg := params[0].(map[string]any)
		data := arg["data"].(hexutil.Bytes)
		m, err := VRABI.MethodById(data[:4])
		if err != nil {
			return nil, err
		}
		in, err := m.Inputs.Unpack(data[4:])
		if err != nil {
			return nil, err
		}
		var out any
		switch m.Name {
		case "config":
			out = ConfigView{Network: c.network, KnownRootEpoch: c.known}
		case "activationCount":
			n := c.count
			if n == 0 {
				n = uint32(len(c.acts))
			}
			out = n
		case "activationAt":
			out = c.acts[in[0].(uint32)]
		case "pendingChanges":
			out = c.pending
		case "change":
			out = c.changes[in[0].(uint64)]
		default:
			return nil, fmt.Errorf("unexpected %s", m.Name)
		}
		b, err := m.Outputs.Pack(out)
		return hexutil.Bytes(b), err
	}
	return nil, fmt.Errorf("unexpected %s", method)
}

type plainRPC struct{ c *schedChain }

func (p plainRPC) CallContext(_ context.Context, result any, method string, args ...any) error {
	p.c.roundTrip++
	v, err := p.c.eval(method, args)
	if err != nil {
		return err
	}
	b, _ := json.Marshal(v)
	return json.Unmarshal(b, result)
}

type batchRPC struct{ plainRPC }

func (p batchRPC) BatchCallContext(_ context.Context, b []rpc.BatchElem) error {
	p.c.roundTrip++
	for i := range b {
		v, err := p.c.eval(b[i].Method, b[i].Args)
		if err != nil {
			b[i].Error = err
			continue
		}
		raw, _ := json.Marshal(v)
		if err := json.Unmarshal(raw, b[i].Result); err != nil {
			b[i].Error = err
		}
	}
	return nil
}

func TestScheduleSourcePinnedRead(t *testing.T) {
	code := []byte{0x60, 0x01}
	hash := [32]byte(crypto.Keccak256Hash(code))
	rule := vrschema.RuleID("future-rule")
	ch := &schedChain{head: common.Hash{0xab}, code: code, known: 6,
		acts:    []Activation{{RuleId: rule, ReleaseDigest: [32]byte{1}, RootEpoch: 9, State: 1, ChangeId: 4}},
		pending: []uint64{7}}
	raw, err := vrschema.EncodeChange(KindScheduleActivation, vrschema.RuleID("later"), vrschema.Word{2}, uint64(12), uint64(0), "x")
	require.NoError(t, err)
	ch.changes = map[uint64]ChangeView{7: {Kind: KindScheduleActivation, State: 1, Payload: raw}}

	for name, rpcc := range map[string]RPC{"batch": batchRPC{plainRPC{ch}}, "single": plainRPC{ch}} {
		ch.blocks, ch.roundTrip = nil, 0
		src := ScheduleSource{Client: New(rpcc, common.Address{}), RegistryCode: &hash}
		ev, err := src.Read(context.Background())
		require.NoError(t, err, name)
		require.Equal(t, [32]byte(ch.head), ev.BlockHash)
		require.EqualValues(t, 6, ev.CoveredEpoch)
		require.Len(t, ev.Schedule, 1)
		require.EqualValues(t, 9, ev.Schedule[0].RootEpoch)
		require.Len(t, ev.Pending, 1)
		require.EqualValues(t, 12, ev.Pending[0].Activation.RootEpoch)
		want := fmt.Sprintf(`{"blockHash":"%s"}`, ch.head.Hex())
		require.NotEmpty(t, ch.blocks)
		for _, b := range ch.blocks {
			require.JSONEq(t, want, b, "%s: every call is pinned to the one block hash, never latest", name)
		}
		if name == "batch" {
			require.LessOrEqual(t, ch.roundTrip, 4, "one pinned batch per round")
		}
	}

	// a different deployment is refused, as is a registry other than the genesis constant
	wrong := [32]byte{1}
	_, err = ScheduleSource{Client: New(plainRPC{ch}, common.Address{}), RegistryCode: &wrong}.Read(context.Background())
	require.ErrorIs(t, err, ErrVR)
	_, err = ScheduleSource{Client: New(plainRPC{ch}, common.Address{1})}.Read(context.Background())
	require.ErrorIs(t, err, ErrVR)

	// two generations with the same code and different schedules: the genesis, network word and certified-block pins tell them apart
	genesis := [32]byte{0x6e}
	ch.genesis = common.Hash(genesis)
	ch.network = [32]byte{0x01}
	ch.count = 0
	mk := func(g, n *[32]byte, anchor func(context.Context) ([32]byte, uint64, error)) error {
		_, err := ScheduleSource{Client: New(plainRPC{ch}, common.Address{}), RegistryCode: &hash, GenesisHash: g, NetworkWord: n, Anchor: anchor}.Read(context.Background())
		return err
	}
	otherGenesis, otherNet := [32]byte{0x6f}, [32]byte{0x02}
	require.NoError(t, mk(&genesis, &ch.network, nil))
	require.ErrorIs(t, mk(&otherGenesis, nil, nil), ErrVR, "another generation's genesis")
	require.ErrorIs(t, mk(nil, &otherNet, nil), ErrVR, "another generation's network word")
	own := func(context.Context) ([32]byte, uint64, error) { return [32]byte(ch.head), 9, nil }
	require.NoError(t, mk(&genesis, nil, own), "the node's own certified block is held by the endpoint")
	foreign := func(context.Context) ([32]byte, uint64, error) { return [32]byte{0xde}, 9, nil }
	require.ErrorIs(t, mk(&genesis, nil, foreign), ErrVR, "a block the endpoint does not hold: not this branch")

	// a count past VR's bound is refused before anything is allocated or read
	ch.count = 65
	_, err = ScheduleSource{Client: New(plainRPC{ch}, common.Address{}), RegistryCode: &hash}.Read(context.Background())
	require.ErrorIs(t, err, ErrVR)
}

var _ vrrules.Source = ScheduleSource{}
