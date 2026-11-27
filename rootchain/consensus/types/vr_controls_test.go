package types_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/vrschema"
	basetypes "github.com/unicitynetwork/bft-go-base/types"
)

func unhex(t *testing.T, s string) []byte {
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	require.NoError(t, err)
	return b
}

// TestVRControlEncodeVectors: every frozen control.encode item decodes as a VR-mode PosControl, re-encodes to exactly the vector's
// bytes and carries the vector's fields; vrschema's strict decoder accepts what this codec encodes.
func TestVRControlEncodeVectors(t *testing.T) {
	raw, err := os.ReadFile("../../../testvectors/validator-registry/encoding.json")
	require.NoError(t, err)
	var f struct {
		Vectors []struct {
			Name   string          `json:"name"`
			Op     string          `json:"op"`
			Input  json.RawMessage `json:"input"`
			Expect struct {
				Bytes string `json:"bytes"`
			} `json:"expect"`
		} `json:"vectors"`
	}
	type input struct {
		ChainID       string  `json:"chainId"`
		Data          string  `json:"data"`
		Network       flexU64 `json:"network"`
		Op            flexU64 `json:"op"`
		OrderingEpoch flexU64 `json:"orderingEpoch"`
		OrderingRound flexU64 `json:"orderingRound"`
		Registry      string  `json:"registry"`
		WitnessHash   string  `json:"witnessHash"`
	}
	require.NoError(t, json.Unmarshal(raw, &f))
	n := 0
	for _, v := range f.Vectors {
		if v.Op != "control.encode" || v.Expect.Bytes == "" {
			continue
		}
		var in input
		require.NoError(t, json.Unmarshal(v.Input, &in), v.Name)
		b := unhex(t, v.Expect.Bytes)
		var c rctypes.PosControl
		require.NoError(t, c.UnmarshalCBOR(b), v.Name)
		require.True(t, c.Registry, v.Name)
		require.Equal(t, uint64(in.Op), c.Op, v.Name)
		require.Equal(t, uint64(in.Network), c.Network, v.Name)
		require.Equal(t, uint64(in.OrderingEpoch), c.OrderingEpoch, v.Name)
		require.Equal(t, uint64(in.OrderingRound), c.OrderingRound, v.Name)
		require.Equal(t, unhex(t, in.Registry), c.Custody[:], v.Name)
		require.Equal(t, unhex(t, in.ChainID), c.ChainID[:], v.Name)
		require.Equal(t, unhex(t, in.WitnessHash), c.WitnessHash[:], v.Name)
		require.Equal(t, unhex(t, in.Data), []byte(append([]byte{}, c.Data...)), v.Name)
		again, err := c.MarshalCBOR()
		require.NoError(t, err)
		require.Equal(t, b, again, v.Name)
		op, _, _, err := vrschema.DecodeVRControl(again)
		require.NoError(t, err, v.Name)
		require.Equal(t, c.Op, op)
		require.NoError(t, rctypesValidate([]rctypes.PosControl{c}), v.Name)
		n++
	}
	require.Equal(t, 7, n, "every positive control.encode vector")
}

func rctypesValidate(cs []rctypes.PosControl) error {
	p := rctypes.Payload{Version: rctypes.VersionHandoff, PosControls: cs}
	return p.IsValid()
}

func vrBase(op uint64) rctypes.PosControl {
	return rctypes.PosControl{Registry: true, Network: 3, Custody: vrschema.ValidatorRegistry, OrderingEpoch: 5, OrderingRound: 900, Op: op}
}

// The refusals of the frozen control.encode vectors, judged by this codec.
func TestVRControlRefusals(t *testing.T) {
	view := vrBase(rctypes.OpHandoffView)
	view.View = &rctypes.ViewContext{IntentDigest: [32]byte{1}, View: 0}
	require.ErrorIs(t, view.Validate(), rctypes.ErrPosControl, "view 0")
	view.View.View = 1
	require.NoError(t, view.Validate())
	withData := view
	withData.Data = make([]byte, 32)
	require.ErrorIs(t, withData.Validate(), rctypes.ErrPosControl, "HandoffView with data")
	withWitness := view
	withWitness.WitnessHash = [32]byte{9}
	require.ErrorIs(t, withWitness.Validate(), rctypes.ErrPosControl, "HandoffView with witness")

	sup := vrBase(rctypes.OpRuleSupport)
	sup.Support = []rctypes.SupportCommitment{}
	require.ErrorIs(t, sup.Validate(), rctypes.ErrPosControl, "RuleSupport empty")
	c := func(id, rule byte) rctypes.SupportCommitment {
		w := func(b byte) []byte { x := make([]byte, 32); x[31] = b; return x }
		return rctypes.SupportCommitment{Network: 3, StakingID: w(id), Generation: 1, RootKeyHash: w(7), BindingRef: w(9), RuleID: w(rule), ReleaseDigest: w(8), Sig: make([]byte, 65)}
	}
	sup.Support = []rctypes.SupportCommitment{c(1, 2), c(1, 1)}
	require.ErrorIs(t, sup.Validate(), rctypes.ErrPosControl, "RuleSupport unsorted")
	sup.Support = []rctypes.SupportCommitment{c(1, 1), c(1, 2), c(2, 1)}
	require.NoError(t, sup.Validate())

	rej := vrBase(rctypes.OpRejectResult)
	rej.Reject = &rctypes.RejectContext{}
	rej.Data = make([]byte, 32)
	require.ErrorIs(t, rej.Validate(), rctypes.ErrPosControl, "RejectResult v1 width")
	rej.Data = make([]byte, 128)
	require.NoError(t, rej.Validate())

	six := vrBase(6)
	require.ErrorIs(t, six.Validate(), rctypes.ErrPosControl, "op 6")

	p85 := rctypes.PosControl{Network: 3, Op: rctypes.OpRejectResult, Reject: &rctypes.RejectContext{}, Data: make([]byte, 32)}
	require.ErrorIs(t, rctypesValidate([]rctypes.PosControl{p85, view}), rctypes.ErrPosControl, "P85 and VR controls never share a block")
	require.ErrorIs(t, rctypesValidate([]rctypes.PosControl{view, view}), rctypes.ErrPosControl, "at most one HandoffView")
	require.ErrorIs(t, rctypesValidate([]rctypes.PosControl{view, sup}), rctypes.ErrPosControl, "RuleSupport before HandoffView")
	require.NoError(t, rctypesValidate([]rctypes.PosControl{rej, sup, view}))

	// round trip of the root-only ops through both codecs
	for _, x := range []rctypes.PosControl{sup, view} {
		b, err := x.MarshalCBOR()
		require.NoError(t, err)
		var back rctypes.PosControl
		require.NoError(t, back.UnmarshalCBOR(b))
		again, err := back.MarshalCBOR()
		require.NoError(t, err)
		require.Equal(t, b, again)
		_, _, _, err = vrschema.DecodeVRControl(b)
		require.NoError(t, err)
	}
}

// flexU64 is a vector integer, a JSON number or a decimal string.
type flexU64 uint64

func (f *flexU64) UnmarshalJSON(b []byte) error {
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		n = json.Number(s)
	}
	v, err := strconv.ParseUint(n.String(), 10, 64)
	*f = flexU64(v)
	return err
}

// TestVRControlNarrowWordsMatchTheFrozenCodec (review #1172, sol 1): the payload words keep their frozen widths (HolderRetirement's
// holder uint8, OutputRejected's reason uint8 and readyBitmap uint16). This codec and vrschema's accept and refuse the same items, both
// through the encoders and on raw malformed items.
func TestVRControlNarrowWordsMatchTheFrozenCodec(t *testing.T) {
	word := func(v uint64) []byte { w := vrschema.U64(v); return w[:] }
	cat := func(ws ...[]byte) []byte {
		var out []byte
		for _, w := range ws {
			out = append(out, w...)
		}
		return out
	}
	h32 := make([]byte, 32)
	h32[0] = 1
	cases := []struct {
		name string
		op   uint64
		data []byte
		ok   bool
	}{
		{"holder 255", rctypes.OpRetirement, cat(word(255), word(1), word(2), h32), true},
		{"holder 256", rctypes.OpRetirement, cat(word(256), word(1), word(2), h32), false},
		{"id 2^64-1", rctypes.OpRetirement, cat(word(1), word(^uint64(0)), word(2), h32), true},
		{"reason 255", rctypes.OpRejectResult, cat(h32, word(255), word(0), word(0)), true},
		{"reason 256", rctypes.OpRejectResult, cat(h32, word(256), word(0), word(0)), false},
		{"readyBitmap 65535", rctypes.OpRejectResult, cat(h32, word(1), word(0), word(65535)), true},
		{"readyBitmap 65536", rctypes.OpRejectResult, cat(h32, word(1), word(0), word(65536)), false},
		{"memberId over uint64", rctypes.OpRejectResult, cat(h32, word(3), append([]byte{1}, make([]byte, 31)...), word(0)), false},
	}
	var chain [32]byte
	chain[31] = 3
	wh := [32]byte{7}
	for _, c := range cases {
		ctx := []any{h32, h32}
		x := vrBase(c.op)
		x.ChainID, x.WitnessHash, x.Data = chain, wh, c.data
		if c.op == rctypes.OpRetirement {
			x.Retire = &rctypes.RetireContext{EVMBlockHash: [32]byte{1}, EVMStateRoot: [32]byte{1}}
		} else {
			x.Reject = &rctypes.RejectContext{PredecessorBodyID: [32]byte{1}, Attempt: 0, EVMBlockHash: [32]byte{1}, EVMStateRoot: [32]byte{1}}
			ctx = []any{h32, uint64(0), h32, h32}
		}
		// the encoders
		ours, errOurs := x.MarshalCBOR()
		schema, errSchema := vrschema.EncodeVRControl(3, chain, vrschema.ValidatorRegistry, 5, 900, c.op, vrschema.ControlContext{EVMBlockHash: h32,
			EVMStateRoot: h32, Predecessor: h32}, c.data, wh)
		require.Equal(t, c.ok, errOurs == nil, "%s: this codec, %v", c.name, errOurs)
		require.Equal(t, c.ok, errSchema == nil, "%s: vrschema, %v", c.name, errSchema)
		if c.ok {
			require.Equal(t, schema, ours, c.name)
		}
		// a raw item built without either encoder
		raw, err := basetypes.Cbor.Marshal([]any{rctypes.VRControlTag, uint64(3), chain[:], vrschema.ValidatorRegistry[:], uint64(5), uint64(900), c.op, ctx, c.data, wh[:]})
		require.NoError(t, err)
		var back rctypes.PosControl
		errDec := back.UnmarshalCBOR(raw)
		_, _, _, errSchemaDec := vrschema.DecodeVRControl(raw)
		require.Equal(t, c.ok, errDec == nil, "%s: this decoder, %v", c.name, errDec)
		require.Equal(t, c.ok, errSchemaDec == nil, "%s: vrschema's decoder, %v", c.name, errSchemaDec)
		if !c.ok {
			require.ErrorIs(t, errDec, rctypes.ErrPosControl, c.name)
		}
	}
}
