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
	require.Equal(t, 5, n, "every positive control.encode vector")
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
		return rctypes.SupportCommitment{Network: 3, StakingID: w(id), Generation: 1, RootKeyHash: w(7), RuleID: w(rule), ReleaseDigest: w(8), Sig: make([]byte, 65)}
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
