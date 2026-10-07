package types

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"
)

func word(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func u64word(v uint64) []byte {
	w := make([]byte, 32)
	for i := 0; i < 8; i++ {
		w[31-i] = byte(v >> (8 * i))
	}
	return w
}

func closeControl(epoch uint64) PosControl {
	data := bytes.Join([][]byte{word(1), u64word(100), word(2), word(3), word(4), word(5)}, nil)
	return PosControl{Network: 5, Op: OpCloseLiability, OrderingEpoch: epoch + 1, OrderingRound: 9, Close: &CloseContext{ClosedEpoch: epoch}, Data: data}
}

func retireControl(id, generation uint64) PosControl {
	return PosControl{Network: 5, Op: OpRetirement, OrderingEpoch: 2, OrderingRound: 9, Retire: &RetireContext{},
		Data: bytes.Join([][]byte{u64word(id), u64word(generation), word(7)}, nil)}
}

func rejectControl() PosControl {
	return PosControl{Network: 5, Op: OpRejectResult, OrderingEpoch: 2, OrderingRound: 9, Reject: &RejectContext{Attempt: 3}, Data: word(9)}
}

func TestPosControlRoundTripsForEveryOp(t *testing.T) {
	for name, c := range map[string]PosControl{"close": closeControl(1), "retire": retireControl(7, 1), "reject": rejectControl()} {
		raw, err := c.MarshalCBOR()
		require.NoError(t, err, name)
		var got PosControl
		require.NoError(t, got.UnmarshalCBOR(raw), name)
		require.Equal(t, c, got, name)
	}
}

func TestPosControlValidateRefusals(t *testing.T) {
	bad := func(f func(c *PosControl)) PosControl { c := closeControl(1); f(&c); return c }
	cases := map[string]PosControl{
		"unknown op":                 bad(func(c *PosControl) { c.Op = 4 }),
		"op without its context":     bad(func(c *PosControl) { c.Close = nil }),
		"two contexts":               bad(func(c *PosControl) { c.Retire = &RetireContext{} }),
		"the context of another op":  bad(func(c *PosControl) { c.Op = OpRetirement }),
		"payload one byte short":     bad(func(c *PosControl) { c.Data = c.Data[:191] }),
		"payload one byte long":      bad(func(c *PosControl) { c.Data = append(c.Data, 0) }),
		"hRound above uint64":        bad(func(c *PosControl) { c.Data[32] = 1 }),
		"closed epoch zero":          bad(func(c *PosControl) { c.Close.ClosedEpoch = 0 }),
		"retirement id above uint64": func() PosControl { c := retireControl(1, 1); c.Data[0] = 1; return c }(),
		"retirement generation high": func() PosControl { c := retireControl(1, 1); c.Data[32] = 1; return c }(),
		"reject payload width":       func() PosControl { c := rejectControl(); c.Data = c.Data[:31]; return c }(),
	}
	for name, c := range cases {
		require.ErrorIs(t, c.Validate(), ErrPosControl, name)
		_, err := c.MarshalCBOR()
		require.ErrorIs(t, err, ErrPosControl, name)
	}
}

func rawItem(t *testing.T, f []any) []byte {
	t.Helper()
	b, err := types.Cbor.Marshal(f)
	require.NoError(t, err)
	return b
}

func itemFields(c PosControl) []any {
	ctx, _ := c.contextValue()
	return []any{PosControlTag, c.Network, c.ChainID[:], c.Custody[:], c.OrderingEpoch, c.OrderingRound, c.Op, ctx, c.Data, c.WitnessHash[:]}
}

func TestPosControlDecodeRefusals(t *testing.T) {
	c := closeControl(1)
	good, err := c.MarshalCBOR()
	require.NoError(t, err)
	mut := func(i int, v any) []byte { f := itemFields(c); f[i] = v; return rawItem(t, f) }
	cases := map[string][]byte{
		"trailing byte":       append(append([]byte(nil), good...), 0),
		"truncated":           good[:len(good)-1],
		"empty":               nil,
		"another tag":         mut(0, "OTHER"),
		"nine elements":       rawItem(t, itemFields(c)[:9]),
		"eleven elements":     rawItem(t, append(itemFields(c), uint64(0))),
		"network a string":    mut(1, "5"),
		"chain id short":      mut(2, make([]byte, 31)),
		"custody 19 bytes":    mut(3, make([]byte, 19)),
		"epoch a string":      mut(4, "2"),
		"op a string":         mut(6, "1"),
		"context null":        mut(7, nil),
		"context a map":       mut(7, map[string]any{}),
		"context of one":      mut(7, []any{uint64(1)}),
		"closed epoch string": mut(7, []any{"1", word(1)}),
		"bundle id 31 bytes":  mut(7, []any{uint64(1), make([]byte, 31)}),
		"data null":           mut(8, nil),
		"witness 31 bytes":    mut(9, make([]byte, 31)),
		"unknown op":          mut(6, uint64(9)),
		"retirement context of three": rawItem(t, func() []any {
			r := retireControl(7, 1)
			f := itemFields(r)
			f[7] = []any{word(1), word(2), word(3)}
			return f
		}()),
		"retirement hash 31 bytes": rawItem(t, func() []any {
			r := retireControl(7, 1)
			f := itemFields(r)
			f[7] = []any{word(1), make([]byte, 31)}
			return f
		}()),
		"rejection attempt a byte string": rawItem(t, func() []any {
			r := rejectControl()
			f := itemFields(r)
			f[7] = []any{word(1), word(2), word(3), word(4)}
			return f
		}()),
		"rejection context of three": rawItem(t, func() []any {
			r := rejectControl()
			f := itemFields(r)
			f[7] = []any{word(1), uint64(3), word(3)}
			return f
		}()),
		// 05 written as 18 05: a valid CBOR integer that is not the shortest form
		"non-shortest network": bytes.Replace(good, []byte{0x05}, []byte{0x18, 0x05}, 1),
	}
	for name, data := range cases {
		var got PosControl
		require.ErrorIs(t, got.UnmarshalCBOR(data), ErrPosControl, name)
	}
}

func TestEmptyPayloadIsTheCanonicalFourElementTuple(t *testing.T) {
	raw, err := (&Payload{Version: 2}).MarshalCBOR()
	require.NoError(t, err)
	require.Equal(t, "8402808080", hex.EncodeToString(raw))
	raw2, err := (&Payload{Version: 2, Requests: []*IRChangeReq{}, HandoffRecords: [][]byte{}, PosControls: []PosControl{}}).MarshalCBOR()
	require.NoError(t, err)
	require.Equal(t, raw, raw2)
	var got Payload
	require.NoError(t, got.UnmarshalCBOR(raw))
	require.True(t, got.IsEmpty())
	require.EqualValues(t, 2, got.Version)
}

func TestPayloadRoundTripsEqualInMemory(t *testing.T) {
	for _, p := range []*Payload{{Version: 2}, {Version: 2, HandoffRecords: [][]byte{{1}}}, {Version: 2, PosControls: []PosControl{rejectControl()}}} {
		raw, err := p.MarshalCBOR()
		require.NoError(t, err)
		var got Payload
		require.NoError(t, got.UnmarshalCBOR(raw))
		require.Equal(t, *p, got, "empty collections are nil in memory, as before the four-element form")
	}
}

func TestPayloadWithControlsRoundTripsAndIsNotEmpty(t *testing.T) {
	p := &Payload{Version: 2, HandoffRecords: [][]byte{{1, 2, 3}}, PosControls: []PosControl{closeControl(1), retireControl(7, 1)}}
	raw, err := p.MarshalCBOR()
	require.NoError(t, err)
	var got Payload
	require.NoError(t, got.UnmarshalCBOR(raw))
	require.Equal(t, p.PosControls, got.PosControls)
	require.False(t, got.IsEmpty())
	require.False(t, (&Payload{Version: 2, PosControls: []PosControl{rejectControl()}}).IsEmpty(), "a control-bearing block is never an empty suffix")
}

func TestPayloadDecodeRefusals(t *testing.T) {
	cases := map[string][]byte{
		"the retired three-element form":    {0x83, 0x02, 0x80, 0x80},
		"null requests":                     {0x84, 0x02, 0xf6, 0x80, 0x80},
		"null handoff records":              {0x84, 0x02, 0x80, 0xf6, 0x80},
		"null controls":                     {0x84, 0x02, 0x80, 0x80, 0xf6},
		"controls a byte string":            {0x84, 0x02, 0x80, 0x80, 0x40},
		"indefinite requests":               {0x84, 0x02, 0x9f, 0xff, 0x80, 0x80},
		"five elements":                     {0x85, 0x02, 0x80, 0x80, 0x80, 0x80},
		"two elements":                      {0x82, 0x02, 0x80},
		"another profile tag":               {0x84, 0x03, 0x80, 0x80, 0x80},
		"profile tag one in the new shape":  {0x84, 0x01, 0x80, 0x80, 0x80},
		"profile tag a string":              {0x84, 0x61, 0x32, 0x80, 0x80, 0x80},
		"trailing byte":                     {0x84, 0x02, 0x80, 0x80, 0x80, 0x00},
		"non-shortest tag":                  {0x84, 0x18, 0x02, 0x80, 0x80, 0x80},
		"a null element of requests":        {0x84, 0x02, 0x81, 0xf6, 0x80, 0x80},
		"a null element of handoff records": {0x84, 0x02, 0x80, 0x81, 0xf6, 0x80},
		"a null element of controls":        {0x84, 0x02, 0x80, 0x80, 0x81, 0xf6},
		"not an array":                      {0xa0},
		"empty":                             nil,
	}
	for name, data := range cases {
		var got Payload
		require.ErrorIs(t, got.UnmarshalCBOR(data), ErrPayloadEncoding, name)
	}
	var ok Payload
	require.NoError(t, ok.UnmarshalCBOR([]byte{0x84, 0x02, 0x80, 0x80, 0x80}))
	// the legacy profile's one-element payload still decodes
	var legacy Payload
	require.NoError(t, legacy.UnmarshalCBOR([]byte{0x81, 0x80}))
	require.Zero(t, legacy.Version)
}

func TestOnlyAVersionTwoPayloadCarriesControls(t *testing.T) {
	p := &Payload{Version: 1, PosControls: []PosControl{rejectControl()}}
	_, err := p.MarshalCBOR()
	require.Error(t, err)
	require.Error(t, p.IsValid())
	p0 := &Payload{PosControls: []PosControl{rejectControl()}}
	require.Error(t, p0.IsValid())
}

func TestControlOrderingRules(t *testing.T) {
	ok := []PosControl{closeControl(1), closeControl(2), rejectControl(), retireControl(3, 1), retireControl(3, 2), retireControl(4, 1)}
	require.NoError(t, validatePosControls(ok))
	require.NoError(t, validatePosControls(nil))

	cases := map[string][]PosControl{
		"closures descending":            {closeControl(2), closeControl(1)},
		"a duplicate closure epoch":      {closeControl(1), closeControl(1)},
		"retirement before closure":      {retireControl(3, 1), closeControl(1)},
		"rejection before closure":       {rejectControl(), closeControl(1)},
		"retirement before rejection":    {retireControl(3, 1), rejectControl()},
		"two rejections":                 {rejectControl(), rejectControl()},
		"retirements descending by id":   {retireControl(4, 1), retireControl(3, 1)},
		"retirements descending by gen":  {retireControl(3, 2), retireControl(3, 1)},
		"a duplicate retirement":         {retireControl(3, 1), retireControl(3, 1)},
		"an invalid item in a valid run": {closeControl(1), func() PosControl { c := retireControl(3, 1); c.Data = c.Data[:95]; return c }()},
	}
	for name, cs := range cases {
		require.ErrorIs(t, validatePosControls(cs), ErrPosControl, name)
	}
	var many []PosControl
	for i := uint64(1); i <= MaxPosControls+1; i++ {
		many = append(many, closeControl(i))
	}
	require.NoError(t, validatePosControls(many[:MaxPosControls]))
	require.ErrorIs(t, validatePosControls(many), ErrPosControl)
	// the payload applies the same rule
	require.Error(t, (&Payload{Version: 2, PosControls: cases["two rejections"]}).IsValid())
}
