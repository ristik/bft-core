package bridgeprofile

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// arrayOf is a canonical CBOR array of n zero integers: n+1 item heads.
func arrayOf(n int) []byte {
	items := make([][]byte, n)
	for i := range items {
		items[i] = CUint(0)
	}
	return CArr(items...)
}

// TestBridgeItemsRule: J counts item heads (containers, tags, scalars, strings, children), never the contents of a byte string.
func TestBridgeItemsRule(t *testing.T) {
	for name, tc := range map[string]struct {
		b []byte
		j int
	}{
		"uint":                {CUint(5), 1},
		"array of three":      {arrayOf(3), 4},
		"tagged array":        {CTag(39002, arrayOf(2)), 4},
		"byte string opaque":  {CBytes(arrayOf(100)), 1},
		"nested":              {CArr(arrayOf(2), CBytes([]byte{1, 2})), 5},
		"map keys and values": {[]byte{0xa1, 0x61, 'k', 0x01}, 3},
	} {
		n, err := BridgeItems(tc.b, MaxBridgeItems)
		require.NoError(t, err, name)
		require.Equal(t, tc.j, n, name)
	}
}

// TestBridgeJCap: J over Cfg, policy, every UC and every IR opening shares one 4,096 budget: exactly 4,096 is admitted, 4,097 is
// ErrTooManyItems, also when the overflow is split across anchors; an IR opening counts separately from anything inside its UC, and
// repeated objects count each time.
func TestBridgeJCap(t *testing.T) {
	f := fix()
	cfg := f.Cfg.Bytes()
	base := func() int {
		n1, err := BridgeItems(cfg, MaxBridgeItems)
		require.NoError(t, err)
		n2, err := BridgeItems(f.Policy.Bytes(), MaxBridgeItems)
		require.NoError(t, err)
		return n1 + n2
	}()
	ir := arrayOf(1) // 2 items
	env := func(ucItems ...int) *Envelope {
		e := &Envelope{PolicyBody: f.Policy.Bytes()}
		for _, n := range ucItems {
			e.Anchors = append(e.Anchors, Anchor{UC: arrayOf(n - 1), InputRecord: ir})
		}
		return e
	}
	// one anchor filling the budget exactly, then one item over
	fill := MaxBridgeItems - base - 2
	j, err := bridgeJ(cfg, env(fill))
	require.NoError(t, err)
	require.Equal(t, uint64(MaxBridgeItems), j)
	_, err = bridgeJ(cfg, env(fill+1))
	require.ErrorIs(t, err, ErrTooManyItems)
	// the same overflow split over three anchors: each IR opening adds its own 2 items
	third := (MaxBridgeItems - base - 3*2) / 3
	rest := MaxBridgeItems - base - 3*2 - 2*third
	j, err = bridgeJ(cfg, env(third, third, rest))
	require.NoError(t, err)
	require.Equal(t, uint64(MaxBridgeItems), j)
	_, err = bridgeJ(cfg, env(third, third, rest+1))
	require.ErrorIs(t, err, ErrTooManyItems)
	// repeated encoded objects count each time
	j1, err := bridgeJ(cfg, env(10))
	require.NoError(t, err)
	j2, err := bridgeJ(cfg, env(10, 10))
	require.NoError(t, err)
	require.Equal(t, j1+10+2, j2)
}

// TestGateItemsTerm: the gate adds 1,000*J, and the contract's two-anchor dense witness (B_env 6,720, J 4,096) has a composing
// allowance of 80*B_env + 1,000*J + 1,000,000 = 5,633,600.
func TestGateItemsTerm(t *testing.T) {
	g := Gate{Intrinsic: 1, B2: 2, Batch: 3, RSMT: 4, J: 4096, Items: GasPerItem * 4096}
	require.Equal(t, uint64(1+2+3+4+4_096_000)+GasReserve, g.Total())
	require.Equal(t, uint64(5_633_600), IntrinsicExecPerByte*6720+GasPerItem*4096+GasReserve)
}

// TestGateCountsItems: the gate of a real composed envelope carries J and its 1,000*J charge, and bridgeJ (which the gate runs before
// any B1 call) refuses an anchor table over the item budget with ErrTooManyItems. A real certificate dense enough to cross 4,096 on
// its own is not built here; the boundary is TestBridgeJCap's.
func TestGateCountsItems(t *testing.T) {
	e := newEnv(t)
	cp := e.composed(t, 1, irTimeOK)
	g, err := GateOf(e.F.Cfg, OpReturn, mustEncode(t, cp.env), TxGasBudget)
	require.NoError(t, err)
	require.Greater(t, g.J, uint64(0))
	require.Equal(t, GasPerItem*g.J, g.Items)
	_, err = bridgeJ(e.F.Cfg.Bytes(), &Envelope{PolicyBody: cp.env.PolicyBody, Anchors: []Anchor{{UC: arrayOf(MaxBridgeItems), InputRecord: arrayOf(1)}}})
	require.ErrorIs(t, err, ErrTooManyItems)
}

func mustEncode(t *testing.T, e *Envelope) []byte {
	b, err := e.Encode()
	require.NoError(t, err)
	return b
}
