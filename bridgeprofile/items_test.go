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
		n, err := BridgeItems(tc.b)
		require.NoError(t, err, name)
		require.Equal(t, tc.j, n, name)
	}
}

// TestBridgeJSums: J over Cfg, policy, every UC and every IR opening is a sum with no shared budget (owner section 36): far more
// than the former 4,096 items across anchors is counted and charged; each object is bounded only by its own native scan
// (MaxCBORItems, ErrTooManyItems); an IR opening counts separately from its UC, and repeated objects count each time.
func TestBridgeJSums(t *testing.T) {
	f := fix()
	cfg := f.Cfg.Bytes()
	base := func() int {
		n1, err := BridgeItems(cfg)
		require.NoError(t, err)
		n2, err := BridgeItems(f.Policy.Bytes())
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
	j, err := bridgeJ(cfg, env(MaxCBORItems, MaxCBORItems, MaxCBORItems))
	require.NoError(t, err)
	require.Equal(t, uint64(base+3*(MaxCBORItems+2)), j)
	_, err = bridgeJ(cfg, env(MaxCBORItems+1))
	require.ErrorIs(t, err, ErrTooManyItems, "one object over its own native scan")
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

// TestGateCountsItems: the estimate of a real composed envelope carries J and its 1,000*J charge.
func TestGateCountsItems(t *testing.T) {
	e := newEnv(t)
	cp := e.composed(t, 1, irTimeOK)
	g, err := GateOf(e.F.Cfg, OpReturn, mustEncode(t, cp.env))
	require.NoError(t, err)
	require.Greater(t, g.J, uint64(0))
	require.Equal(t, GasPerItem*g.J, g.Items)
}

func mustEncode(t *testing.T, e *Envelope) []byte {
	b, err := e.Encode()
	require.NoError(t, err)
	return b
}
