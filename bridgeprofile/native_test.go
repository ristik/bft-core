package bridgeprofile

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

// The status table: every code names a distinct sentinel, in the corpus reason order.
func TestComposeStatusTable(t *testing.T) {
	require.Nil(t, ComposeStatus[0])
	pos := map[error]int{}
	for i, r := range reasons {
		pos[r.err] = i
	}
	seen := map[string]bool{}
	last := -1
	for i := 1; i < len(ComposeStatus); i++ {
		name := ComposeStatusName(uint64(i))
		require.NotEmpty(t, name, "code %d", i)
		require.False(t, seen[name], name)
		seen[name] = true
		p, ok := pos[ComposeStatus[i]]
		require.True(t, ok, name)
		require.Greater(t, p, last, "%s keeps the corpus reason order", name)
		last = p
	}
	require.Empty(t, ComposeStatusName(0))
	require.Empty(t, ComposeStatusName(uint64(len(ComposeStatus))))
}

// StatusOf takes the outermost sentinel of the chain, depth first, and refuses an error without one.
func TestStatusOf(t *testing.T) {
	code := func(e error) uint64 {
		c, err := StatusOf(e)
		require.NoError(t, err)
		return c
	}
	require.Equal(t, uint64(0), code(nil))
	require.Equal(t, "ErrShape", ComposeStatusName(code(ErrShape)))
	require.Equal(t, "ErrIRTime", ComposeStatusName(code(fmt.Errorf("leaf 3: %w", ErrIRTime))))
	// two sentinels in one chain: the first met depth first decides
	require.Equal(t, "ErrLockProofShape", ComposeStatusName(code(fmt.Errorf("%w: %w", ErrLockProofShape, ErrTruncated))))
	require.Equal(t, "ErrTruncated", ComposeStatusName(code(fmt.Errorf("%w: %w", ErrTruncated, ErrLockProofShape))))
	_, err := StatusOf(errors.New("other"))
	require.ErrorIs(t, err, errComposeUnmapped)
	_, err = StatusOf(ErrLockUC)
	require.ErrorIs(t, err, errComposeUnmapped, "a backing reason is never a compose status")
}

func TestComposeGroupGas(t *testing.T) {
	for k, want := range map[uint64]uint64{0: 0, 1: 0, 2: 100, 3: 300, 4: 400, 5: 750, 16: 3200, 17: 4250} {
		require.Equal(t, want, ComposeGroupGas(k), "K=%d", k)
	}
}

func nativeCorpus(t *testing.T) (*Corpus, *FixtureSet) {
	t.Helper()
	c, err := BuildCorpus()
	require.NoError(t, err)
	return c, c.Set
}

// Every compose case of the corpus, natively: the same status as Compose's reason, the fixed result of Compose's result, and on
// success the closed-form charge of its dimensions. Each status is mapped (no compose error lacks a code).
func TestNativeComposeEqualsCompose(t *testing.T) {
	c, fs := nativeCorpus(t)
	n := 0
	for _, cs := range c.Cases["proof"] {
		if cs.Op != "compose" {
			continue
		}
		n++
		cfg, err := fs.cfg(cs.Cfg)
		require.NoError(t, err)
		env, err := hex.DecodeString(cs.Input)
		require.NoError(t, err)
		b1, err := parseClaims(cs.Aux["claims"])
		require.NoError(t, err)
		op := uint8(OpReturn)
		if cs.Aux["operation"] == "mint" {
			op = OpMint
		}
		res, cerr := Compose(cfg, op, env, b1)
		in, err := EncodeComposeInput(op, cfg.Bytes(), env)
		require.NoError(t, err)
		out, status, gas, halt := NativeCompose(in, math.MaxUint64, b1)
		require.NoError(t, halt, cs.ID)
		require.Equal(t, ComposeMarker[:], out[:32])
		require.Equal(t, new(big.Int).SetUint64(status).FillBytes(make([]byte, 32)), out[32:64])
		if cerr != nil {
			name, _ := Reason(cerr)
			require.Equal(t, name, ComposeStatusName(status), cs.ID)
			require.Equal(t, make([]byte, 320), out[64:], "%s: a status carries no result", cs.ID)
		} else {
			require.Zero(t, status, cs.ID)
			require.Equal(t, res.Cfg[:], out[64:96])
			require.Equal(t, res.Nonce, new(big.Int).SetBytes(out[96:128]).Uint64())
			require.Zero(t, res.Amount.Cmp(new(big.Int).SetBytes(out[128:160])))
			require.Equal(t, res.TokenID[:], out[160:192])
			require.Equal(t, res.Salt[:], out[192:224])
			require.Equal(t, res.FirstPredicateHash[:], out[224:256])
			require.Equal(t, res.LockDigest[:], out[256:288])
			require.Equal(t, make([]byte, 12), out[288:300])
			require.Equal(t, res.ReleaseTo[:], out[300:320])
			require.Equal(t, res.Nullifier[:], out[320:352])
			require.Equal(t, uint64(len(res.Leaves)), new(big.Int).SetBytes(out[352:384]).Uint64())
			g, err := GateOf(cfg, op, env)
			require.NoError(t, err)
			e, err := DecodeEnvelope(env)
			require.NoError(t, err)
			jh, err := BridgeItems(e.History)
			require.NoError(t, err)
			d := ComposeDims{B: uint64(len(in)), J: g.J + uint64(jh), L: uint64(len(res.Leaves)), Q: g.Grouping.Q, E: g.Grouping.E,
				A: g.Grouping.A, K: g.Grouping.K, P: g.Steps}
			require.Equal(t, ComposeGas(d), gas, cs.ID)
		}
		// charge-before-work: exactly the metered gas reproduces the outcome, one less halts out of gas
		out2, status2, gas2, halt2 := NativeCompose(in, gas, b1)
		require.NoError(t, halt2, cs.ID)
		require.Equal(t, [3]any{out, status, gas}, [3]any{out2, status2, gas2}, cs.ID)
		_, _, gas3, halt3 := NativeCompose(in, gas-1, b1)
		require.ErrorIs(t, halt3, ErrComposeOutOfGas, cs.ID)
		require.Equal(t, gas-1, gas3, "a halt consumes the forwarded gas")
	}
	require.Greater(t, n, 40)
}

// Halts and the first-stage statuses, with the gas each stage meters.
func TestNativeComposeStages(t *testing.T) {
	e := newEnv(t)
	cp := e.composed(t, 1, irTimeOK)
	env := mustEncode(t, cp.env)
	b1 := RefB1{TB: e.TB}
	cfg := e.F.Cfg.Bytes()
	base := func(in []byte) uint64 { return ComposeBase + ComposePerByte*uint64(len(in)) }
	in, err := EncodeComposeInput(OpReturn, cfg, env)
	require.NoError(t, err)
	_, status, _, halt := NativeCompose(in, math.MaxUint64, b1)
	require.NoError(t, halt)
	require.Zero(t, status)

	// non-canonical framing halts, below the base it is out of gas first
	_, _, _, halt = NativeCompose(append(append([]byte{}, in...), make([]byte, 32)...), math.MaxUint64, b1)
	require.ErrorIs(t, halt, ErrComposeABI)
	_, _, _, halt = NativeCompose(in[:len(in)-1], math.MaxUint64, b1)
	require.ErrorIs(t, halt, ErrComposeABI)
	_, _, _, halt = NativeCompose(in, base(in)-1, b1)
	require.ErrorIs(t, halt, ErrComposeOutOfGas)

	// an unknown operation is a status at the base charge
	bad, err := EncodeComposeInput(3, cfg, env)
	require.NoError(t, err)
	_, status, gas, halt := NativeCompose(bad, math.MaxUint64, b1)
	require.NoError(t, halt)
	require.Equal(t, "ErrBadOperation", ComposeStatusName(status))
	require.Equal(t, base(bad), gas)

	// an oversized input is ErrInputTooLarge at the base charge, before any decode
	huge := make([]byte, MaxComposeInputBytes+32)
	_, status, gas, halt = NativeCompose(huge, math.MaxUint64, b1)
	require.NoError(t, halt)
	require.Equal(t, "ErrInputTooLarge", ComposeStatusName(status))
	require.Equal(t, base(huge), gas)

	// a Cfg that does not decode adds no item charge
	junk, err := EncodeComposeInput(OpReturn, []byte{0x01}, env)
	require.NoError(t, err)
	_, status, gas, halt = NativeCompose(junk, math.MaxUint64, b1)
	require.NoError(t, halt)
	require.Equal(t, "ErrShape", ComposeStatusName(status))
	require.Equal(t, base(junk), gas)

	// an envelope that does not decode: the base and the Cfg's items
	cfgJ, err := BridgeItems(cfg)
	require.NoError(t, err)
	noEnv, err := EncodeComposeInput(OpReturn, cfg, []byte{1, 2, 3})
	require.NoError(t, err)
	_, status, gas, halt = NativeCompose(noEnv, math.MaxUint64, b1)
	require.NoError(t, halt)
	require.Equal(t, "ErrABIFraming", ComposeStatusName(status))
	require.Equal(t, base(noEnv)+ComposePerItem*uint64(cfgJ), gas)
}
