package bridgeprofile

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

// lineageInput is the NativeComposeV2 input of a lineage part's return under real certificates.
func lineageInput(t testing.TB, e *env, b *LineageBuilder, part *LineageToken, op uint8) ([]byte, *Lineage) {
	t.Helper()
	env, lin, _, err := b.Envelope(part, BaseTime+1000)
	require.NoError(t, err)
	enc, err := env.Encode()
	require.NoError(t, err)
	in, err := EncodeComposeInput(op, e.F.Cfg.Bytes(), enc)
	require.NoError(t, err)
	return in, lin
}

func TestNativeComposeV2Output(t *testing.T) {
	e, b := newLineage(t)
	_, kids := tokenWithSplit(t, b, nil)
	b.Return(kids[0], rcpt, big.NewInt(40))
	in, lin := lineageInput(t, e, b, kids[0], OpReturn)
	out, status, gas, halt := NativeComposeV2(in, 1<<40, RefB1{TB: e.TB})
	require.NoError(t, halt)
	require.Zero(t, status)
	st, res, err := DecodeComposeOutputV2(out[:])
	require.NoError(t, err)
	require.Zero(t, st)
	require.Equal(t, lin.Result.Cfg, res.Cfg)
	require.Equal(t, big.NewInt(100), res.Amount, "word 4 is the root lock's amount")
	require.Equal(t, big.NewInt(40), res.PartAmount, "word 13 is the redeemed part's")
	require.Equal(t, lin.PartTokenID, res.PartTokenID)
	require.Equal(t, lin.TokenID, res.TokenID)
	require.Equal(t, lin.LockDigest, res.LockDigest)
	require.Equal(t, lin.Nullifier, res.Nullifier)
	require.Equal(t, lin.ReleaseTo, res.ReleaseTo)
	require.Equal(t, uint64(1), res.Depth)
	require.Equal(t, uint64(len(lin.Leaves)), new(big.Int).SetBytes(out[352:384]).Uint64())

	// gas: exact charge succeeds, one less is an out-of-gas halt
	_, status, g2, halt := NativeComposeV2(in, gas, RefB1{TB: e.TB})
	require.NoError(t, halt)
	require.Zero(t, status)
	require.Equal(t, gas, g2)
	_, _, g3, halt := NativeComposeV2(in, gas-1, RefB1{TB: e.TB})
	require.ErrorIs(t, halt, ErrComposeOutOfGas)
	require.Equal(t, gas-1, g3)
}

// The split terms are charged: the same part with one more ancestor level costs strictly more than the per-leaf terms alone.
func TestNativeComposeV2ChargesTheLineage(t *testing.T) {
	e, b := newLineage(t)
	var gases []uint64
	for _, depth := range []int{0, 1, 2, 4} {
		part, err := b.Chain(9, big.NewInt(1<<16), depth, "g")
		require.NoError(t, err)
		b.Return(part, rcpt, part.Amount)
		in, lin := lineageInput(t, e, b, part, OpReturn)
		gas, status, halt := ComposeGasV2(in, RefB1{TB: e.TB})
		require.NoError(t, halt)
		require.Zero(t, status, "depth %d", depth)
		// the V1 formula over the lineage's leaves is a lower bound of the charge
		require.Greater(t, gas, ComposePerLeaf*uint64(len(lin.Leaves)))
		gases = append(gases, gas)
	}
	for i := 1; i < len(gases); i++ {
		require.Greater(t, gases[i], gases[i-1])
	}
}

// The mint operation refuses a split reason; the lineage is a redemption relation.
func TestNativeComposeV2MintRefusesSplit(t *testing.T) {
	e, b := newLineage(t)
	// a part with no transfer, so only its justification can refuse the mint operation
	_, kids := tokenWithSplitX(t, b, nil, SplitOut{Label: "x", Amount: big.NewInt(40), Owners: lineageKeys("x")[:1]})
	cert, err := e.Agg.Certify([]Leaf{{SID: H([]byte("x")), Value: H([]byte("x"))}}, nil, BaseTime+1000, 100)
	require.NoError(t, err)
	env := &Envelope{PolicyBody: e.F.Policy.Bytes(), History: kids[0].H.Bytes(), Anchors: cert.Anchors, LeafProofs: cert.Proofs}
	enc, err := env.Encode()
	require.NoError(t, err)
	in, err := EncodeComposeInput(OpMint, e.F.Cfg.Bytes(), enc)
	require.NoError(t, err)
	out, status, _, halt := NativeComposeV2(in, 1<<40, RefB1{TB: e.TB})
	require.NoError(t, halt)
	require.Equal(t, "ErrMintJustif", ComposeStatusNameV2(status))
	st, _, err := DecodeComposeOutputV2(out[:])
	require.NoError(t, err)
	require.Equal(t, status, st)
}

// Version 5 refuses a lineage: it is not weakened by the new relation.
func TestComposeV1StillRefusesSplits(t *testing.T) {
	e, b := newLineage(t)
	_, kids := tokenWithSplit(t, b, nil)
	b.Return(kids[0], rcpt, big.NewInt(40))
	_, err := VerifyReturnWith(e.F.Cfg, kids[0].H.Bytes(), ComposedHistory)
	require.ErrorIs(t, err, ErrMintJustif)
}

// Each status of the V2 table is a distinct sentinel in the corpus reason order and the V1 prefix is unchanged.
func TestComposeStatusTableV2(t *testing.T) {
	require.Equal(t, ComposeStatus, ComposeStatusV2[:len(ComposeStatus)])
	seen := map[string]bool{}
	for i := 1; i < len(ComposeStatusV2); i++ {
		n := ComposeStatusNameV2(uint64(i))
		require.NotEmpty(t, n)
		require.False(t, seen[n], n)
		seen[n] = true
	}
	for _, e := range []error{ErrSplitJustif, ErrSplitProofCount, ErrSplitProofShape, ErrSplitManifest, ErrSplitBurn, ErrSplitProof, ErrSplitSum} {
		c, err := StatusOfV2(e)
		require.NoError(t, err)
		require.NotZero(t, c)
	}
	_, err := StatusOf(ErrSplitProof)
	require.ErrorIs(t, err, errComposeUnmapped, "V1 never reports a split reason")
}

// The oracle's estimate by depth (trial schedule; logged for the spec's table). Depth 32 is admitted: there is no depth cap.
func TestNativeComposeV2GasByDepth(t *testing.T) {
	e, b := newLineage(t)
	prev := uint64(0)
	for _, depth := range []int{0, 1, 2, 8, 32} {
		part, err := b.Chain(9, big.NewInt(1<<40), depth, "d")
		require.NoError(t, err)
		b.Return(part, rcpt, part.Amount)
		in, lin := lineageInput(t, e, b, part, OpReturn)
		gas, status, halt := ComposeGasV2(in, RefB1{TB: e.TB})
		require.NoError(t, halt)
		require.Zero(t, status, "depth %d", depth)
		require.Greater(t, gas, prev)
		prev = gas
		t.Logf("depth %2d: leaves %3d, input %7d B, gas %d", depth, len(lin.Leaves), len(in), gas)
	}
}

// Random byte mutations of a depth-2 input never panic: every outcome is a halt or a status of the V2 table (an ancestor's malformed
// certificate is a status, not an unmapped error).
func TestNativeComposeV2MutationsNeverPanic(t *testing.T) {
	e, b := newLineage(t)
	part, err := b.Real2(t)
	require.NoError(t, err)
	b.Return(part, rcpt, part.Amount)
	in, _ := lineageInput(t, e, b, part, OpReturn)
	rng := uint64(0x9e3779b97f4a7c15)
	next := func() uint64 { rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; return rng }
	b1 := RefB1{TB: e.TB}
	seen := map[uint64]int{}
	for i := 0; i < 3000; i++ {
		m := append([]byte{}, in...)
		for k := 0; k < 1+int(next()%3); k++ {
			m[next()%uint64(len(m))] ^= byte(1 + next()%255)
		}
		require.NotPanics(t, func() {
			_, st, _, _ := NativeComposeV2(m, 1<<40, b1)
			require.Less(t, st, uint64(len(ComposeStatusV2)), "a status of the table")
			seen[st]++
		})
	}
	require.Greater(t, seen[uint64(len(ComposeStatus)+7)], 0, "ErrCertScan was exercised")
}
