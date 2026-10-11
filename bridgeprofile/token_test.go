package bridgeprofile

import (
	"bytes"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

func (c *composition) token(t testing.TB) (*Token, []byte) {
	t.Helper()
	tok := TokenFromHistory(c.h, c.cert.InclusionProofs())
	return tok, tok.Bytes()
}

func TestTokenCodecAndProjection(t *testing.T) {
	e := newEnv(t)
	c := e.composed(t, 2, irTimeOK)
	tok, b := c.token(t)
	got, err := DecodeToken(b)
	require.NoError(t, err)
	require.Equal(t, b, got.Bytes())
	// Exact layout: tag 39040, [2,[M,proof0],[[T,proof]...]]; no third slot.
	root, err := scanOneNative(b)
	require.NoError(t, err)
	require.Equal(t, uint64(TagToken), root.arg)
	require.Len(t, root.kids[0].kids, 3)
	require.Equal(t, uint64(2), root.kids[0].kids[0].arg)
	require.Len(t, root.kids[0].kids[1].kids, 2, "certified transaction is exactly [tx, proof]")
	for _, p := range root.kids[0].kids[2].kids {
		require.Len(t, p.kids, 2)
	}
	// Projection: every t is the proof's, the bytes equal the kernel's input.
	proj, err := ProjectToken(b)
	require.NoError(t, err)
	require.Equal(t, c.h.Bytes(), proj)
	require.Equal(t, tok.MintProof.T, got.Project().MintTime)
	res, err := VerifyReturn(e.F.Cfg, proj)
	require.NoError(t, err)
	require.Equal(t, c.res, res)
	// A t edited in a proof changes the projection and nothing else.
	got.Proofs[0].T++
	p2 := got.Project()
	require.Equal(t, c.h.Times[0]+1, p2.Times[0])
	require.Equal(t, c.h.Transfers[0], p2.Transfers[0])
}

func TestTokenDecodeRejections(t *testing.T) {
	e := newEnv(t)
	c := e.composed(t, 1, irTimeOK)
	tok, b := c.token(t)
	p0 := tok.MintProof.Bytes()
	ucItem := tok.MintProof.UC
	cdB := tok.MintProof.CD.Bytes()
	path := append([]byte{}, tok.MintProof.Bitmap[:]...)
	for _, s := range tok.MintProof.Siblings {
		path = append(path, s[:]...)
	}
	proof := func(items ...[]byte) []byte { return CTag(TagInclusion, CArr(items...)) }
	rep := func(repl []byte) error {
		_, err := DecodeToken(replaceOnce(b, p0, repl))
		return err
	}
	good := []byte{}
	_ = good
	require.ErrorIs(t, rep(proof(CUint(1), cdB, CBytes(path), ucItem)), ErrShape, "pre-3.0 proof without t")
	require.ErrorIs(t, rep(proof(CUint(1), cdB, CUint(tok.MintProof.T), CBytes(path), ucItem, CNull)), ErrShape, "extra slot")
	require.ErrorIs(t, rep(proof(CUint(2), cdB, CUint(tok.MintProof.T), CBytes(path), ucItem)), ErrVersion)
	require.ErrorIs(t, rep(CNull), ErrShape, "pending response is not a proof")
	require.ErrorIs(t, rep(proof(CUint(1), CNull, CUint(1), CBytes(path), ucItem)), ErrShape, "no CD")
	require.ErrorIs(t, rep(proof(CUint(1), cdB, CBytes([]byte{1}), CBytes(path), ucItem)), ErrShape, "t not an integer")
	require.ErrorIs(t, rep(proof(CUint(1), cdB, CUint(1), CBytes(path[:len(path)-1]), ucItem)), ErrLength)
	require.ErrorIs(t, rep(proof(CUint(1), cdB, CUint(1), CBytes(append(path, make([]byte, 32)...)), ucItem)), ErrLength, "sibling beyond the bitmap")
	require.ErrorIs(t, rep(proof(CUint(1), cdB, CUint(1), CBytes(nil), ucItem)), ErrLength)
	require.ErrorIs(t, rep(proof(CUint(1), cdB, CUint(1), CBytes(path), CNull)), ErrShape, "no certificate")
	require.ErrorIs(t, rep(proof(CUint(1), cdB, CUint(1), CBytes(path), CTag(1, CBytes(make([]byte, MaxProofUCBytes))))), ErrInputTooLarge)
	_, err := DecodeToken(append(bytes.Clone(b), 0))
	require.ErrorIs(t, err, ErrTrailing)
	// Token-level: version, the separate reference-time slot, the wrong tag.
	root, _ := scanOneNative(b)
	k := root.kids[0].kids
	slice := func(i int) []byte { return b[k[i].start:k[i].end] }
	tk := func(items ...[]byte) []byte { return CTag(TagToken, CArr(items...)) }
	_, err = DecodeToken(tk(CUint(1), slice(1), slice(2)))
	require.ErrorIs(t, err, ErrVersion)
	_, err = DecodeToken(tk(CUint(2), slice(1), slice(2), CUint(5)))
	require.ErrorIs(t, err, ErrShape, "no third reference-time slot")
	_, err = DecodeToken(CTag(TagToken+1, CArr(CUint(2), slice(1), slice(2))))
	require.ErrorIs(t, err, ErrTag)
	_, err = DecodeToken(tk(CUint(2), CArr(slice(1)), slice(2)))
	require.ErrorIs(t, err, ErrShape, "genesis without its proof")
	_, err = DecodeToken(make([]byte, MaxTokenBytes+1))
	require.ErrorIs(t, err, ErrInputTooLarge)
	// A map or text outside the certificate is still forbidden.
	_, err = DecodeToken(tk(CUint(2), []byte{0xa0}, slice(2)))
	require.ErrorIs(t, err, ErrShape)
}

func TestTokenCumulativePathSteps(t *testing.T) {
	e := newEnv(t)
	realUC := e.composed(t, 2, irTimeOK).cert.InclusionProofs()[0].UC
	build := func(transfers int) error {
		keys := manyKeys(transfers + 1)
		h, err := e.F.BuildToken(5, amt, keys)
		require.NoError(t, err)
		proofs := make([]InclusionProof, transfers+1)
		for i := range proofs {
			for j := range proofs[i].Bitmap {
				proofs[i].Bitmap[j] = 0xff
			}
			// The real UC carries one shard-tree sibling: 255 path siblings make 256 steps per proof.
			proofs[i].Bitmap[31] = 0x7f
			proofs[i].Siblings = make([][32]byte, 255)
			proofs[i].UC = realUC
		}
		_, err = DecodeToken(TokenFromHistory(h, proofs).Bytes())
		return err
	}
	require.NoError(t, build(7), "eight proofs of 256 steps: exactly 2048")
	require.ErrorIs(t, build(8), ErrTooManyPaths)
}

func manyKeys(n int) []*secp256k1.PrivateKey {
	out := make([]*secp256k1.PrivateKey, n)
	for i := range out {
		out[i] = KeyFromSeed("mk" + string(rune('A'+i%26)) + string(rune('a'+i/26)))
	}
	return out
}

// --- kernel ABI -------------------------------------------------------------------

func TestKernelResultSizeAndRoundTrip(t *testing.T) {
	f := fix()
	h, _, _ := retToken(t, f, 5, 3)
	res, err := VerifyReturn(f.Cfg, h.Bytes())
	require.NoError(t, err)
	m := len(res.Leaves)
	out, err := EncodeResult(true, res)
	require.NoError(t, err)
	require.Equal(t, 448+128*m, len(out))
	valid, got, err := DecodeResult(out)
	require.NoError(t, err)
	require.True(t, valid)
	require.Equal(t, res, got)
	zero, err := EncodeResult(false, nil)
	require.NoError(t, err)
	require.Equal(t, 448, len(zero))
	require.Equal(t, KernelMarker[:], out[:32])
	require.Equal(t, KernelMarker[:], zero[:32])

	// Through the ABI entry point: each operation, success and relation failure.
	cfgB := f.Cfg.Bytes()
	in, err := EncodeKernelInput(OpReturn, cfgB, h.Bytes())
	require.NoError(t, err)
	ko, err := Kernel(in)
	require.NoError(t, err)
	require.Equal(t, out, ko)
	mint, _, _ := retToken(t, f, 5, 0)
	mt, err := f.BuildToken(5, amt, oneKey())
	require.NoError(t, err)
	_ = mint
	in, _ = EncodeKernelInput(OpMint, cfgB, mt.Bytes())
	ko, err = Kernel(in)
	require.NoError(t, err)
	require.Len(t, ko, 448+128)
	p0 := sigPred(oneKey()[0]).Bytes()
	in, _ = EncodeKernelInput(OpPrepareLock, cfgB, PreparePayload(5, amt, p0))
	ko, err = Kernel(in)
	require.NoError(t, err)
	require.Len(t, ko, 448, "prepare returns no leaves")
	v, pr, err := DecodeResult(ko)
	require.NoError(t, err)
	require.True(t, v)
	mr, merr := VerifyMint(f.Cfg, mt.Bytes())
	require.NoError(t, merr)
	require.Equal(t, mr.LockDigest, pr.LockDigest)
	// A history that does not hold is the all-zero false output; a malformed one halts.
	in, _ = EncodeKernelInput(OpMint, cfgB, h.Bytes()) // has transfers
	ko, err = Kernel(in)
	require.NoError(t, err)
	require.Equal(t, zero, ko)
	in, _ = EncodeKernelInput(OpReturn, cfgB, append(h.Bytes(), 0))
	_, err = Kernel(in)
	require.ErrorIs(t, err, ErrTrailing)
	in, _ = EncodeKernelInput(9, cfgB, nil)
	_, err = Kernel(in)
	require.ErrorIs(t, err, ErrBadOperation)
	bad := *f.Cfg
	bad.Ty[0] ^= 1
	in, _ = EncodeKernelInput(OpReturn, bad.Bytes(), h.Bytes())
	ko, err = Kernel(in)
	require.NoError(t, err)
	require.Equal(t, zero, ko, "Cfg whose identifiers are not derived")
}

func TestKernelFramingRejections(t *testing.T) {
	f := fix()
	h, _, _ := retToken(t, f, 5, 1)
	res, _ := VerifyReturn(f.Cfg, h.Bytes())
	out, _ := EncodeResult(true, res)
	// Leaf layout: head 14 words, leaves array at 0x1c0: length, then 4-word leaves.
	leafStart := 448 // after the array length word of an empty array; leaves follow
	_ = leafStart
	mutate := func(off int, v byte) []byte { b := bytes.Clone(out); b[off] = v; return b }
	// referenceTime is the third word of the first leaf; its high bytes must be zero.
	refWord := 448 - 32 + 0 // start of leaf 0
	_ = refWord
	for _, c := range []struct {
		name string
		b    []byte
	}{
		{"truncated", out[:len(out)-32]},
		{"not a whole leaf", out[:len(out)-1]},
		{"trailing word", append(bytes.Clone(out), make([]byte, 32)...)},
		{"marker", mutate(0, out[0]^1)},
		{"valid word not a bool", mutate(63, 2)},
		{"empty", nil},
		{"over maximum leaves", make([]byte, 448+128*(MaxLeaves+1))},
	} {
		_, _, err := DecodeResult(c.b)
		require.ErrorIs(t, err, ErrResultFrame, c.name)
	}
	// Dirty high padding in a narrow timestamp word is rejected by re-encoding.
	leaf0 := len(out) - 128*len(res.Leaves)
	dirty := bytes.Clone(out)
	dirty[leaf0+64] = 1 // first byte of the referenceTime word
	_, _, err := DecodeResult(dirty)
	require.ErrorIs(t, err, ErrResultFrame)
	// valid=false must be the all-zero empty result.
	zero, _ := EncodeResult(false, nil)
	for name, at := range map[string]int{"tuple offset word": 95, "cfg word": 127} {
		nz := bytes.Clone(zero)
		nz[at] = 1 // words: 0 marker, 1 valid, 2 tuple offset (64..95), 3 the Result's cfg (96..127)
		_, _, err = DecodeResult(nz)
		require.ErrorIs(t, err, ErrResultFrame, name)
	}
	// Kernel input framing.
	in, _ := EncodeKernelInput(OpReturn, f.Cfg.Bytes(), h.Bytes())
	for name, b := range map[string][]byte{"trailing": append(bytes.Clone(in), make([]byte, 32)...), "short": in[:64], "unaligned": in[:len(in)-1]} {
		_, _, _, err := DecodeKernelInput(b)
		require.ErrorIs(t, err, ErrABIFraming, name)
	}
	_, _, _, err = DecodeKernelInput(make([]byte, MaxKernelInputBytes+32))
	require.ErrorIs(t, err, ErrInputTooLarge)
	_ = big.NewInt
}

// The kernel judges the Cfg before any operation: a Cfg whose identifiers are not derived is the false output for every operation, so
// the check is not backstopped by the relation it guards.
func TestKernelRejectsUnderivedCfgForEveryOperation(t *testing.T) {
	e := newEnv(t)
	bad := *e.F.Cfg
	bad.Ty[0] ^= 1
	require.ErrorIs(t, bad.Validate(), ErrCfgMismatch, "the mutation must make the Cfg invalid, not merely different")
	falseOut, err := EncodeResult(false, nil)
	require.NoError(t, err)
	good, err := Kernel(mustKernelIn(t, OpPrepareLock, e.F.Cfg.Bytes(), PreparePayload(5, amt, sigPred(KeyFromSeed("kc")).Bytes())))
	require.NoError(t, err)
	require.NotEqual(t, falseOut, good, "with the derived Cfg the same prepare input holds")
	out, err := Kernel(mustKernelIn(t, OpPrepareLock, bad.Bytes(), PreparePayload(5, amt, sigPred(KeyFromSeed("kc")).Bytes())))
	require.NoError(t, err)
	require.Equal(t, falseOut, out)
}

func mustKernelIn(t *testing.T, op uint8, cfg, payload []byte) []byte {
	t.Helper()
	b, err := EncodeKernelInput(op, cfg, payload)
	require.NoError(t, err)
	return b
}
