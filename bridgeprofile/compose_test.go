package bridgeprofile

import (
	"math/big"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"
)

// permissiveB1 authenticates every anchor, so a test can reach the IR opening
// and time checks with a claim a real B1 would never authenticate; membership
// is still the real RSMT_MEMBER_V1.
type permissiveB1 struct{ RefB1 }

func (permissiveB1) AuthenticateAnchor(*Anchor) error { return nil }

// composition is a certified return history ready for Compose.
type composition struct {
	e    *env
	h    *History
	keys []*secp256k1.PrivateKey
	res  *Result
	cert *CertifiedLeaves
	env  *Envelope
}

const irTimeOK = BaseTime + 1000

func (e *env) composed(t testing.TB, transfers int, irTime uint64) *composition {
	t.Helper()
	keys := make([]*secp256k1.PrivateKey, transfers+1)
	for i := range keys {
		keys[i] = KeyFromSeed("c" + string(rune('a'+i)))
	}
	h, err := e.F.BuildToken(5, amt, keys)
	require.NoError(t, err)
	var rcpt [20]byte
	rcpt[0], rcpt[19] = 0xAA, 0x01
	e.F.AppendBurn(h, keys[len(keys)-1], rcpt, amt)
	res, err := VerifyReturn(e.F.Cfg, h.Bytes())
	require.NoError(t, err)
	extra := []Leaf{{SID: H([]byte("other-1")), Value: H([]byte("v1"))}, {SID: H([]byte("other-2")), Value: H([]byte("v2"))}}
	cert, err := e.Agg.Certify(res.Leaves, extra, irTime, 100)
	require.NoError(t, err)
	c := &composition{e: e, h: h, keys: keys, res: res, cert: cert}
	c.env = &Envelope{PolicyBody: e.F.Policy.Bytes(), History: h.Bytes(), Anchors: []Anchor{cert.Anchor}, LeafProofs: cert.Proofs}
	return c
}

func (c *composition) run(t testing.TB, b1 B1) (*Result, error) {
	t.Helper()
	b, err := c.env.Encode()
	require.NoError(t, err)
	return Compose(c.e.F.Cfg, OpReturn, b, b1)
}

func TestComposeAcceptsCertifiedHistory(t *testing.T) {
	e := newEnv(t)
	c := e.composed(t, 3, irTimeOK)
	res, err := c.run(t, RefB1{TB: e.TB})
	require.NoError(t, err)
	require.Equal(t, c.res, res)
	require.Len(t, res.Leaves, 5)
	// The mint operation composes the mint alone.
	mintOnly, err := e.F.BuildToken(5, amt, c.keys[:1])
	require.NoError(t, err)
	mres, err := VerifyMint(e.F.Cfg, mintOnly.Bytes())
	require.NoError(t, err)
	cert, err := e.Agg.Certify(mres.Leaves, nil, irTimeOK, 100)
	require.NoError(t, err)
	env := &Envelope{PolicyBody: e.F.Policy.Bytes(), History: mintOnly.Bytes(), Anchors: []Anchor{cert.Anchor}, LeafProofs: cert.Proofs}
	b, err := env.Encode()
	require.NoError(t, err)
	_, err = Compose(e.F.Cfg, OpMint, b, RefB1{TB: e.TB})
	require.NoError(t, err)
	_, err = Compose(e.F.Cfg, OpPrepareLock, b, RefB1{TB: e.TB})
	require.ErrorIs(t, err, ErrBadOperation)
}

func TestComposeReferenceTimeBound(t *testing.T) {
	e := newEnv(t)
	maxT := BaseTime + 10*uint64(4) // the burn is transfer 4
	for _, c := range []struct {
		name   string
		irTime uint64
		want   error
	}{
		{"IR time equals the latest t", maxT, nil},
		{"IR time one second before the latest t", maxT - 1, ErrIRTime},
		{"IR time far before every t", 1, ErrIRTime},
		{"IR time long after", maxT + 1<<30, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			cp := e.composed(t, 3, c.irTime)
			_, err := cp.run(t, RefB1{TB: e.TB})
			if c.want == nil {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, c.want)
			require.ErrorIs(t, err, ErrInvalid)
		})
	}
}

func TestComposeOpeningIsBoundToTheAuthenticatedHash(t *testing.T) {
	e := newEnv(t)
	// A prover offering an opening with a huge timestamp for the same expected
	// hash is caught by the hash equality, with the real B1 authenticating the
	// untouched (stateRoot, irHash) pair.
	cp := e.composed(t, 2, BaseTime) // times 1..: later than the IR so the lie would matter
	cp.env.Anchors[0].InputRecord = rewriteIR(t, cp.env.Anchors[0].InputRecord, func(ir *types.InputRecord) { ir.Timestamp = 1 << 60 })
	_, err := cp.run(t, RefB1{TB: e.TB})
	require.ErrorIs(t, err, ErrIROpening)

	// Without the lie, the true timestamp rejects the same history.
	cp = e.composed(t, 2, BaseTime)
	_, err = cp.run(t, RefB1{TB: e.TB})
	require.ErrorIs(t, err, ErrIRTime)

	// State hash: an opening whose hash matches but whose state differs.
	cp = e.composed(t, 2, irTimeOK)
	other := rewriteIR(t, cp.env.Anchors[0].InputRecord, func(ir *types.InputRecord) { ir.Hash = sl(H([]byte("another-root"))) })
	cp.env.Anchors[0].InputRecord = other
	cp.env.Anchors[0].ExpectedIRHash = H(other)
	_, err = cp.run(t, permissiveB1{RefB1{TB: e.TB}})
	require.ErrorIs(t, err, ErrIRState)
}

func TestComposeOpeningShapes(t *testing.T) {
	e := newEnv(t)
	base := e.composed(t, 1, irTimeOK).env.Anchors[0].InputRecord
	root, err := scanOne(base)
	require.NoError(t, err)
	body := root.kids[0]
	field := func(i int) []byte { return base[body.kids[i].start:body.kids[i].end] }
	rebuild := func(mut func(f [][]byte) [][]byte) []byte {
		var f [][]byte
		for i := range body.kids {
			f = append(f, field(i))
		}
		return CTag(TagInputRecord, CArr(mut(f)...))
	}
	cases := map[string][]byte{
		"wrong tag":         CTag(TagInputRecord+1, CArr(rebuild2(body, base)...)),
		"version 2":         rebuild(func(f [][]byte) [][]byte { f[0] = CUint(2); return f }),
		"arity 9":           rebuild(func(f [][]byte) [][]byte { return f[:9] }),
		"arity 11":          rebuild(func(f [][]byte) [][]byte { return append(f, CNull) }),
		"state hash null":   rebuild(func(f [][]byte) [][]byte { f[4] = CNull; return f }),
		"state hash 31":     rebuild(func(f [][]byte) [][]byte { f[4] = CBytes(make([]byte, 31)); return f }),
		"timestamp bytes":   rebuild(func(f [][]byte) [][]byte { f[6] = CBytes([]byte{1}); return f }),
		"summary 257":       rebuild(func(f [][]byte) [][]byte { f[5] = CBytes(make([]byte, 257)); return f }),
		"summary integer":   rebuild(func(f [][]byte) [][]byte { f[5] = CUint(1); return f }),
		"block hash 31":     rebuild(func(f [][]byte) [][]byte { f[7] = CBytes(make([]byte, 31)); return f }),
		"previous hash int": rebuild(func(f [][]byte) [][]byte { f[3] = CUint(1); return f }),
		"fees bytes":        rebuild(func(f [][]byte) [][]byte { f[8] = CBytes(nil); return f }),
		"trailing byte":     append(append([]byte{}, base...), 0),
		"oversize":          append(append([]byte{}, base...), make([]byte, MaxInputRecordBytes)...),
		"empty":             {},
	}
	for name, ir := range cases {
		t.Run(name, func(t *testing.T) {
			cp := e.composed(t, 1, irTimeOK)
			cp.env.Anchors[0].InputRecord = ir
			cp.env.Anchors[0].ExpectedIRHash = H(ir)
			_, err := cp.run(t, permissiveB1{RefB1{TB: e.TB}})
			require.ErrorIs(t, err, ErrIRShape)
		})
	}
	// Exactly the bound is accepted: a canonical record padded by a 256-byte summary.
	big := rewriteIR(t, base, func(ir *types.InputRecord) { ir.SummaryValue = make([]byte, MaxSummaryBytes) })
	require.LessOrEqual(t, len(big), MaxInputRecordBytes)
	cp := e.composed(t, 1, irTimeOK)
	cp.env.Anchors[0].InputRecord = big
	cp.env.Anchors[0].ExpectedIRHash = H(big)
	_, err = cp.run(t, permissiveB1{RefB1{TB: e.TB}})
	require.NoError(t, err, "a canonical opening at the size bound composes")
}

func rebuild2(body item, base []byte) [][]byte {
	var f [][]byte
	for i := range body.kids {
		f = append(f, base[body.kids[i].start:body.kids[i].end])
	}
	return f
}

func rewriteIR(t testing.TB, raw []byte, mut func(ir *types.InputRecord)) []byte {
	t.Helper()
	var ir types.InputRecord
	require.NoError(t, ir.UnmarshalCBOR(raw))
	mut(&ir)
	out, err := ir.Bytes()
	require.NoError(t, err)
	return out
}

func TestComposeAnchorAndLeafRejections(t *testing.T) {
	e := newEnv(t)
	t.Run("anchor not authenticated by an admitted root", func(t *testing.T) {
		other, err := NewAuthority("rogue")
		require.NoError(t, err)
		tb, err := other.TrustBase(3, 1)
		require.NoError(t, err)
		cp := e.composed(t, 2, irTimeOK)
		_, err = cp.run(t, RefB1{TB: tb})
		require.ErrorIs(t, err, ErrAnchorAuth)
	})
	t.Run("expected IR hash not the certificate's", func(t *testing.T) {
		cp := e.composed(t, 2, irTimeOK)
		cp.env.Anchors[0].ExpectedIRHash[0] ^= 1
		_, err := cp.run(t, RefB1{TB: e.TB})
		require.ErrorIs(t, err, ErrAnchorAuth)
	})
	t.Run("expected state root not the certificate's", func(t *testing.T) {
		cp := e.composed(t, 2, irTimeOK)
		cp.env.Anchors[0].ExpectedStateRoot[0] ^= 1
		_, err := cp.run(t, RefB1{TB: e.TB})
		require.ErrorIs(t, err, ErrAnchorAuth)
	})
	t.Run("one corrupted path rejects the whole proof", func(t *testing.T) {
		for i := range e.composed(t, 2, irTimeOK).res.Leaves {
			cp := e.composed(t, 2, irTimeOK)
			cp.env.LeafProofs[i].Bitmap = cp.cert.Proofs[i].Bitmap
			if len(cp.env.LeafProofs[i].Siblings) == 0 {
				cp.env.LeafProofs[i].Siblings = [][32]byte{{1}}
				cp.env.LeafProofs[i].Bitmap = [32]byte{0x80}
			} else {
				cp.env.LeafProofs[i].Siblings = append([][32]byte{}, cp.cert.Proofs[i].Siblings...)
				cp.env.LeafProofs[i].Siblings[0][0] ^= 1
			}
			_, err := cp.run(t, RefB1{TB: e.TB})
			require.ErrorIs(t, err, ErrLeafProof, "leaf %d", i)
		}
	})
	t.Run("the txHash is not the leaf value", func(t *testing.T) {
		cp := e.composed(t, 2, irTimeOK)
		confused := make([]Leaf, len(cp.res.Leaves))
		for i, l := range cp.res.Leaves {
			confused[i] = Leaf{SID: l.SID, Value: l.TxHash}
		}
		cert, err := e.Agg.Certify(confused, nil, irTimeOK, 100)
		require.NoError(t, err)
		cp.env.Anchors, cp.env.LeafProofs = []Anchor{cert.Anchor}, cert.Proofs
		_, err = cp.run(t, RefB1{TB: e.TB})
		require.ErrorIs(t, err, ErrLeafProof)
	})
	t.Run("paths in the wrong order", func(t *testing.T) {
		cp := e.composed(t, 2, irTimeOK)
		cp.env.LeafProofs[0], cp.env.LeafProofs[1] = cp.env.LeafProofs[1], cp.env.LeafProofs[0]
		_, err := cp.run(t, RefB1{TB: e.TB})
		require.ErrorIs(t, err, ErrLeafProof)
	})
	t.Run("policy and counts are checked before B1", func(t *testing.T) {
		cp := e.composed(t, 2, irTimeOK)
		cp.env.LeafProofs = cp.env.LeafProofs[:1]
		_, err := cp.run(t, RefB1{TB: e.TB})
		require.ErrorIs(t, err, ErrPolicyLeafCount)
		cp = e.composed(t, 2, irTimeOK)
		cp.env.Anchors[0].Partition++
		_, err = cp.run(t, RefB1{TB: e.TB})
		require.ErrorIs(t, err, ErrPolicyTuple)
	})
}

// A later anchor re-proves the same leaves; the original t never moves.
func TestComposeRefreshPreservesReferenceTimes(t *testing.T) {
	e := newEnv(t)
	cp := e.composed(t, 2, irTimeOK)
	_, err := cp.run(t, RefB1{TB: e.TB})
	require.NoError(t, err)
	later, err := e.Agg.Certify(cp.res.Leaves, []Leaf{{SID: H([]byte("newer")), Value: H([]byte("n"))}}, irTimeOK+3600, 900)
	require.NoError(t, err)
	cp.env.Anchors, cp.env.LeafProofs = []Anchor{later.Anchor}, later.Proofs
	res, err := cp.run(t, RefB1{TB: e.TB})
	require.NoError(t, err)
	for i, l := range res.Leaves {
		require.Equal(t, cp.res.Leaves[i], l, "leaf %d is unchanged by refresh", i)
	}
	// Substituting the refresh certificate's timestamp for t rebuilds a different
	// leaf: the old paths do not prove it.
	for i := range cp.h.Times {
		cp.h.Times[i] = irTimeOK + 3600
	}
	cp.h.MintTime = irTimeOK + 3600
	cp.env.History = cp.h.Bytes()
	_, err = cp.run(t, RefB1{TB: e.TB})
	require.ErrorIs(t, err, ErrLeafProof)
}

func TestComposeRejectsKernelFailuresFirst(t *testing.T) {
	e := newEnv(t)
	cp := e.composed(t, 2, irTimeOK)
	cp.h.Transfers[0].Data = []byte{1}
	cp.h.Refresh()
	require.NoError(t, cp.h.Resign(cp.keys))
	cp.env.History = cp.h.Bytes()
	_, err := cp.run(t, RefB1{TB: e.TB})
	require.ErrorIs(t, err, ErrTransferData)
	_ = big.NewInt
}
