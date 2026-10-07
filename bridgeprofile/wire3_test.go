package bridgeprofile

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"
)

// --- identifiers and the value envelope ----------------------------------------

func TestIdentifiersAreTheUnicityNativeFamily(t *testing.T) {
	var root, exec [32]byte
	root[0], exec[0] = 0x11, 0x22
	d := "3:" + hex.EncodeToString(root[:]) + ":" + hex.EncodeToString(exec[:]) + ":31337:" + string(bytes.Repeat([]byte("0"), 40))
	require.Equal(t, 1+1+64+1+64+1+5+1+40, len(d), "D has the documented shape")
	wantTy := H([]byte("unicity-bridge:unicity-native:" + d))
	wantAid := H([]byte("unicity-bridge-coin:unicity-native:" + d))
	require.Equal(t, wantTy, DeriveType(3, root, exec, 31337))
	require.Equal(t, wantAid, DeriveAsset(3, root, exec, 31337))
	require.NotEqual(t, wantTy, wantAid)

	// Every input of D moves both identifiers; the vault is not an input.
	for name, mut := range map[string]func() ([32]byte, [32]byte){
		"network": func() ([32]byte, [32]byte) {
			return DeriveType(4, root, exec, 31337), DeriveAsset(4, root, exec, 31337)
		},
		"root": func() ([32]byte, [32]byte) {
			r := root
			r[1]++
			return DeriveType(3, r, exec, 31337), DeriveAsset(3, r, exec, 31337)
		},
		"exec": func() ([32]byte, [32]byte) {
			e := exec
			e[1]++
			return DeriveType(3, root, e, 31337), DeriveAsset(3, root, e, 31337)
		},
		"chain": func() ([32]byte, [32]byte) {
			return DeriveType(3, root, exec, 31338), DeriveAsset(3, root, exec, 31338)
		},
	} {
		ty, aid := mut()
		require.NotEqual(t, wantTy, ty, name)
		require.NotEqual(t, wantAid, aid, name)
	}
	// Leading zeros never appear: chain 7 is "7", not "07".
	require.Equal(t, H([]byte("unicity-bridge:unicity-native:3:"+hex.EncodeToString(root[:])+":"+hex.EncodeToString(exec[:])+":7:"+string(bytes.Repeat([]byte("0"), 40)))),
		DeriveType(3, root, exec, 7))
}

func TestCfgValidateRecomputesIdentity(t *testing.T) {
	f := fix()
	require.NoError(t, f.Cfg.Validate())
	for name, mut := range map[string]func(c *Cfg){
		"type":      func(c *Cfg) { c.Ty[0] ^= 1 },
		"asset":     func(c *Cfg) { c.Aid[0] ^= 1 },
		"zero addr": func(c *Cfg) { c.ZeroAddress[19] = 1 },
		"vault":     func(c *Cfg) { c.Vault = [20]byte{} },
		"root":      func(c *Cfg) { c.RootGenesis[0] ^= 1 },
	} {
		c := *f.Cfg
		mut(&c)
		require.ErrorIs(t, c.Validate(), ErrCfgMismatch, name)
	}
	// Replacement vaults represent the same asset: only cfg, salts and locks differ.
	c := *f.Cfg
	c.Vault[0] ^= 1
	require.NoError(t, c.Validate())
	require.NotEqual(t, f.Cfg.Hash(), c.Hash())
}

func TestValueEnvelopeExactBytes(t *testing.T) {
	var aid [32]byte
	for i := range aid {
		aid[i] = byte(i)
	}
	got := ValueData(aid, big.NewInt(258))
	want := "d9988a" + "83" + "01" + "81" + "82" + "5820" + hex.EncodeToString(aid[:]) + "420102" + "f6"
	require.Equal(t, want, hex.EncodeToString(got))
	require.Equal(t, 39050, TagValue)
}

// --- SDK 3.0.1 transaction bytes ------------------------------------------------

func TestSDK3TransactionShapes(t *testing.T) {
	f := fix()
	h, keys, _ := retToken(t, f, 5, 2)
	// Arity and version: M 8/2, T 5/2, CD 6/2.
	m := h.Mint.Bytes()
	root, err := scanOne(m)
	require.NoError(t, err)
	require.Len(t, root.kids[0].kids, 8)
	require.Equal(t, uint64(2), root.kids[0].kids[0].arg)
	require.True(t, root.kids[0].kids[7].null, "constructors default to the null deadline")
	tr, _ := scanOne(h.Transfers[0].Bytes())
	require.Len(t, tr.kids[0].kids, 5)
	require.Equal(t, uint64(2), tr.kids[0].kids[0].arg)
	cd, _ := scanOne(h.MintCD.Bytes())
	require.Len(t, cd.kids[0].kids, 6)
	require.Equal(t, uint64(2), cd.kids[0].kids[0].arg)
	require.True(t, cd.kids[0].kids[4].null, "deadline precedes the unlock")
	require.True(t, cd.kids[0].kids[5].isBytes())
	require.Len(t, cd.kids[0].kids[5].data, 65)
	_ = keys
	// txHash commits the deadline: only the deadline changes the hash.
	a := h.Transfers[0]
	b := a
	b.Deadline = DeadlineAt(1 << 40)
	require.NotEqual(t, H(a.Bytes()), H(b.Bytes()))
}

func TestPre30ShapesRejected(t *testing.T) {
	f := fix()
	h, _, _ := retToken(t, f, 5, 2)
	good := h.Bytes()
	pr := func(old, repl []byte) error {
		_, err := DecodeHistory(replaceOnce(good, old, repl))
		return err
	}
	// v1 mint: version 1, arity 7, no deadline.
	m1 := CTag(TagMint, CArr(CUint(1), CUint(uint64(h.Mint.Network)), h.Mint.Recipient.Bytes(), CBytes(h.Mint.Salt[:]),
		CBytes(h.Mint.Type[:]), CNullOr(h.Mint.Justification), CNullOr(h.Mint.Data)))
	require.ErrorIs(t, pr(h.Mint.Bytes(), m1), ErrShape)
	// v1 transfer: version 1, arity 4.
	t1 := CTag(TagTransfer, CArr(CUint(1), h.Transfers[0].Recipient.Bytes(), CBytes(h.Transfers[0].Mask[:]), CNull))
	require.ErrorIs(t, pr(h.Transfers[0].Bytes(), t1), ErrShape)
	// v1 CD: arity 5, deadline absent.
	c := h.MintCD
	c1 := CTag(TagCertification, CArr(CUint(1), c.Source.Bytes(), CBytes(c.SourceHash[:]), CBytes(c.TxHash[:]), CBytes(c.Unlock)))
	require.ErrorIs(t, pr(h.MintCD.Bytes(), c1), ErrShape)
	// Right arity, old version: a v1 mint carrying the new trailing slot.
	m1b := CTag(TagMint, CArr(CUint(1), CUint(uint64(h.Mint.Network)), h.Mint.Recipient.Bytes(), CBytes(h.Mint.Salt[:]),
		CBytes(h.Mint.Type[:]), CNullOr(h.Mint.Justification), CNullOr(h.Mint.Data), CNull))
	require.ErrorIs(t, pr(h.Mint.Bytes(), m1b), ErrVersion)
	cb := CTag(TagCertification, CArr(CUint(1), c.Source.Bytes(), CBytes(c.SourceHash[:]), CBytes(c.TxHash[:]), CNull, CBytes(c.Unlock)))
	require.ErrorIs(t, pr(h.MintCD.Bytes(), cb), ErrVersion)
	// Old projection pair arity: [T,CD] without t.
	pair := CArr(CArr(h.Mint.Bytes(), h.MintCD.Bytes()), CArr())
	_, err := DecodeHistory(pair)
	require.ErrorIs(t, err, ErrShape)
	// Old pointer-only lock reason v1 (arity 5) and the old bare payload.
	c0 := f.Cfg
	old := CTag(TagMintLock, CArr(CUint(1), CUint(c0.ChainID), CBytes(c0.Vault[:]), CBytes(c0.ZeroAddress[:]), CUint(5)))
	_, _, err = ParseJustification(c0, old)
	require.ErrorIs(t, err, ErrMintJustif)
	// Lock reason v1 with the new arity.
	v1 := CTag(TagMintLock, CArr(CUint(1), CUint(c0.ChainID), CBytes(c0.Vault[:]), CBytes(c0.ZeroAddress[:]), CUint(5), f.StructuralProof(5).Bytes()))
	_, _, err = ParseJustification(c0, v1)
	require.ErrorIs(t, err, ErrMintJustif)
}

// --- deadlines and reference times ------------------------------------------------

// withDeadline gives transfer i the explicit deadline e and the certified time tt.
func withDeadline(t *testing.T, i int, e Deadline, tt uint64) (*Fixture, *History, []*secp256k1.PrivateKey) {
	t.Helper()
	f := fix()
	h, keys, _ := retToken(t, f, 5, 3)
	h.Transfers[i].Deadline = e
	h.Times[i] = tt
	require.NoError(t, h.Resign(keys))
	return f, h, keys
}

func TestDeadlineBoundary(t *testing.T) {
	const e = 1_700_000_500
	for _, c := range []struct {
		name string
		tt   uint64
		want error
	}{
		{"e-1", e - 1, nil},
		{"e", e, ErrDeadlineExpired},
		{"e+1", e + 1, ErrDeadlineExpired},
		{"far past", 1, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			f, h, _ := withDeadline(t, 1, DeadlineAt(e), c.tt)
			res, err := VerifyReturn(f.Cfg, roundTrip(t, h))
			if c.want == nil {
				require.NoError(t, err)
				require.Equal(t, c.tt, res.Leaves[2].ReferenceTime)
				return
			}
			require.ErrorIs(t, err, c.want)
			require.ErrorIs(t, err, ErrInvalid)
		})
	}
	// The mint carries a deadline too.
	f := fix()
	keys := []*secp256k1.PrivateKey{KeyFromSeed("md")}
	h, err := f.BuildTokenWith(5, amt, keys, BuildOpts{MintDeadline: DeadlineAt(BaseTime)})
	require.NoError(t, err)
	_, err = VerifyMint(f.Cfg, roundTrip(t, h))
	require.ErrorIs(t, err, ErrDeadlineExpired, "t == e at the mint")
	h, err = f.BuildTokenWith(5, amt, keys, BuildOpts{MintDeadline: DeadlineAt(BaseTime + 1)})
	require.NoError(t, err)
	_, err = VerifyMint(f.Cfg, roundTrip(t, h))
	require.NoError(t, err)
}

func TestNullDeadlineNeverExpires(t *testing.T) {
	f := fix()
	h, keys, _ := retToken(t, f, 5, 2)
	for i := range h.Times {
		h.Times[i] = 1<<64 - 1 // the largest reference time; null deadlines do not bind it
	}
	require.NoError(t, h.Resign(keys))
	_, err := VerifyReturn(f.Cfg, roundTrip(t, h))
	require.NoError(t, err)
}

func TestDeadlineMustEqualBetweenCDAndTransaction(t *testing.T) {
	type mm struct {
		name string
		mut  func(h *History)
	}
	for _, c := range []mm{
		{"tx explicit, cd null", func(h *History) { h.Transfers[0].Deadline = DeadlineAt(1 << 50); h.CDs[0].Deadline = NoDeadline }},
		{"tx null, cd explicit", func(h *History) { h.CDs[0].Deadline = DeadlineAt(1 << 50) }},
		{"both explicit, differ", func(h *History) {
			h.Transfers[0].Deadline = DeadlineAt(1 << 50)
			h.CDs[0].Deadline = DeadlineAt(1<<50 + 1)
		}},
		{"mint explicit, cd null", func(h *History) { h.Mint.Deadline = DeadlineAt(1 << 50) }},
		{"mint null, cd explicit", func(h *History) { h.MintCD.Deadline = DeadlineAt(1 << 50) }},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := fix()
			h, _, _ := retToken(t, f, 5, 2)
			c.mut(h)
			// The transaction hash must stay consistent with its (mutated)
			// bytes, so the isolated failing relation is the deadline equality.
			h.Refresh()
			h.CDs[0].TxHash = H(h.transfersRaw[0])
			h.MintCD.TxHash = H(h.mintRaw)
			_, err := VerifyReturn(f.Cfg, roundTrip(t, h))
			if c.name == "mint explicit, cd null" || c.name == "tx explicit, cd null" {
				// txHash covers the new deadline, which invalidates the CD's source
				// chain only through the unlock; the deadline equality fires first.
				require.ErrorIs(t, err, ErrDeadlineMismatch)
				return
			}
			require.ErrorIs(t, err, ErrDeadlineMismatch)
		})
	}
}

func TestDeadlineEncodingRejected(t *testing.T) {
	f := fix()
	h, _, _ := retToken(t, f, 5, 1)
	good := h.Bytes()
	mutM := func(e []byte) error {
		m := CTag(TagMint, CArr(CUint(2), CUint(uint64(h.Mint.Network)), h.Mint.Recipient.Bytes(), CBytes(h.Mint.Salt[:]),
			CBytes(h.Mint.Type[:]), CNullOr(h.Mint.Justification), CNullOr(h.Mint.Data), e))
		_, err := DecodeHistory(replaceOnce(good, h.Mint.Bytes(), m))
		return err
	}
	require.NoError(t, mutM(CNull))
	require.NoError(t, mutM(CUint(1)))
	require.NoError(t, mutM(CUint(1<<64-1)))
	require.ErrorIs(t, mutM(CUint(0)), ErrDeadline, "e = 0")
	require.ErrorIs(t, mutM(CBytes([]byte{1})), ErrDeadline, "byte string")
	require.ErrorIs(t, mutM(CArr()), ErrDeadline, "array")
	require.ErrorIs(t, mutM([]byte{0x18, 0x01}), ErrNonCanonical, "non-shortest head")
	require.ErrorIs(t, mutM([]byte{0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}), ErrTruncated, "overflowing head")
	require.ErrorIs(t, mutM([]byte{0x20}), ErrForbiddenCBOR, "negative integer")
	require.ErrorIs(t, mutM([]byte{0xf4}), ErrForbiddenCBOR, "false")
	// And the same slot inside a CD and a transfer.
	cdz := CTag(TagCertification, CArr(CUint(2), h.MintCD.Source.Bytes(), CBytes(h.MintCD.SourceHash[:]), CBytes(h.MintCD.TxHash[:]), CUint(0), CBytes(h.MintCD.Unlock)))
	_, err := DecodeHistory(replaceOnce(good, h.MintCD.Bytes(), cdz))
	require.ErrorIs(t, err, ErrDeadline)
	tz := CTag(TagTransfer, CArr(CUint(2), h.Transfers[0].Recipient.Bytes(), CBytes(h.Transfers[0].Mask[:]), CNull, CUint(0)))
	_, err = DecodeHistory(replaceOnce(good, h.Transfers[0].Bytes(), tz))
	require.ErrorIs(t, err, ErrDeadline)
}

func TestLeafValueIsNotTheTxHash(t *testing.T) {
	f := fix()
	h, _, _ := retToken(t, f, 5, 2)
	res, err := VerifyReturn(f.Cfg, h.Bytes())
	require.NoError(t, err)
	for i, l := range res.Leaves {
		require.Equal(t, LeafValue(l.TxHash, l.ReferenceTime), l.Value)
		require.NotEqual(t, l.TxHash, l.Value, "txHash alone is not the value")
		require.NotEqual(t, Imprint(l.TxHash)[2:], l.Value[:])
		require.Equal(t, H(CArr(CBytes(l.TxHash[:]), CUint(l.ReferenceTime))), l.Value)
		_ = i
	}
	// t is part of the value; the same transaction at another time is another leaf.
	require.NotEqual(t, LeafValue(res.Leaves[0].TxHash, 1), LeafValue(res.Leaves[0].TxHash, 2))
	// Changing only a projected t changes only that leaf's value, never sid or txHash.
	h.Times[0]++
	res2, err := VerifyReturn(f.Cfg, h.Bytes())
	require.NoError(t, err)
	require.Equal(t, res.Leaves[1].SID, res2.Leaves[1].SID)
	require.Equal(t, res.Leaves[1].TxHash, res2.Leaves[1].TxHash)
	require.NotEqual(t, res.Leaves[1].Value, res2.Leaves[1].Value)
	require.Equal(t, res.Leaves[2], res2.Leaves[2])
}
