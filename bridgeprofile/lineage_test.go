package bridgeprofile

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

func newLineage(t testing.TB) (*env, *LineageBuilder) {
	t.Helper()
	e := newEnv(t)
	b, err := NewLineageBuilder(e.Deployment)
	require.NoError(t, err)
	return e, b
}

// tokenWithSplit builds root(100) -> {40, 60}, then returns the 40 part burned for its whole amount.
func tokenWithSplit(t testing.TB, b *LineageBuilder, hk *SplitHooks) (root *LineageToken, kids []*LineageToken) {
	return tokenWithSplitX(t, b, hk, SplitOut{Label: "x", Amount: big.NewInt(40), Owners: lineageKeys("x")})
}

// tokenWithSplitX is tokenWithSplit with the first output given.
func tokenWithSplitX(t testing.TB, b *LineageBuilder, hk *SplitHooks, x SplitOut) (root *LineageToken, kids []*LineageToken) {
	t.Helper()
	root, err := b.Root(5, big.NewInt(100), lineageKeys("root"))
	require.NoError(t, err)
	kids, err = b.Split(root, []SplitOut{
		x,
		{Label: "y", Amount: big.NewInt(60), Owners: lineageKeys("y")},
	}, hk)
	require.NoError(t, err)
	return root, kids
}

func verifyPart(t testing.TB, e *env, part *LineageToken, amount *big.Int) (*Lineage, error) {
	t.Helper()
	b := NewLineageBuilderMust(t, e)
	b.Return(part, rcpt, amount)
	return VerifyLineageReturn(e.F.Cfg, part.H.Bytes(), ComposedHistory)
}

func NewLineageBuilderMust(t testing.TB, e *env) *LineageBuilder {
	b, err := NewLineageBuilder(e.Deployment)
	require.NoError(t, err)
	return b
}

// sum-tree: every leaf of trees of fan-out 1, 2, 16 and 256 proves its amount and the total, and nothing else.
func TestSumTreeProofs(t *testing.T) {
	for _, n := range []int{1, 2, 3, 16, 256} {
		var leaves []SumLeaf
		total := new(big.Int)
		for i := 0; i < n; i++ {
			v := big.NewInt(int64(i + 1))
			leaves = append(leaves, SumLeaf{Key: H([]byte(fmt.Sprint("k", i))), Data: H([]byte(fmt.Sprint("d", i))), Value: v})
			total.Add(total, v)
		}
		tree, err := BuildSumTree(leaves)
		require.NoError(t, err)
		require.Equal(t, total, tree.Total())
		for _, l := range leaves {
			p, ok := tree.Proof(l.Key)
			require.True(t, ok)
			sum, ok := p.Verify(l.Key, l.Data, l.Value, tree.Root())
			require.True(t, ok, "fan-out %d", n)
			require.Equal(t, total, sum)
			// wrong amount, key, data and root each fail
			_, ok = p.Verify(l.Key, l.Data, new(big.Int).Add(l.Value, big.NewInt(1)), tree.Root())
			require.False(t, ok)
			_, ok = p.Verify(H([]byte("other")), l.Data, l.Value, tree.Root())
			require.False(t, ok)
			_, ok = p.Verify(l.Key, H([]byte("other")), l.Value, tree.Root())
			require.False(t, ok)
			_, ok = p.Verify(l.Key, l.Data, l.Value, H([]byte("other")))
			require.False(t, ok)
		}
		// the proof of an absent key does not exist
		_, ok := tree.Proof(H([]byte("absent")))
		if n > 0 {
			require.False(t, ok)
		}
	}
}

func TestSumTreeIsOrderIndependent(t *testing.T) {
	var a, b []SumLeaf
	for i := 0; i < 9; i++ {
		l := SumLeaf{Key: H([]byte(fmt.Sprint("k", i))), Data: H([]byte("d")), Value: big.NewInt(int64(i + 1))}
		a = append(a, l)
		b = append([]SumLeaf{l}, b...)
	}
	ta, err := BuildSumTree(a)
	require.NoError(t, err)
	tb, err := BuildSumTree(b)
	require.NoError(t, err)
	require.Equal(t, ta.Root(), tb.Root())
}

// Builder refusals: duplicate keys, zero amounts, empty and overflowing trees.
func TestSumTreeBuilderRefusals(t *testing.T) {
	k, d := H([]byte("k")), H([]byte("d"))
	max := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	_, err := BuildSumTree(nil)
	require.ErrorIs(t, err, ErrSplitProofShape)
	_, err = BuildSumTree([]SumLeaf{{k, d, big.NewInt(1)}, {k, H([]byte("d2")), big.NewInt(2)}})
	require.ErrorIs(t, err, ErrSplitProofShape, "duplicate key")
	_, err = BuildSumTree([]SumLeaf{{k, d, new(big.Int)}})
	require.ErrorIs(t, err, ErrSplitProofShape, "zero amount")
	_, err = BuildSumTree([]SumLeaf{{k, d, new(big.Int).Lsh(big.NewInt(1), 256)}})
	require.ErrorIs(t, err, ErrSplitProofShape, "amount over 2^256-1")
	_, err = BuildSumTree([]SumLeaf{{k, d, max}, {H([]byte("k2")), d, big.NewInt(1)}})
	require.ErrorIs(t, err, ErrSplitProofShape, "sum overflow")
}

// A full-width (256-step) proof: two keys that agree on 255 bits.
func TestSumProofAtMaxDepth(t *testing.T) {
	var a, c [32]byte
	c[31] = 1
	tree, err := BuildSumTree([]SumLeaf{{a, H([]byte("a")), big.NewInt(7)}, {c, H([]byte("c")), big.NewInt(5)}})
	require.NoError(t, err)
	p, ok := tree.Proof(a)
	require.True(t, ok)
	require.Len(t, p, 1)
	require.Equal(t, uint8(255), p[0].Depth)
	sum, ok := p.Verify(a, H([]byte("a")), big.NewInt(7), tree.Root())
	require.True(t, ok)
	require.Equal(t, big.NewInt(12), sum)
}

// Proof decoding is strict: step count, depth order, sums, hash width.
func TestDecodeSumProofStrict(t *testing.T) {
	step := func(depth uint64, hash []byte, sum []byte) []byte {
		return CArr(CUint(depth), CBytes(hash), CBytes(sum))
	}
	h := make([]byte, 32)
	dec := func(b []byte) error {
		it, err := scanOne(b)
		require.NoError(t, err)
		_, err = decodeSumProof(it)
		return err
	}
	require.NoError(t, dec(CArr(step(9, h, []byte{7}), step(3, h, []byte{1}))))
	require.NoError(t, dec(CArr()), "the empty proof is the single-leaf tree")
	require.ErrorIs(t, dec(CArr(step(3, h, []byte{7}), step(3, h, []byte{1}))), ErrSplitProofShape, "equal depths")
	require.ErrorIs(t, dec(CArr(step(3, h, []byte{7}), step(5, h, []byte{1}))), ErrSplitProofShape, "increasing depths")
	require.ErrorIs(t, dec(CArr(step(256, h, []byte{7}))), ErrSplitProofShape, "depth over 255")
	require.ErrorIs(t, dec(CArr(step(3, h, []byte{}))), ErrSplitProofShape, "zero sum")
	require.ErrorIs(t, dec(CArr(step(3, h, []byte{0, 1}))), ErrSplitProofShape, "non-minimal sum")
	require.ErrorIs(t, dec(CArr(step(3, h, make([]byte, 33)))), ErrSplitProofShape, "sum over 256 bits")
	require.Error(t, dec(CArr(step(3, h[:31], []byte{1}))), "short hash")
	var many [][]byte
	for i := 0; i < 257; i++ {
		many = append(many, step(uint64(255-i%256), h, []byte{1}))
	}
	require.ErrorIs(t, dec(CArr(many...)), ErrSplitProofShape, "more than 256 steps")
}

// Depth 0 is the ordinary full redemption: the lineage result is the plain result with the part equal to the root.
func TestLineageDepthZeroEqualsPlainRedemption(t *testing.T) {
	e, b := newLineage(t)
	root, err := b.Root(5, amt, lineageKeys("plain"))
	require.NoError(t, err)
	b.Return(root, rcpt, amt)
	lin, err := VerifyLineageReturn(e.F.Cfg, root.H.Bytes(), ComposedHistory)
	require.NoError(t, err)
	plain, err := VerifyReturnWith(e.F.Cfg, root.H.Bytes(), ComposedHistory)
	require.NoError(t, err)
	require.Equal(t, plain.Leaves, lin.Leaves)
	require.Equal(t, plain.LockDigest, lin.LockDigest)
	require.Equal(t, plain.Nullifier, lin.Nullifier)
	require.Equal(t, plain.ReleaseTo, lin.ReleaseTo)
	require.Equal(t, plain.TokenID, lin.PartTokenID)
	require.Equal(t, plain.Amount, lin.PartAmount)
	require.Zero(t, lin.Depth)
}

// A split part redeems for its own amount while the lock identity is the root's.
func TestLineageOneSplit(t *testing.T) {
	e, b := newLineage(t)
	root, kids := tokenWithSplit(t, b, nil)
	lin, err := verifyPart(t, e, kids[0], big.NewInt(40))
	require.NoError(t, err)
	require.Equal(t, uint64(1), lin.Depth)
	require.Equal(t, big.NewInt(100), lin.Amount, "the lock amount is the root's")
	require.Equal(t, big.NewInt(40), lin.PartAmount)
	require.Equal(t, root.ID, lin.TokenID)
	require.Equal(t, kids[0].ID, lin.PartTokenID)
	require.Equal(t, uint64(5), lin.Nonce)
	// L = 2d + 2 + T with T = 0 ordinary transfers beyond each level's burn: root mint+transfer(1 owner hop)+burn, part mint+hop+burn
	require.Len(t, lin.Leaves, len(root.H.Transfers)+1+len(kids[0].H.Transfers)+1)
	require.Equal(t, []int{len(root.H.Transfers) + 1, len(kids[0].H.Transfers) + 1}, []int{lin.Levels[0].Leaves, lin.Levels[1].Leaves})
	// the lock digest is the digest of the full 100 lock, never recomputed with the part amount
	want := e.LockDigestFor(5, big.NewInt(100), sigPred(root.Owners[0]))
	require.Equal(t, want, lin.LockDigest)
	// the leaf order is root first: the root's mint is the first leaf
	mk, _ := MinterKey(root.ID)
	require.Equal(t, StateID(sigPred(mk), MintSourceHash(root.ID)), lin.Leaves[0].SID)
}

// Both siblings redeem from the same lock with distinct part IDs and the same lock identity.
func TestLineageSiblingsShareTheLock(t *testing.T) {
	e, b := newLineage(t)
	_, kids := tokenWithSplit(t, b, nil)
	l0, err := verifyPart(t, e, kids[0], big.NewInt(40))
	require.NoError(t, err)
	l1, err := verifyPart(t, e, kids[1], big.NewInt(60))
	require.NoError(t, err)
	require.Equal(t, l0.LockDigest, l1.LockDigest)
	require.Equal(t, l0.Nonce, l1.Nonce)
	require.NotEqual(t, l0.PartTokenID, l1.PartTokenID)
	require.NotEqual(t, l0.Nullifier, l1.Nullifier)
	require.Equal(t, big.NewInt(100), new(big.Int).Add(l0.PartAmount, l1.PartAmount))
}

// Repeated splits: depths 1, 2, 5 and 8; the lock amount and identity never change and the leaf count is the sum over levels.
func TestLineageRepeatedSplits(t *testing.T) {
	e, b := newLineage(t)
	for _, depth := range []int{1, 2, 5, 8} {
		part, err := b.Chain(7, big.NewInt(1<<20), depth, fmt.Sprint("chain", depth))
		require.NoError(t, err)
		b.Return(part, rcpt, part.Amount)
		lin, err := VerifyLineageReturn(e.F.Cfg, part.H.Bytes(), ComposedHistory)
		require.NoError(t, err, "depth %d", depth)
		require.Equal(t, uint64(depth), lin.Depth)
		require.Len(t, lin.Levels, depth+1)
		require.Equal(t, big.NewInt(1<<20), lin.Amount)
		require.Equal(t, part.Amount, lin.PartAmount)
		n := 0
		for _, lv := range lin.Levels {
			n += lv.Leaves
		}
		require.Len(t, lin.Leaves, n)
		// every token here has a mint, one owner hop and its burn: three leaves, so L = 2d+2+T with T = d+1 ordinary transfers
		require.Len(t, lin.Leaves, 3*(depth+1))
	}
}

// The composition accepts a lineage under real certificates and returns the same result whatever anchors carry it.
func TestComposeLineage(t *testing.T) {
	e, b := newLineage(t)
	_, kids := tokenWithSplit(t, b, nil)
	b.Return(kids[0], rcpt, big.NewInt(40))
	var nulls [][32]byte
	for _, irTime := range []uint64{BaseTime + 1000, BaseTime + 5000} {
		env, lin, _, err := b.Envelope(kids[0], irTime)
		require.NoError(t, err)
		enc, err := env.Encode()
		require.NoError(t, err)
		got, err := ComposeLineage(e.F.Cfg, OpReturn, enc, RefB1{TB: e.TB})
		require.NoError(t, err)
		require.Equal(t, lin.Result, got.Result)
		nulls = append(nulls, got.Nullifier)
	}
	require.Equal(t, nulls[0], nulls[1], "refreshed witnesses leave the nullifier unchanged")
}

// negatives: each changes exactly one property of an otherwise valid lineage.
func TestLineageNegatives(t *testing.T) {
	e, b := newLineage(t)
	cfg := e.F.Cfg
	one := big.NewInt(1)

	type tc struct {
		name string
		hk   *SplitHooks
		amt  *big.Int // return amount of the part x (40 unless set)
		want error
	}
	cases := []tc{
		{name: "tree understates the part's allocation", hk: &SplitHooks{TreeValues: []*big.Int{big.NewInt(39), big.NewInt(60)}}, want: ErrSplitProof},
		{name: "tree total under the source amount", hk: &SplitHooks{TreeValues: []*big.Int{big.NewInt(40), big.NewInt(59)}}, want: ErrSplitSum},
		{name: "tree total over the source amount", hk: &SplitHooks{TreeValues: []*big.Int{big.NewInt(40), big.NewInt(61)}}, want: ErrSplitSum},
		{name: "child salt changed after commitment", hk: &SplitHooks{ChildMint: func(i int, m *MintTx) {
			if i == 0 {
				m.Salt[0] ^= 1
			}
		}}, want: ErrSplitProof},
		{name: "child amount raised after commitment", hk: &SplitHooks{ChildMint: func(i int, m *MintTx) {
			if i == 0 {
				m.Data = ValueData(cfg.Aid, big.NewInt(41))
			}
		}}, want: ErrSplitProof},
		{name: "child type changed", hk: &SplitHooks{ChildMint: func(i int, m *MintTx) {
			if i == 0 {
				m.Type[0] ^= 1
			}
		}}, want: ErrMintType},
		{name: "child network changed", hk: &SplitHooks{ChildMint: func(i int, m *MintTx) {
			if i == 0 {
				m.Network++
			}
		}}, want: ErrMintShape},
		{name: "child asset changed", hk: &SplitHooks{ChildMint: func(i int, m *MintTx) {
			if i == 0 {
				m.Data = ValueData(H([]byte("another asset")), big.NewInt(40))
			}
		}}, want: ErrMintData},
		{name: "child carries the lock reason instead of the split reason", hk: &SplitHooks{ChildMint: func(i int, m *MintTx) {
			if i == 0 {
				m.Justification = MintJustification(cfg.ChainID, cfg.Vault, cfg.ZeroAddress, 5, e.F.StructuralProof(5))
			}
		}}, want: ErrMintSalt},
		{name: "child justification is neither reason", hk: &SplitHooks{ChildMint: func(i int, m *MintTx) {
			if i == 0 {
				m.Justification = CTag(39099, CArr(CUint(1)))
			}
		}}, want: ErrMintJustif},
		{name: "child has no justification", hk: &SplitHooks{ChildMint: func(i int, m *MintTx) {
			if i == 0 {
				m.Justification = nil
			}
		}}, want: ErrMintJustif},
		{name: "proof depth changed", hk: &SplitHooks{Proof: func(i int, p SumProof) SumProof {
			if i == 0 {
				q := append(SumProof{}, p...)
				q[0].Depth = 200
				return q
			}
			return p
		}}, want: ErrSplitProof},
		{name: "proof sibling sum inflated", hk: &SplitHooks{Proof: func(i int, p SumProof) SumProof {
			if i == 0 {
				q := append(SumProof{}, p...)
				q[len(q)-1].Sum = new(big.Int).Add(q[len(q)-1].Sum, one)
				return q
			}
			return p
		}}, want: ErrSplitProof},
		{name: "proof truncated", hk: &SplitHooks{Proof: func(i int, p SumProof) SumProof {
			if i == 0 {
				return p[:len(p)-1]
			}
			return p
		}}, want: ErrSplitProof},
		{name: "burn data is another manifest root", hk: &SplitHooks{Manifest: func(m SplitManifest) []byte {
			m.Root[0] ^= 1
			return m.Bytes()
		}}, want: ErrSplitProof},
		{name: "burn data is not a manifest", hk: &SplitHooks{Manifest: func(SplitManifest) []byte { return []byte{0x01} }}, want: ErrSplitManifest},
		{name: "burn data is a return reason", hk: &SplitHooks{Manifest: func(SplitManifest) []byte {
			return ReturnReason(cfg.ChainID, cfg.Vault, cfg.ZeroAddress, cfg.Ty, cfg.Aid, rcpt, big.NewInt(100))
		}}, want: ErrSplitManifest},
		{name: "parent does not end in a burn", hk: &SplitHooks{NoSplitBurn: true}, want: ErrSplitBurn},
		{name: "partial-part return", amt: big.NewInt(39), want: ErrReturnAmount},
		{name: "return of more than the part", amt: big.NewInt(100), want: ErrReturnAmount},
	}
	t.Run("proof prepared for another recipient", func(t *testing.T) {
		_, kids := tokenWithSplitX(t, b, nil, SplitOut{Label: "x", Amount: big.NewInt(40), Owners: lineageKeys("x"), CommitTo: KeyFromSeed("intended")})
		b.Return(kids[0], rcpt, big.NewInt(40))
		_, err := VerifyLineageReturn(cfg, kids[0].H.Bytes(), ComposedHistory)
		require.ErrorIs(t, err, ErrSplitProof)
	})
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, kids := tokenWithSplit(t, b, c.hk)
			ret := c.amt
			if ret == nil {
				ret = big.NewInt(40)
			}
			b.Return(kids[0], rcpt, ret)
			_, err := VerifyLineageReturn(cfg, kids[0].H.Bytes(), ComposedHistory)
			require.ErrorIs(t, err, c.want)
		})
	}
}

// The byte formats are the Rust SDK's (unicity-token at state-transition-sdk-rust 7ed017e, examples/splitvec.rs): the same seven
// leaves, tree, proofs, manifest and commitment, produced by that code and copied here. PR2 repeats the check against the JS SDK
// and the reviewed SDK revisions.
func TestSumTreeMatchesRustSDK(t *testing.T) {
	var leaves []SumLeaf
	for i, v := range []int64{10, 20, 30, 40, 5, 1, 7} {
		leaves = append(leaves, SumLeaf{Key: H([]byte(fmt.Sprint("k", i))), Data: H([]byte(fmt.Sprint("d", i))), Value: big.NewInt(v)})
	}
	tree, err := BuildSumTree(leaves)
	require.NoError(t, err)
	require.Equal(t, "9eea1208997e6265a6721ed964faa8c944088f328c449ae79fb2ca10a8d7c0f1", fmt.Sprintf("%x", tree.Root()))
	require.Equal(t, big.NewInt(113), tree.Total())
	proofs := []string{
		"8283015820a3e3bee5f9f1ba8e61dc76e43b7f83cbf13c402dabdeb570216c55666e5600c34106830058205439cfb032742013466d9905edf97e80ab3a57aa1258a06b58bdd38b898fb99b4161",
		"8283015820676f2f41042f2c6fa63ed309708d333fba9fa4b72e9a33cce776c8a5c99d9048414d8300582080859c09ae3a636a467faa0b0c8559d5db97fa3a8abb4fd09a4f7824d6c1f2f04110",
		"8483035820fa023a879689320bea216f8534a8ac8c68cca73810fe54c46cf5d4b607f1e03b4107830258202f225e9909d85bea92598c631cffc5a3ded2d1474ffd5e972f6910018e2c2f4a4128830158204706676c14fefc14d858107f3eb013a3e838388d963fbe711694210309328bce41148300582080859c09ae3a636a467faa0b0c8559d5db97fa3a8abb4fd09a4f7824d6c1f2f04110",
		"8383025820ba878813f6f1c8916af6b7aef8e6fb1aa024395bd654db8cb1323a3fa37748d54125830158204706676c14fefc14d858107f3eb013a3e838388d963fbe711694210309328bce41148300582080859c09ae3a636a467faa0b0c8559d5db97fa3a8abb4fd09a4f7824d6c1f2f04110",
		"83830358202d4fffa06a72e2cb323dac21bdf75509e0b7268d5a6b2cf5ea15598ed88f46fa4101830158206d64abf86a8428f7d508c258e6ae1413151fbbd0168ab3c7f4bec3d7adac36a6410a830058205439cfb032742013466d9905edf97e80ab3a57aa1258a06b58bdd38b898fb99b4161",
		"83830358203d5bfdf2cfef792bc29e62fda9c413a926794978c4af382e01250c94042f56b14105830158206d64abf86a8428f7d508c258e6ae1413151fbbd0168ab3c7f4bec3d7adac36a6410a830058205439cfb032742013466d9905edf97e80ab3a57aa1258a06b58bdd38b898fb99b4161",
		"8483035820567463038addeef1b5659f7084492dbb7678c75c1aa9d8bd64f12a3b931711d3411e830258202f225e9909d85bea92598c631cffc5a3ded2d1474ffd5e972f6910018e2c2f4a4128830158204706676c14fefc14d858107f3eb013a3e838388d963fbe711694210309328bce41148300582080859c09ae3a636a467faa0b0c8559d5db97fa3a8abb4fd09a4f7824d6c1f2f04110",
	}
	for i, l := range leaves {
		p, ok := tree.Proof(l.Key)
		require.True(t, ok)
		require.Equal(t, proofs[i], fmt.Sprintf("%x", p.Bytes()), "proof %d", i)
	}
	man := SplitManifest{Root: tree.Root()}
	require.Equal(t, "d998868158209eea1208997e6265a6721ed964faa8c944088f328c449ae79fb2ca10a8d7c0f1", fmt.Sprintf("%x", man.Bytes()))
	require.Equal(t, "1272ced37675eb83af20051a4dfd03b100165e3802d5f9f72073b560b77d905e", fmt.Sprintf("%x", man.ReasonHash()))
	pred := SignaturePredicate(bytes32x33(2))
	require.Equal(t, "d99878830141015821020202020202020202020202020202020202020202020202020202020202020202", fmt.Sprintf("%x", pred.Bytes()))
	c := splitOutputCommitment(H([]byte("src")), 3, pred, H([]byte("salt")), H([]byte("out")), H([]byte("type")), []byte("payload-bytes"))
	require.Equal(t, "c577cb851297a8ccacdd180dcb743879b217434eef5c1f0d122dbcb729125dfa", fmt.Sprintf("%x", c))
}

// The state-ID set is global to the lineage: a child that reuses an ancestor's token ID repeats the ancestor's mint state.
func TestLineageRepeatedIDAcrossLevels(t *testing.T) {
	e, b := newLineage(t)
	root, err := b.Root(5, big.NewInt(100), lineageKeys("root"))
	require.NoError(t, err)
	salt := root.H.Mint.Salt
	kids, err := b.Split(root, []SplitOut{
		{Label: "x", Amount: big.NewInt(40), Owners: lineageKeys("x"), Salt: &salt},
		{Label: "y", Amount: big.NewInt(60), Owners: lineageKeys("y")},
	}, nil)
	require.NoError(t, err)
	require.Equal(t, root.ID, kids[0].ID)
	b.Return(kids[0], rcpt, big.NewInt(40))
	_, err = VerifyLineageReturn(e.F.Cfg, kids[0].H.Bytes(), ComposedHistory)
	require.ErrorIs(t, err, ErrRepeatedSID)
}

// A forged ancestor: each fault is in the embedded parent token, which the part's own mint hash commits to.
func TestLineageForgedAncestor(t *testing.T) {
	e, b := newLineage(t)
	cfg := e.F.Cfg
	cases := []struct {
		name string
		src  func(h *History)
		want error
	}{
		{"parent unlock signature invalid", func(h *History) { h.CDs[len(h.CDs)-1].Unlock[0] ^= 1 }, ErrUnlockKey},
		{"parent mint certification data not its mint", func(h *History) { h.MintCD.TxHash[0] ^= 1 }, ErrCDMismatch},
		{"parent mint is not lock-backed by this vault", func(h *History) {
			h.Mint.Justification = MintJustification(cfg.ChainID, [20]byte{9}, cfg.ZeroAddress, 5, e.F.StructuralProof(5))
			_ = h.Resign(lineageKeys("root"))
		}, ErrMintJustif},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, kids := tokenWithSplit(t, b, &SplitHooks{ParentSource: c.src})
			b.Return(kids[0], rcpt, big.NewInt(40))
			_, err := VerifyLineageReturn(cfg, kids[0].H.Bytes(), ComposedHistory)
			require.Error(t, err)
			require.ErrorIs(t, err, c.want)
		})
	}
}

// The envelope must witness every leaf of the lineage in order, each under an authenticated seal that is not before its time.
func TestComposeLineageWitnesses(t *testing.T) {
	e, b := newLineage(t)
	_, kids := tokenWithSplit(t, b, nil)
	b.Return(kids[0], rcpt, big.NewInt(40))
	env, lin, _, err := b.Envelope(kids[0], BaseTime+1000)
	require.NoError(t, err)
	run := func(env *Envelope) error {
		enc, err := env.Encode()
		require.NoError(t, err)
		_, err = ComposeLineage(e.F.Cfg, OpReturn, enc, RefB1{TB: e.TB})
		return err
	}
	require.NoError(t, run(env))
	require.Greater(t, len(lin.Leaves), 4)

	missing := *env
	missing.LeafProofs = env.LeafProofs[1:]
	require.ErrorIs(t, run(&missing), ErrPolicyLeafCount, "an ancestor leaf without a witness")

	swapped := *env
	swapped.LeafProofs = append([]LeafProof{}, env.LeafProofs...)
	swapped.LeafProofs[1], swapped.LeafProofs[2] = swapped.LeafProofs[2], swapped.LeafProofs[1]
	require.Error(t, run(&swapped), "witnesses out of leaf order")

	early, _, _, err := b.Envelope(kids[0], BaseTime+5)
	require.NoError(t, err)
	require.ErrorIs(t, run(early), ErrIRTime, "a seal earlier than the lineage's reference times")
}

// The justification body: exactly [token, [one proof]], nothing else.
func TestDecodeSplitJustificationShapes(t *testing.T) {
	_, b := newLineage(t)
	_, kids := tokenWithSplit(t, b, nil)
	good := kids[0].H.Mint.Justification
	sj, err := DecodeSplitJustification(good)
	require.NoError(t, err)
	require.Equal(t, good, SplitJustificationBytes(sj.Token, sj.Proof), "re-encoding reproduces the input")

	tok := sj.Token
	p := sj.Proof.Bytes()
	for name, tc := range map[string]struct {
		in   []byte
		want error
	}{
		"two proofs":        {CTag(TagSplitJustification, CArr(tok, CArr(p, p))), ErrSplitProofCount},
		"no proof":          {CTag(TagSplitJustification, CArr(tok, CArr())), ErrSplitProofCount},
		"token not inline":  {CTag(TagSplitJustification, CArr(CBytes(tok), CArr(p))), ErrSplitJustif},
		"extra slot":        {CTag(TagSplitJustification, CArr(tok, CArr(p), CUint(0))), ErrSplitJustif},
		"another tag":       {CTag(39045, CArr(tok, CArr(p))), ErrSplitJustif},
		"trailing bytes":    {append(append([]byte{}, good...), 0), ErrSplitJustif},
		"proof list absent": {CTag(TagSplitJustification, CArr(tok, p[:0:0])), ErrSplitJustif},
	} {
		_, err := DecodeSplitJustification(tc.in)
		require.ErrorIs(t, err, tc.want, name)
	}
}

// Verify refuses what the codec would: it never trusts its caller to have decoded.
func TestSumProofVerifyRejects(t *testing.T) {
	k1, k2 := H([]byte("k1")), H([]byte("k2"))
	d := H([]byte("d"))
	tree, err := BuildSumTree([]SumLeaf{{k1, d, big.NewInt(3)}, {k2, d, big.NewInt(4)}})
	require.NoError(t, err)
	p, _ := tree.Proof(k1)
	_, ok := p.Verify(k1, d, big.NewInt(3), tree.Root())
	require.True(t, ok)
	_, ok = (append(SumProof{}, p[0], p[0])).Verify(k1, d, big.NewInt(3), tree.Root())
	require.False(t, ok, "equal depths")
	q := append(SumProof{}, p...)
	q[0].Sum = new(big.Int)
	_, ok = q.Verify(k1, d, big.NewInt(3), tree.Root())
	require.False(t, ok, "zero sibling sum")
	_, ok = p.Verify(k1, d, new(big.Int), tree.Root())
	require.False(t, ok, "zero leaf amount")
	over := make(SumProof, MaxSumProofSteps+1)
	_, ok = over.Verify(k1, d, big.NewInt(3), tree.Root())
	require.False(t, ok, "more than 256 steps")
	max := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	big2, err := BuildSumTree([]SumLeaf{{k1, d, big.NewInt(1)}, {k2, d, big.NewInt(2)}})
	require.NoError(t, err)
	r, _ := big2.Proof(k1)
	r[0].Sum = max
	_, ok = r.Verify(k1, d, big.NewInt(1), big2.Root())
	require.False(t, ok, "sum overflow")
}
