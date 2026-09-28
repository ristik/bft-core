package registryproof

import (
	"bytes"
	"errors"
	"math/big"
	"strconv"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/stretchr/testify/require"
	bfttypes "github.com/unicitynetwork/bft-go-base/types"
)

// TestSlotKeysMatchTheIndependentVector compares the keys with the vector printed by the #153 model
// (docs/design/models/f4aregistry TestSlotKeys) and pinned in the contract's tests.
func TestSlotKeysMatchTheIndependentVector(t *testing.T) {
	want := [FieldCount]string{
		"79b704796b8c2ee2cf835e5113e27bbaf138c9831ce0b1cc259966898323094a",
		"1dc271a4e4328f3a46506e6e6e1db1488418d59ca41e005534ed0eda129e6150",
		"abe1d0722ec7cab6bc8be8343a4900e571bdb46fad619947267449a2b9aa7497",
		"7671d07e8accfd833bdccd596ad3a1c4a402a090b727f511a073a2498c590ae5",
		"e77628dabc86b477c0db337bda981ad320031675934be9c596d69ebbc20f1a24",
		"c3adc23527bab9702dd784bd0b145d2ab1a7dce35235a0db3dbfd3da7a53143d",
		"1dfe98fa5011e0dbfdfc5efa804744e3497514271b58499de63781a9941c9a51",
		"459cf503c328e501962bcf0cd8ca53327ab531deeb9155c48d827d2478932c6c",
		"8af142b0300add3b2aec220298bb445eb0c9884bb45fcd5059be6fcd18e7090d",
		"bee6419aa5a12f10d4794669dbd882527b590089e967b14012543a23e0b78e72",
		"e58f62addabf9360d9fcddf3db70a93d2b2ba476996540ecefbbed5ee3cc9c80",
		"14386166497930a3efb28f5976da18bcbf7bec69c7b2c449c3ce32552f037844",
		"a0cbe06c0b5a76b8d67341bd1bd8f162e5d5c6aea162604a10cec0dce4e0d060",
		"47a3f86feb14af4a7e5a1a1fb3362c95b32dfbf03a7a3ca31717f8e829382b3c",
		"e39f0827feecb5f38ffbd452e7c3556ecd0ba586a94434c3f5a10f846cbbfcea",
		"1b118c38b50e4765caa320a933997b81ec1218283e0c260e18a4609340314deb",
		"80ce058bdccaa08590781edd25c9005041ebaba94b6a8941896d46eb60394931",
		"2d5c30492e4b770265db26c3b2d89794cb0435f97f91a351ae818c18236222a7",
		"a6dfb02f4e0457f6dc0ca8f4fd82b31c4a0df5261e0214610377f2af855a5ee5",
		"435c00c3e0bb551759ef849ef59de7b0a62c300b5c1aa3011d4363b09ddef85a",
		"9071048d24ef915056944fc390854c5afc82c7b780af60912f32c98b8a009850",
		"902fa8def05f8c67caa8c59344f53ee4ebbc428d5073e5fbf37e23543232cae5",
		"f64ae08ca348865e7c42acf81d3a418af899eeafa1c21504ea348c15d212c4b8",
		"dedd17782b4935024a9ff293bbd39d406d127447bf3b1d6ed496032fa0cd58e5",
		"a17f343c4f400f901a88319ee38011c1770dfd251fb8f2afb0e66b3ac0e3d1a5",
		"ecd1c378aba52fc330dbbc613de4db55413282426cdedf09fd6ed57a76bc90b5",
		"f4f5ae5954831b1d1559d70dc2cabdc751ef64cc34ab0750efbd97479665f06a",
		"af0d5400378db3d13018c5af67f324d41d95126cd3f97f3e3b4ac05ba9afdaeb",
	}
	for i := range SlotNames {
		require.Equal(t, common.HexToHash(want[i]), SlotKey(i), SlotNames[i])
	}
	require.Equal(t, common.HexToAddress("0xff00000000000000000000000000000000000002"), RegistryAddress)
}

func TestGenesisProofDecodes(t *testing.T) {
	c := newChain(t)
	s, err := Verify(c.context(), c.genesis.hash, c.genesis.ev)
	require.NoError(t, err)
	require.True(t, s.Fields().Genesis)
	require.Equal(t, uint64(0), s.Fields().Number)
	require.Equal(t, c.genesis.stateRoot, s.Fields().StateRoot)
	require.Equal(t, uint64(1), s.Fields().LayoutVersion)
	require.Equal(t, genesisCommitment, s.Fields().GenesisCommitment)
	require.Equal(t, fullShardConfHash, s.Fields().ShardConfHash)
	require.Equal(t, uint64(1), s.Fields().RootEpoch)
	require.Equal(t, uint64(2), s.Fields().Phase)
	require.Equal(t, uint64(0), s.LastAppliedRootRound(), "§9.1: the zero cursor, authoritative because steps 2 and 5 passed")
	require.Equal(t, uint64(0), s.Fields().RoundAuthorized)
}

func TestVerifiedTransitionStorageRequiresEveryBoundField(t *testing.T) {
	c := newChain(t)
	base := executed(1, 5, 0, "S0", "")
	fields := []string{"transition.bodyID", "transition.genesisID", "transition.frozenID", "transition.commitID", "transition.frozenParent", "transition.successorTR"}
	installed := base.with("assignment.rootEpoch", num(2), "transition.cursor", num(1))
	for _, name := range fields {
		installed = installed.with(name, named(name))
	}
	valid := build(t, spec{number: 1, parent: c.genesis.hash, words: installed, fillers: fillers})
	s, err := Verify(c.context(), valid.hash, valid.ev)
	require.NoError(t, err)
	require.Equal(t, uint64(2), s.Fields().RootEpoch)
	require.Equal(t, uint64(1), s.Fields().TransitionCursor)

	for _, name := range fields {
		t.Run("missing "+name, func(t *testing.T) {
			b := build(t, spec{number: 1, parent: c.genesis.hash, words: installed.with(name, common.Hash{}), fillers: fillers})
			_, err := Verify(c.context(), b.hash, b.ev)
			require.ErrorIs(t, err, ErrConfiguration)
		})
		t.Run("unexpected "+name, func(t *testing.T) {
			b := build(t, spec{number: 1, parent: c.genesis.hash, words: base.with(name, named(name)), fillers: fillers})
			_, err := Verify(c.context(), b.hash, b.ev)
			require.ErrorIs(t, err, ErrConfiguration)
		})
	}
	for name, changed := range map[string]words{
		"wrong successor epoch": installed.with("assignment.rootEpoch", num(3)),
		"wrong old epoch":       base.with("assignment.rootEpoch", num(2)),
		"unexpected inbox":      base.with("inbox.consumed", num(1)),
		"multiple transitions":  installed.with("transition.cursor", num(2)),
	} {
		t.Run(name, func(t *testing.T) {
			b := build(t, spec{number: 1, parent: c.genesis.hash, words: changed, fillers: fillers})
			_, err := Verify(c.context(), b.hash, b.ev)
			require.ErrorIs(t, err, ErrConfiguration)
		})
	}
	overflow := build(t, spec{number: 1, parent: c.genesis.hash,
		words: installed.with("assignment.rootEpoch", num(0)), fillers: fillers})
	ctx := c.context()
	ctx.RootEpoch = ^uint64(0)
	_, err = Verify(ctx, overflow.hash, overflow.ev)
	require.ErrorIs(t, err, ErrConfiguration)
}

func TestExecutedBlocksDecode(t *testing.T) {
	c := newChain(t)
	for _, tc := range []struct {
		name                      string
		b                         block
		clock, round, certified   uint64
		stateHash, blockHash      string
		input, outcomesCommitment string
	}{
		{"§9.2 round 1", c.b1, 5, 1, 0, "S0", "", "X1", "R1"},
		{"§9.3 round 2", c.b2, 6, 2, 1, "S1", "B1", "X2", "R2"},
		{"§9.4 round 4 after a repeat", c.b3, 9, 4, 2, "S2", "B2", "X4", "R4"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := Verify(c.context(), tc.b.hash, tc.b.ev)
			require.NoError(t, err)
			require.False(t, s.Fields().Genesis)
			require.Equal(t, tc.b.number, s.Fields().Number)
			require.Equal(t, tc.b.hash, s.Fields().ParentHash)
			require.Equal(t, tc.clock, s.LastAppliedRootRound())
			require.Equal(t, tc.round, s.Fields().RoundAuthorized)
			require.Equal(t, tc.round, s.Fields().OutcomesRound)
			require.Equal(t, tc.certified, s.Fields().CertifiedRound)
			require.Equal(t, named(tc.stateHash), s.Fields().CertifiedStateHash)
			require.Equal(t, named(tc.input), s.Fields().InputCommitment)
			require.Equal(t, named(tc.outcomesCommitment), s.Fields().OutcomesCommitment)
			require.Equal(t, 1_700_000_000+tc.clock, s.Fields().OriginTimestamp)
			require.Equal(t, named("U"+uitoa(tc.clock)), s.Fields().OriginTreeRoot)
			if tc.blockHash == "" {
				require.False(t, s.Fields().HasBlockHash)
				require.Equal(t, common.Hash{}, s.Fields().CertifiedBlockHash)
			} else {
				require.True(t, s.Fields().HasBlockHash)
				require.Equal(t, named(tc.blockHash), s.Fields().CertifiedBlockHash)
			}
		})
	}
}

func uitoa(n uint64) string { return strconv.FormatUint(n, 10) }

// §13 item 8 and §8.1: replaying round 2 (block 2) reads the registry at its parent, block 1, not at the
// current head. The head's evidence cannot stand in for the parent's.
func TestHistoricalParentReplayReadsThatParent(t *testing.T) {
	c := newChain(t)
	s, err := Verify(c.context(), c.b1.hash, c.b1.ev)
	require.NoError(t, err)
	require.Equal(t, uint64(5), s.LastAppliedRootRound())

	head, err := Verify(c.context(), c.b3.hash, c.b3.ev)
	require.NoError(t, err)
	require.Equal(t, uint64(9), head.LastAppliedRootRound(), "premise: the head has moved on")

	_, err = Verify(c.context(), c.b1.hash, c.b3.ev)
	require.ErrorIs(t, err, ErrHeaderHash, "§13 item 7: the executor head's evidence is not the certified parent's")
}

func TestRefusalsFromOneElementChanges(t *testing.T) {
	c := newChain(t)
	ctx := c.context()
	_, err := Verify(ctx, c.b2.hash, c.b2.ev)
	require.NoError(t, err, "premise: the unmodified evidence verifies")

	b2 := func() Evidence { return cloneEvidence(c.b2.ev) }

	cases := map[string]struct {
		parent common.Hash
		ev     Evidence
		want   error
	}{
		"a header byte changed":                   {c.b2.hash, func() Evidence { e := b2(); e.Header[len(e.Header)-40] ^= 1; return e }(), ErrHeaderHash},
		"another block's valid header and proofs": {c.b2.hash, cloneEvidence(c.b1.ev), ErrHeaderHash},
		"account proof missing its last node":     {c.b2.hash, func() Evidence { e := b2(); e.AccountProof = e.AccountProof[:len(e.AccountProof)-1]; return e }(), ErrAccountProof},
		"account proof missing its root node":     {c.b2.hash, func() Evidence { e := b2(); e.AccountProof = e.AccountProof[1:]; return e }(), ErrAccountProof},
		"account proof node byte changed":         {c.b2.hash, func() Evidence { e := b2(); n := e.AccountProof[len(e.AccountProof)-1]; n[len(n)-1] ^= 1; return e }(), ErrAccountProof},
		"account proof empty":                     {c.b2.hash, func() Evidence { e := b2(); e.AccountProof = nil; return e }(), ErrAccountProof},
		"storage proof missing its last node": {c.b2.hash, func() Evidence {
			e := b2()
			p := e.StorageProofs[fClockRootRound]
			e.StorageProofs[fClockRootRound] = p[:len(p)-1]
			return e
		}(), ErrStorageProof},
		"storage proof node byte changed": {c.b2.hash, func() Evidence {
			e := b2()
			p := e.StorageProofs[fRoundAuthorized]
			p[len(p)-1][len(p[len(p)-1])-1] ^= 1
			return e
		}(), ErrStorageProof},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Verify(ctx, tc.parent, tc.ev)
			require.ErrorIs(t, err, tc.want)
		})
	}
}

// A storage proof for another key cannot supply a field: the path for the wanted key is walked, and the
// nodes supplied for a different key either do not reach it or prove it absent.
func TestStorageProofForAnotherKey(t *testing.T) {
	c := newChain(t)
	e := cloneEvidence(c.b2.ev)
	e.StorageProofs[fClockRootRound] = cloneNodes(c.b2.ev.StorageProofs[fOriginTimestamp])
	_, err := Verify(c.context(), c.b2.hash, e)
	require.Error(t, err, "block 2 has clock 6; another key's nodes cannot supply it")
	require.True(t, errors.Is(err, ErrStorageProof) || errors.Is(err, ErrNotFinalized), "got %v", err)
}

func TestSummaryFieldsAreNotEvidence(t *testing.T) {
	c := newChain(t)
	r := getProofResult(c.b2)
	// The response's own claims, which a JSON body would also carry, are absent from GetProofResult by
	// construction. Swapping in the proofs of block 3 while keeping block 2's header shows only nodes decide.
	ev, err := EvidenceFromGetProof(c.b2.ev.Header, r)
	require.NoError(t, err)
	s, err := Verify(c.context(), c.b2.hash, ev)
	require.NoError(t, err)
	require.Equal(t, uint64(6), s.LastAppliedRootRound())

	mixed := getProofResult(c.b3)
	ev, err = EvidenceFromGetProof(c.b2.ev.Header, mixed)
	require.NoError(t, err)
	_, err = Verify(c.context(), c.b2.hash, ev)
	require.ErrorIs(t, err, ErrAccountProof, "block 3's account proof does not verify against block 2's state root")
}

func getProofResult(b block) GetProofResult {
	r := GetProofResult{Address: RegistryAddress}
	for _, n := range b.ev.AccountProof {
		r.AccountProof = append(r.AccountProof, common.CopyBytes(n))
	}
	// Reversed order: position is not identity, the key is.
	for i := FieldCount - 1; i >= 0; i-- {
		sp := StorageProofResult{Key: SlotKey(i).Hex()}
		for _, n := range b.ev.StorageProofs[i] {
			sp.Proof = append(sp.Proof, common.CopyBytes(n))
		}
		r.StorageProof = append(r.StorageProof, sp)
	}
	return r
}

func TestEvidenceFromGetProofRefusals(t *testing.T) {
	c := newChain(t)
	for name, tc := range map[string]struct {
		change func(*GetProofResult)
		want   error
	}{
		"another address":         {func(r *GetProofResult) { r.Address = common.HexToAddress("0xff01") }, ErrAccountProof},
		"a storage proof missing": {func(r *GetProofResult) { r.StorageProof = r.StorageProof[1:] }, ErrStorageProof},
		"an extra storage proof":  {func(r *GetProofResult) { r.StorageProof = append(r.StorageProof, r.StorageProof[0]) }, ErrStorageProof},
		"a duplicate key":         {func(r *GetProofResult) { r.StorageProof[1].Key = r.StorageProof[0].Key }, ErrStorageProof},
		"an unexpected key":       {func(r *GetProofResult) { r.StorageProof[0].Key = named("other").Hex() }, ErrStorageProof},
		"a key without 0x":        {func(r *GetProofResult) { r.StorageProof[0].Key = r.StorageProof[0].Key[2:] }, ErrStorageProof},
		// A leading zero byte keeps the key's value, so only the length bound refuses it.
		"a key longer than 32 bytes": {func(r *GetProofResult) { r.StorageProof[0].Key = "0x00" + r.StorageProof[0].Key[2:] }, ErrStorageProof},
	} {
		t.Run(name, func(t *testing.T) {
			r := getProofResult(c.b2)
			tc.change(&r)
			_, err := EvidenceFromGetProof(c.b2.ev.Header, r)
			require.ErrorIs(t, err, tc.want)
		})
	}
	t.Run("a quantity-form key is the same key", func(t *testing.T) {
		r := getProofResult(c.b2)
		r.StorageProof[0].Key = "0x" + stripZeros(r.StorageProof[0].Key[2:])
		_, err := EvidenceFromGetProof(c.b2.ev.Header, r)
		require.NoError(t, err)
	})
}

func stripZeros(s string) string {
	for len(s) > 1 && s[0] == '0' {
		s = s[1:]
	}
	return s
}

func TestHeaderShape(t *testing.T) {
	for name, tc := range map[string]struct {
		change func(*types.Header)
		want   error
	}{
		"parent beacon root missing (pre-Cancun)": {func(h *types.Header) { h.ParentBeaconRoot = nil }, ErrHeaderShape},
		"blob gas fields missing":                 {func(h *types.Header) { h.ParentBeaconRoot, h.BlobGasUsed, h.ExcessBlobGas = nil, nil, nil }, ErrHeaderShape},
		"no post-London fields": {func(h *types.Header) {
			h.ParentBeaconRoot, h.BlobGasUsed, h.ExcessBlobGas, h.WithdrawalsHash, h.BaseFee = nil, nil, nil, nil, nil
		}, ErrHeaderShape},
		"requests hash present (Prague)": {func(h *types.Header) { r := common.Hash{1}; h.RequestsHash = &r }, ErrHeaderShape},
	} {
		t.Run(name, func(t *testing.T) {
			c := newChain(t)
			b := build(t, spec{number: 1, parent: c.genesis.hash, words: executed(1, 5, 0, "S0", ""), fillers: fillers, header: tc.change})
			_, err := Verify(c.context(), b.hash, b.ev)
			require.ErrorIs(t, err, tc.want, "the header hashes correctly; only its shape is refused")
		})
	}

	t.Run("non-canonical RLP of a valid header", func(t *testing.T) {
		c := newChain(t)
		enc := nonCanonicalList(c.b1.ev.Header)
		require.NotEqual(t, c.b1.ev.Header, enc)
		var h types.Header
		require.NoError(t, rlp.DecodeBytes(c.b1.ev.Header, &h), "premise")
		e := cloneEvidence(c.b1.ev)
		e.Header = enc
		_, err := Verify(c.context(), crypto.Keccak256Hash(enc), e)
		require.ErrorIs(t, err, ErrHeaderShape)
	})

	t.Run("trailing bytes after the header list", func(t *testing.T) {
		c := newChain(t)
		e := cloneEvidence(c.b1.ev)
		e.Header = append(e.Header, 0x80)
		_, err := Verify(c.context(), crypto.Keccak256Hash(e.Header), e)
		require.ErrorIs(t, err, ErrHeaderShape)
	})
}

// nonCanonicalList re-encodes an RLP list header with one more length byte than needed.
func nonCanonicalList(enc []byte) []byte {
	lenOfLen := int(enc[0] - 0xf7)
	payload := enc[1+lenOfLen:]
	lenBytes := append([]byte{0}, enc[1:1+lenOfLen]...)
	return append(append([]byte{0xf7 + byte(len(lenBytes))}, lenBytes...), payload...)
}

func TestCodeHashAndAccountAbsence(t *testing.T) {
	c := newChain(t)
	other := crypto.Keccak256Hash([]byte{0x00})
	for name, s := range map[string]spec{
		"another code hash":        {number: 1, parent: c.genesis.hash, words: executed(1, 5, 0, "S0", ""), fillers: fillers, codeHash: &other},
		"no account at a_sr":       {number: 1, parent: c.genesis.hash, fillers: fillers, absent: true},
		"an empty account at a_sr": {number: 1, parent: c.genesis.hash, fillers: fillers, codeHash: &types.EmptyCodeHash},
	} {
		t.Run(name, func(t *testing.T) {
			b := build(t, s)
			_, err := Verify(c.context(), b.hash, b.ev)
			require.ErrorIs(t, err, ErrCodeHash)
		})
	}
}

func TestStorageValueDecoding(t *testing.T) {
	c := newChain(t)
	base := executed(2, 6, 1, "S1", "B1")
	for name, tc := range map[string]struct {
		raw   map[string][]byte
		words words
		want  error
	}{
		"leading zero byte":           {raw: map[string][]byte{"clock.rootRound": {0x82, 0x00, 0x06}}, want: ErrValue},
		"single byte in long form":    {raw: map[string][]byte{"clock.rootRound": {0x81, 0x06}}, want: ErrValue},
		"33 bytes":                    {raw: map[string][]byte{"origin.treeRoot": append([]byte{0xa1}, bytes.Repeat([]byte{1}, 33)...)}, want: ErrValue},
		"an RLP list":                 {raw: map[string][]byte{"clock.rootRound": {0xc1, 0x06}}, want: ErrValue},
		"an empty string":             {raw: map[string][]byte{"clock.rootRound": {0x80}}, want: ErrValue},
		"trailing bytes":              {raw: map[string][]byte{"clock.rootRound": {0x06, 0x06}}, want: ErrValue},
		"scalar wider than uint64":    {words: base.with("round.authorized", common.BigToHash(new(big.Int).Lsh(big.NewInt(1), 64))), want: ErrValue},
		"hasBlockHash is 2":           {words: base.with("certified.hasBlockHash", num(2)), want: ErrValue},
		"null block hash not zero":    {words: base.with("certified.hasBlockHash", common.Hash{}), want: ErrValue},
		"phase 3":                     {words: base.with("phase", num(3)), want: ErrValue},
		"layout version 2":            {words: base.with("layoutVersion", num(2)), want: ErrConfiguration},
		"layout version absent":       {words: base.with("layoutVersion", common.Hash{}), want: ErrNotInitialized},
		"genesis commitment absent":   {words: base.with("genesisCommitment", common.Hash{}), want: ErrNotInitialized},
		"another genesis commitment":  {words: base.with("genesisCommitment", named("G'")), want: ErrConfiguration},
		"another configuration":       {words: base.with("config.shardConfHash", named("C'")), want: ErrConfiguration},
		"another shard epoch":         {words: base.with("assignment.epoch", num(1)), want: ErrConfiguration},
		"another root epoch":          {words: base.with("assignment.rootEpoch", num(2)), want: ErrConfiguration},
		"transition cursor advanced":  {words: base.with("transition.cursor", num(1)), want: ErrConfiguration},
		"inbox watermark advanced":    {words: base.with("inbox.consumed", num(1)), want: ErrConfiguration},
		"phase open":                  {words: base.with("phase", num(1)), want: ErrNotFinalized},
		"phase absent":                {words: base.with("phase", common.Hash{}), want: ErrValue},
		"outcomes for another round":  {words: base.with("outcomes.round", num(1)), want: ErrNotFinalized},
		"outcomes commitment missing": {words: base.with("outcomes.commitment", common.Hash{}), want: ErrNotFinalized},
		"nothing at all":              {words: words{}, want: ErrNotInitialized},
	} {
		t.Run(name, func(t *testing.T) {
			w := tc.words
			if w == nil {
				w = base
			}
			b := build(t, spec{number: 2, parent: c.b1.hash, words: w, raw: tc.raw, fillers: fillers})
			_, err := Verify(c.context(), b.hash, b.ev)
			require.ErrorIs(t, err, tc.want)
		})
	}
}

func TestGenesisStorageRules(t *testing.T) {
	c := newChain(t)
	ctx := c.context()

	t.Run("a genesis-hash block with an executed field is refused", func(t *testing.T) {
		g := build(t, spec{number: 0, words: genesisWords().with("clock.rootRound", num(1)), fillers: fillers})
		ctx := ctx
		ctx.EVMGenesisHash = g.hash
		_, err := Verify(ctx, g.hash, g.ev)
		require.ErrorIs(t, err, ErrConfiguration)
	})
	t.Run("the configured genesis must be block 0", func(t *testing.T) {
		// The storage is exactly §5.4, so only the block number is wrong.
		notZero := build(t, spec{number: 1, parent: c.genesis.hash, words: genesisWords(), fillers: fillers})
		ctx := ctx
		ctx.EVMGenesisHash = notZero.hash
		_, err := Verify(ctx, notZero.hash, notZero.ev)
		require.ErrorIs(t, err, ErrConfiguration)
		require.ErrorContains(t, err, "has number 1")
	})
	t.Run("another block 0 is not the configured genesis", func(t *testing.T) {
		other := build(t, spec{number: 0, words: genesisWords(), fillers: fillers + 1})
		_, err := Verify(ctx, other.hash, other.ev)
		require.ErrorIs(t, err, ErrConfiguration)
	})
	t.Run("genesis storage is not refused for lacking outcomes", func(t *testing.T) {
		_, err := Verify(ctx, c.genesis.hash, c.genesis.ev)
		require.NoError(t, err)
	})
}

func TestContextRefusals(t *testing.T) {
	c := newChain(t)
	for name, change := range map[string]func(*Context){
		"another registry address": func(x *Context) {
			x.RegistryAddress = common.HexToAddress("0xff00000000000000000000000000000000000003")
		},
		"zero code hash":          func(x *Context) { x.RegistryCodeHash = common.Hash{} },
		"zero genesis commitment": func(x *Context) { x.GenesisCommitment = common.Hash{} },
		"zero configuration hash": func(x *Context) { x.FullShardConfHash = common.Hash{} },
		"zero EVM genesis hash":   func(x *Context) { x.EVMGenesisHash = common.Hash{} },
	} {
		t.Run(name, func(t *testing.T) {
			ctx := c.context()
			change(&ctx)
			_, err := Verify(ctx, c.b2.hash, c.b2.ev)
			require.ErrorIs(t, err, ErrContext)
		})
	}
	t.Run("zero parent hash", func(t *testing.T) {
		_, err := Verify(c.context(), common.Hash{}, c.b2.ev)
		require.ErrorIs(t, err, ErrContext)
	})
	t.Run("a correct proof under another configured code hash", func(t *testing.T) {
		ctx := c.context()
		ctx.RegistryCodeHash = named("another deployment")
		_, err := Verify(ctx, c.b2.hash, c.b2.ev)
		require.ErrorIs(t, err, ErrCodeHash)
	})
}

func TestUnavailableIsNotInvalid(t *testing.T) {
	c := newChain(t)
	_, err := Verify(c.context(), c.b2.hash, Evidence{})
	require.ErrorIs(t, err, ErrUnavailable)
	require.False(t, errors.Is(err, ErrBounds) || errors.Is(err, ErrHeaderHash))

	for name, ev := range map[string]Evidence{
		"header only":        {Header: c.b2.ev.Header},
		"proofs only":        {AccountProof: c.b2.ev.AccountProof, StorageProofs: c.b2.ev.StorageProofs},
		"empty storage list": {Header: c.b2.ev.Header, AccountProof: c.b2.ev.AccountProof, StorageProofs: [][][]byte{}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Verify(c.context(), c.b2.hash, ev)
			require.Error(t, err)
			require.NotErrorIs(t, err, ErrUnavailable, "partial evidence is invalid evidence, not missing evidence")
		})
	}
}

// Each bound is enforced from lengths alone. The oversized input is otherwise junk, so reaching any later
// step would produce a different error.
func TestBoundsBeforeVerification(t *testing.T) {
	c := newChain(t)
	junk := func(n int) []byte { return bytes.Repeat([]byte{0xff}, n) }
	l := defaultLimits
	for name, tc := range map[string]func(e *Evidence){
		"header too large":              func(e *Evidence) { e.Header = junk(l.headerBytes + 1) },
		"21 storage proofs":             func(e *Evidence) { e.Header = junk(10); e.StorageProofs = e.StorageProofs[:21] },
		"23 storage proofs":             func(e *Evidence) { e.Header = junk(10); e.StorageProofs = append(e.StorageProofs, nil) },
		"too many account proof nodes":  func(e *Evidence) { e.Header = junk(10); e.AccountProof = make([][]byte, l.nodesPerProof+1) },
		"too many storage proof nodes":  func(e *Evidence) { e.Header = junk(10); e.StorageProofs[21] = make([][]byte, l.nodesPerProof+1) },
		"an account proof node too big": func(e *Evidence) { e.Header = junk(10); e.AccountProof = [][]byte{junk(l.nodeBytes + 1)} },
		"a storage proof node too big":  func(e *Evidence) { e.Header = junk(10); e.StorageProofs[3] = [][]byte{junk(l.nodeBytes + 1)} },
		"total size": func(e *Evidence) {
			e.Header = junk(10)
			for i := range e.StorageProofs {
				e.StorageProofs[i] = [][]byte{junk(l.nodeBytes), junk(l.nodeBytes), junk(l.nodeBytes), junk(l.nodeBytes), junk(l.nodeBytes), junk(l.nodeBytes), junk(l.nodeBytes), junk(l.nodeBytes), junk(l.nodeBytes), junk(l.nodeBytes), junk(l.nodeBytes), junk(l.nodeBytes)}
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := cloneEvidence(c.b2.ev)
			tc(&e)
			_, err := Verify(c.context(), c.b2.hash, e)
			require.ErrorIs(t, err, ErrBounds)
		})
	}

	t.Run("a well-formed proof fits with margin", func(t *testing.T) {
		total, maxNodes, maxNode := len(c.b3.ev.Header), len(c.b3.ev.AccountProof), 0
		for _, p := range append([][][]byte{c.b3.ev.AccountProof}, c.b3.ev.StorageProofs...) {
			maxNodes = max(maxNodes, len(p))
			for _, n := range p {
				total += len(n)
				maxNode = max(maxNode, len(n))
			}
		}
		t.Logf("fixture evidence: %d bytes total, longest path %d nodes, largest node %d bytes", total, maxNodes, maxNode)
		require.Less(t, total*8, l.totalBytes)
		require.LessOrEqual(t, maxNode, 532, "a branch node of a hashed-key trie is at most 532 bytes")
	})
}

func TestOutputsDoNotAliasInputs(t *testing.T) {
	c := newChain(t)
	e := cloneEvidence(c.b2.ev)
	s1, err := Verify(c.context(), c.b2.hash, e)
	require.NoError(t, err)
	for i := range e.Header {
		e.Header[i] = 0
	}
	for _, p := range append([][][]byte{e.AccountProof}, e.StorageProofs...) {
		for _, n := range p {
			for i := range n {
				n[i] = 0
			}
		}
	}
	require.Equal(t, uint64(6), s1.LastAppliedRootRound())
	require.Equal(t, c.b2.stateRoot, s1.Fields().StateRoot)
	require.Equal(t, named("B1"), s1.Fields().CertifiedBlockHash)
}

// §7.3 E1 to E4 over verified snapshots, including the §9.2a initial-timeout case.
func TestGenesisParentEligibility(t *testing.T) {
	c := newChain(t)
	s0 := named("S0").Bytes()
	genesis, err := Verify(c.context(), c.genesis.hash, c.genesis.ev)
	require.NoError(t, err)
	b1, err := Verify(c.context(), c.b1.hash, c.b1.ev)
	require.NoError(t, err)

	installed := &bfttypes.InputRecord{RoundNumber: 0, PreviousHash: s0, Hash: s0}
	for name, n := range map[string]uint64{"first payload round 1": 1, "§9.2a after one initial timeout, round 2": 2, "after three timeouts, round 4": 4} {
		t.Run(name, func(t *testing.T) {
			require.NoError(t, GenesisParentEligible(n, installed, s0, genesis))
		})
	}
	t.Run("quiet certified round at the genesis state", func(t *testing.T) {
		quiet := &bfttypes.InputRecord{RoundNumber: 1, PreviousHash: s0, Hash: s0}
		require.NoError(t, GenesisParentEligible(2, quiet, s0, genesis))
	})

	s1, b1hash := named("S1").Bytes(), named("B1").Bytes()
	for name, tc := range map[string]struct {
		n      uint64
		ir     *bfttypes.InputRecord
		parent Snapshot
		want   error
	}{
		"E1 round 0":                         {0, installed, genesis, ErrGenesisInstallation},
		"E2 no certificate":                  {2, nil, genesis, ErrNotGenesisHistory},
		"E2 certificate names a block":       {2, &bfttypes.InputRecord{RoundNumber: 1, PreviousHash: s0, Hash: s1, BlockHash: b1hash}, genesis, ErrNotGenesisHistory},
		"E2 block hash at the genesis state": {2, &bfttypes.InputRecord{RoundNumber: 1, PreviousHash: s0, Hash: s0, BlockHash: b1hash}, genesis, ErrNotGenesisHistory},
		"E2 certified round not below":       {2, &bfttypes.InputRecord{RoundNumber: 2, PreviousHash: s0, Hash: s0}, genesis, ErrNotGenesisHistory},
		"E2 previous state is not genesis":   {3, &bfttypes.InputRecord{RoundNumber: 2, PreviousHash: s1, Hash: s0}, genesis, ErrNotGenesisHistory},
		"E3 parent is block 1":               {2, installed, b1, ErrParentNotGenesis},
		"E3 snapshot not produced by Verify": {2, installed, Snapshot{}, ErrParentNotGenesis},
	} {
		t.Run(name, func(t *testing.T) {
			require.ErrorIs(t, GenesisParentEligible(tc.n, tc.ir, s0, tc.parent), tc.want)
		})
	}

	// The records below cannot come from Verify, which refuses executed fields at the genesis hash and a
	// genesis flag at any other hash. They exercise the eligibility checks as a second layer, by building
	// the unexported record directly, which only code inside this package can do.
	withRecord := func(change func(*record)) Snapshot {
		r := *genesis.r
		change(&r)
		return Snapshot{r: &r}
	}
	t.Run("E3 a record flagged genesis for another parent hash", func(t *testing.T) {
		s := withRecord(func(r *record) { r.f.ParentHash = c.b1.hash })
		require.ErrorIs(t, GenesisParentEligible(2, installed, s0, s), ErrParentNotGenesis)
	})
	t.Run("E3 a record at the genesis hash not flagged genesis", func(t *testing.T) {
		s := withRecord(func(r *record) { r.f.Genesis = false })
		require.ErrorIs(t, GenesisParentEligible(2, installed, s0, s), ErrParentNotGenesis)
	})
	t.Run("E3 a record flagged genesis at a non-zero number", func(t *testing.T) {
		s := withRecord(func(r *record) { r.f.Number = 1 })
		require.ErrorIs(t, GenesisParentEligible(2, installed, s0, s), ErrParentNotGenesis)
	})
	t.Run("E4 a genesis record that executed a round", func(t *testing.T) {
		s := withRecord(func(r *record) { r.f.RoundAuthorized = 1 })
		require.ErrorIs(t, GenesisParentEligible(2, installed, s0, s), ErrRegistryNotAtGenesis)
		s = withRecord(func(r *record) { r.f.CertifiedRound = 1 })
		require.ErrorIs(t, GenesisParentEligible(2, installed, s0, s), ErrRegistryNotAtGenesis)
	})
	t.Run("premise: the unchanged record is eligible and was not changed by the copies", func(t *testing.T) {
		require.NoError(t, GenesisParentEligible(2, installed, s0, withRecord(func(*record) {})))
		require.NoError(t, GenesisParentEligible(2, installed, s0, genesis))
	})
}
