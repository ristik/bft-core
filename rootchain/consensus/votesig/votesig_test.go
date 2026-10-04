package votesig_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
)

// The expected bytes below were produced by an independent encoder (not by this package) from the semantic inputs.
const (
	wantVI  = "8605784a726f6f742d766f74652f3865636132633335316266373764336239343738333035303936336331383633353332333832363763616531646566663566613136333262306539663734373019012c1a000111701a0001116f5820e0e1e2e3e4e5e6e7e8e9eaebecedeeefe0e1e2e3e4e5e6e7e8e9eaebecedeeef"
	wantVH  = "8fa17efc241f8adea5cc371f24e85680ae5696f1963a031cc6351f20b0a733c7"
	wantPV  = "8670554e49434954595f504f535f564f544505784a726f6f742d766f74652f3865636132633335316266373764336239343738333035303936336331383633353332333832363763616531646566663566613136333262306539663734373058208fa17efc241f8adea5cc371f24e85680ae5696f1963a031cc6351f20b0a733c75820c0c1c2c3c4c5c6c7c8c9cacbcccdcecfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf1a0001116e"
	wantPVn = "8670554e49434954595f504f535f564f544505784a726f6f742d766f74652f3865636132633335316266373764336239343738333035303936336331383633353332333832363763616531646566663566613136333262306539663734373058208fa17efc241f8adea5cc371f24e85680ae5696f1963a031cc6351f20b0a733c7f600"
	wantPT  = "8873554e49434954595f504f535f54494d454f555405784d726f6f742d74696d656f75742f3865636132633335316266373764336239343738333035303936336331383633353332333832363763616531646566663566613136333262306539663734373019012c1a000111711a00011170f6666e6f64652d31"
	wantPTa = "8873554e49434954595f504f535f54494d454f555405784d726f6f742d74696d656f75742f3865636132633335316266373764336239343738333035303936336331383633353332333832363763616531646566663566613136333262306539663734373019012d1a000111711a00011170835820a0a1a2a3a4a5a6a7a8a9aaabacadaeafa0a1a2a3a4a5a6a7a8a9aaabacadaeaf19012d1a00011170666e6f64652d31"
)

func testConfig() votesig.Config {
	return votesig.Config{Scheme: votesig.SchemeDomainBound, Network: 5, Genesis: sha256.Sum256([]byte("votesig-test-genesis"))}
}

func seq(base byte) []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = base + byte(i%16)
	}
	return b
}

func testVote() (votesig.VoteInfo, votesig.Commit) {
	vi := votesig.VoteInfo{Epoch: 300, Round: 70000, Parent: 69999}
	copy(vi.Exec[:], seq(0xe0))
	return vi, votesig.Commit{Hash: seq(0xc0), Round: 69998}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

func TestExactBytes(t *testing.T) {
	cfg := testConfig()
	vi, commit := testVote()

	got, err := cfg.VoteInfoBytes(vi)
	require.NoError(t, err)
	require.Equal(t, wantVI, hex.EncodeToString(got))
	vh, err := cfg.VoteInfoHash(vi)
	require.NoError(t, err)
	require.Equal(t, wantVH, hex.EncodeToString(vh[:]))
	require.Equal(t, sha256.Sum256(got), vh)

	pv, err := cfg.VotePreimage(vi, commit)
	require.NoError(t, err)
	require.Equal(t, wantPV, hex.EncodeToString(pv))
	require.Equal(t, byte(0x86), pv[0], "an array of six, the tag is text inside it")

	pvn, err := cfg.VotePreimage(vi, votesig.Commit{})
	require.NoError(t, err)
	require.Equal(t, wantPVn, hex.EncodeToString(pvn), "a non-committing vote: null hash, round 0")

	pt, err := cfg.TimeoutPreimage(votesig.Timeout{Epoch: 300, Round: 70001, HighQcRound: 70000, Author: "node-1"})
	require.NoError(t, err)
	require.Equal(t, wantPT, hex.EncodeToString(pt))
	require.Equal(t, byte(0x88), pt[0])

	var ag [32]byte
	copy(ag[:], seq(0xa0))
	pta, err := cfg.TimeoutPreimage(votesig.Timeout{Epoch: 301, Round: 70001, HighQcRound: 70000, Anchor: &votesig.Anchor{GenesisID: ag, Epoch: 301, Slot: 70000}, Author: "node-1"})
	require.NoError(t, err)
	require.Equal(t, wantPTa, hex.EncodeToString(pta))

	// the strict decoder reads the same structure back
	v, err := votesig.Decode(pv)
	require.NoError(t, err)
	arr := v.([]any)
	require.Equal(t, []any{votesig.VoteTag, uint64(5), cfg.VoteDomain(), vh[:], seq(0xc0), uint64(69998)}, arr)
	require.Equal(t, "root-vote/"+hex.EncodeToString(cfg.Genesis[:]), cfg.VoteDomain())
	require.Equal(t, "root-timeout/"+hex.EncodeToString(cfg.Genesis[:]), cfg.TimeoutDomain())
}

// The D5 model in evmroot is the specification's executable form: for the same inputs the production encoder and the model
// produce the same bytes, with the message domain being Dv.
func TestMatchesTheD5Model(t *testing.T) {
	cfg := testConfig()
	vi, commit := testVote()
	model := evmroot.VoteInfo{Network: cfg.Network, MessageDomain: cfg.VoteDomain(), VotingEpoch: vi.Epoch, VotingRound: vi.Round, ParentRound: vi.Parent, ExecStateHash: vi.Exec[:]}
	want := model.Hash()
	got, err := cfg.VoteInfoHash(vi)
	require.NoError(t, err)
	require.Equal(t, [32]byte(want), got)

	for name, c := range map[string]votesig.Commit{"committing": commit, "non-committing": {}} {
		lci := evmroot.LedgerCommitInfo{VoteInfoHash: want[:], CommitStateHash: c.Hash, CommitRound: c.Round}
		require.True(t, lci.BindsVoteInfo(model))
		pv, err := cfg.VotePreimage(vi, c)
		require.NoError(t, err)
		require.Equal(t, evmroot.SigningPreimage(model, lci), pv, name)
	}
}

func TestStatementValidation(t *testing.T) {
	cfg := testConfig()
	vi, commit := testVote()
	bad := map[string]func() error{
		"zero voting round": func() error { v := vi; v.Round = 0; _, err := cfg.VotePreimage(v, votesig.Commit{}); return err },
		"parent not below":  func() error { v := vi; v.Parent = v.Round; _, err := cfg.VotePreimage(v, votesig.Commit{}); return err },
		"commit hash without round": func() error {
			_, err := cfg.VotePreimage(vi, votesig.Commit{Hash: commit.Hash})
			return err
		},
		"commit round without hash": func() error { _, err := cfg.VotePreimage(vi, votesig.Commit{Round: 5}); return err },
		"short commit hash":         func() error { _, err := cfg.VotePreimage(vi, votesig.Commit{Hash: []byte{1}, Round: 5}); return err },
		"empty (non-nil) commit hash": func() error {
			_, err := cfg.VotePreimage(vi, votesig.Commit{Hash: []byte{}, Round: 0})
			return err
		},
		"commit round not below voting round": func() error {
			_, err := cfg.VotePreimage(vi, votesig.Commit{Hash: commit.Hash, Round: vi.Round})
			return err
		},
		"timeout without author": func() error {
			_, err := cfg.TimeoutPreimage(votesig.Timeout{Epoch: 1, Round: 3, HighQcRound: 2})
			return err
		},
		"timeout round not above the high QC round": func() error {
			_, err := cfg.TimeoutPreimage(votesig.Timeout{Epoch: 1, Round: 3, HighQcRound: 3, Author: "a"})
			return err
		},
		"anchor timeout with another slot": func() error {
			_, err := cfg.TimeoutPreimage(votesig.Timeout{Epoch: 2, Round: 9, HighQcRound: 7, Author: "a", Anchor: &votesig.Anchor{Epoch: 2, Slot: 6}})
			return err
		},
		"anchor timeout with another epoch": func() error {
			_, err := cfg.TimeoutPreimage(votesig.Timeout{Epoch: 2, Round: 9, HighQcRound: 6, Author: "a", Anchor: &votesig.Anchor{Epoch: 3, Slot: 6}})
			return err
		},
	}
	for name, run := range bad {
		require.ErrorIs(t, run(), votesig.ErrStatement, name)
	}
	legacy := votesig.Config{Scheme: votesig.SchemeLegacy, Network: 5}
	_, err := legacy.VotePreimage(vi, commit)
	require.ErrorIs(t, err, votesig.ErrScheme, "scheme 1 has no domain-bound preimage")
	_, err = legacy.TimeoutPreimage(votesig.Timeout{Epoch: 1, Round: 3, HighQcRound: 2, Author: "a"})
	require.ErrorIs(t, err, votesig.ErrScheme)
	require.ErrorIs(t, votesig.Config{Scheme: 3}.Validate(), votesig.ErrScheme)
	require.ErrorIs(t, votesig.Config{Scheme: 2, Network: 5}.Validate(), votesig.ErrConfig, "scheme 2 needs the root-chain genesis identity")
}

// Every field of the statement is signed: a single change of any one produces other bytes.
func TestEverySignedFieldChangesThePreimage(t *testing.T) {
	cfg := testConfig()
	vi, commit := testVote()
	base, err := cfg.VotePreimage(vi, commit)
	require.NoError(t, err)
	changed := map[string]func() ([]byte, error){
		"network": func() ([]byte, error) { c := cfg; c.Network++; return c.VotePreimage(vi, commit) },
		"genesis": func() ([]byte, error) { c := cfg; c.Genesis[0] ^= 1; return c.VotePreimage(vi, commit) },
		"epoch":   func() ([]byte, error) { v := vi; v.Epoch++; return cfg.VotePreimage(v, commit) },
		"round":   func() ([]byte, error) { v := vi; v.Round++; return cfg.VotePreimage(v, commit) },
		"parent":  func() ([]byte, error) { v := vi; v.Parent--; return cfg.VotePreimage(v, commit) },
		"exec":    func() ([]byte, error) { v := vi; v.Exec[31] ^= 1; return cfg.VotePreimage(v, commit) },
		"commit hash": func() ([]byte, error) {
			c := commit
			c.Hash = bytes.Clone(c.Hash)
			c.Hash[0] ^= 1
			return cfg.VotePreimage(vi, c)
		},
		"commit round": func() ([]byte, error) { c := commit; c.Round--; return cfg.VotePreimage(vi, c) },
	}
	for name, run := range changed {
		got, err := run()
		require.NoError(t, err, name)
		require.NotEqual(t, base, got, name)
	}
	tbase := votesig.Timeout{Epoch: 300, Round: 70001, HighQcRound: 70000, Author: "node-1"}
	pt, err := cfg.TimeoutPreimage(tbase)
	require.NoError(t, err)
	for name, mutate := range map[string]func(*votesig.Timeout){
		"epoch":    func(x *votesig.Timeout) { x.Epoch++ },
		"round":    func(x *votesig.Timeout) { x.Round++ },
		"high QC":  func(x *votesig.Timeout) { x.HighQcRound-- },
		"author":   func(x *votesig.Timeout) { x.Author = "node-2" },
		"anchored": func(x *votesig.Timeout) { x.Anchor = &votesig.Anchor{Epoch: x.Epoch, Slot: x.HighQcRound} },
	} {
		x := tbase
		mutate(&x)
		got, err := cfg.TimeoutPreimage(x)
		require.NoError(t, err, name)
		require.NotEqual(t, pt, got, name)
	}
	// a vote and a timeout of the same identity never share bytes: tag, kind and domain separate them
	require.NotEqual(t, cfg.VoteDomain(), cfg.TimeoutDomain())
}

func TestStrictDecoder(t *testing.T) {
	for name, in := range map[string][]byte{
		"non-shortest integer (one byte for 5)":    {0x18, 0x05},
		"non-shortest integer (two bytes for 5)":   {0x19, 0x00, 0x05},
		"non-shortest integer (two bytes for 255)": {0x19, 0x00, 0xff},
		"trailing bytes":   {0x05, 0x05},
		"indefinite array": {0x9f, 0x05, 0xff},
		"tag":              {0xc1, 0x05},
		"float":            {0xf9, 0x3c, 0x00},
		"map":              {0xa1, 0x01, 0x02},
		"negative integer": {0x20},
		"truncated string": {0x43, 0x01},
		"invalid UTF-8":    {0x61, 0xff},
		"empty":            {},
		"true":             {0xf5},
	} {
		_, err := votesig.Decode(in)
		require.ErrorIs(t, err, votesig.ErrNotCanonical, name)
	}
	v, err := votesig.Decode([]byte{0x83, 0x18, 0x18, 0xf6, 0x62, 0x68, 0x69})
	require.NoError(t, err)
	require.Equal(t, []any{uint64(24), nil, "hi"}, v)
}

func TestPeekWrapper(t *testing.T) {
	ok, err := votesig.PeekWrapper([]byte{0x82, 0x02, 0xf6, 0xf6})
	require.NoError(t, err)
	require.True(t, ok)
	for name, in := range map[string][]byte{"legacy six-array": {0x86, 0xd9, 0x01}, "legacy pair of arrays": {0x82, 0x83, 0x01}, "short": {0x82}, "empty": nil} {
		ok, err := votesig.PeekWrapper(in)
		require.NoError(t, err, name)
		require.False(t, ok, name)
	}
	_, err = votesig.PeekWrapper([]byte{0x82, 0x01})
	require.ErrorIs(t, err, votesig.ErrScheme)
	_, err = votesig.PeekWrapper([]byte{0x82, 0x17})
	require.ErrorIs(t, err, votesig.ErrScheme)
	_, err = votesig.PeekWrapper([]byte{0x82, 0x19, 0x00, 0x02})
	require.ErrorIs(t, err, votesig.ErrNotCanonical)
}

func TestSignatureShape(t *testing.T) {
	require.NoError(t, votesig.CheckSignatureShape(make([]byte, 64)))
	for _, v := range []byte{0, 1} {
		require.NoError(t, votesig.CheckSignatureShape(append(make([]byte, 64), v)))
	}
	for name, sig := range map[string][]byte{"nil": nil, "63": make([]byte, 63), "66": make([]byte, 66), "65 with v=2": append(make([]byte, 64), 2), "65 with v=27": append(make([]byte, 64), 27)} {
		require.ErrorIs(t, votesig.CheckSignatureShape(sig), votesig.ErrSignatureShape, name)
	}
	d := votesig.Digest([]byte("x"))
	require.Equal(t, sha256.Sum256([]byte("x")), d)
}

func TestDecoderBoundsNesting(t *testing.T) {
	nested := func(levels int) []byte {
		b := bytes.Repeat([]byte{0x81}, levels) // arrays of one item
		return append(b, 0xf6)
	}
	_, err := votesig.Decode(nested(8))
	require.NoError(t, err, "eight levels of nesting are the most a signing object needs")
	_, err = votesig.Decode(nested(9))
	require.ErrorIs(t, err, votesig.ErrNotCanonical)
}
