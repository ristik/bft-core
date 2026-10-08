package q4replay

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"

	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
)

var testCfg = votesig.Config{Scheme: votesig.SchemeDomainBound, Network: 5, Genesis: sha256.Sum256([]byte("q4replay-test"))}

type signerSet struct {
	names   []string
	weights []uint64
	signers map[string]abcrypto.Signer
}

func newSigners(t *testing.T) *signerSet {
	s := &signerSet{names: []string{"H", "a", "b", "c"}, weights: []uint64{6, 1, 1, 1}, signers: map[string]abcrypto.Signer{}}
	for _, n := range s.names {
		sg, err := abcrypto.NewInMemorySecp256K1Signer()
		require.NoError(t, err)
		s.signers[n] = sg
	}
	return s
}

func (s *signerSet) epoch(t *testing.T, epoch uint64) Epoch {
	e := Epoch{Epoch: epoch, Scheme: votesig.SchemeDomainBound, Network: testCfg.Network, Genesis: testCfg.Genesis[:], Total: 9, Quorum: 7, Faulty: 2}
	for i, n := range s.names {
		ver, err := s.signers[n].Verifier()
		require.NoError(t, err)
		pub, err := ver.MarshalPublicKey()
		require.NoError(t, err)
		e.Members = append(e.Members, Member{Name: n, ID: "id-" + n, PubKey: pub, Weight: s.weights[i]})
	}
	return e
}

func (s *signerSet) vote(t *testing.T, name string, epoch, round uint64, root byte) []byte {
	info := &drctypes.RoundInfo{Version: 1, RoundNumber: round, Epoch: epoch, Timestamp: 1111, ParentRoundNumber: round - 1, CurrentRootHash: bytes.Repeat([]byte{root}, 32)}
	vi := votesig.VoteInfo{Epoch: epoch, Round: round, Parent: round - 1, Timestamp: 1111}
	copy(vi.Exec[:], info.CurrentRootHash)
	h, err := testCfg.VoteInfoHash(vi)
	require.NoError(t, err)
	v := &abdrc.VoteMsg{VoteInfo: info, LedgerCommitInfo: &types.UnicitySeal{Version: 1, PreviousHash: h[:]}, Author: "id-" + name}
	require.NoError(t, v.SignDomainBound(s.signers[name], testCfg))
	raw, err := types.Cbor.Marshal(v)
	require.NoError(t, err)
	return raw
}

func (s *signerSet) timeout(t *testing.T, name string, epoch, round uint64) []byte {
	info := &drctypes.RoundInfo{Version: 1, RoundNumber: round - 1, ParentRoundNumber: round - 2, Epoch: epoch, Timestamp: 1, CurrentRootHash: bytes.Repeat([]byte{1}, 32)}
	h, err := info.Hash(crypto.SHA256)
	require.NoError(t, err)
	qc := &drctypes.QuorumCert{VoteInfo: info, LedgerCommitInfo: &types.UnicitySeal{Version: 1, PreviousHash: h}, Signatures: map[string]hex.Bytes{}}
	m := abdrc.NewTimeoutMsg(drctypes.NewTimeout(round, epoch, qc), "id-"+name, nil)
	require.NoError(t, m.SignDomainBound(s.signers[name], testCfg))
	raw, err := types.Cbor.Marshal(m)
	require.NoError(t, err)
	return raw
}

// send appends an attempt and its delivery.
func send(b *Bundle, class string, epoch, round uint64, author string, raw []byte) {
	id := uint64(len(b.Events)/2 + 1)
	b.Events = append(b.Events,
		Event{Seq: uint64(len(b.Events) + 1), Kind: "attempt", SendID: id, From: "id-" + author, To: "id-H", Class: class, Epoch: epoch, Round: round, Author: "id-" + author, Raw: raw},
		Event{Seq: uint64(len(b.Events) + 2), Kind: "deliver", SendID: id, DeliveryID: id, From: "id-" + author, To: "id-H", Class: class, Epoch: epoch, Round: round, Author: "id-" + author, Raw: raw})
}

// goodBundle is an IN-BOUND run of A (6,1,1,1): every member votes for rounds 5 and 6, a light times out, two nodes commit the
// same blocks, a progress window then a stall window.
func goodBundle(t *testing.T) *Bundle {
	s := newSigners(t)
	b := &Bundle{Version: Version, Scenario: "synthetic", Coverage: "ORACLE-ONLY", Scope: "unit", Class: InBound, Epochs: []Epoch{s.epoch(t, 2)},
		Frozen: Frozen{DeadlineMs: 1000, MaxCommitGapMs: 400}}
	for _, n := range s.names {
		for _, r := range []uint64{5, 6} {
			send(b, "vote", 2, r, n, s.vote(t, n, 2, r, 7))
		}
	}
	send(b, "timeout", 2, 9, "a", s.timeout(t, "a", 2, 9))
	blocks := []Block{{Round: 5, Hash: []byte{5}, Parent: 4}, {Round: 6, Hash: []byte{6}, Parent: 5}, {Round: 7, Hash: []byte{7}, Parent: 6}}
	b.Chains = []Chain{
		{Node: "H", Blocks: blocks, Observed: []Observe{{5, 1100}, {6, 1300}, {7, 1500}}},
		{Node: "a", Blocks: blocks, Observed: []Observe{{5, 1150}, {6, 1350}, {7, 1550}}},
	}
	b.Windows = []Window{
		{Name: "recover", Expect: "progress", Nodes: []string{"H", "a"}, StartMs: 1000, MinCommits: 3},
		{Name: "stall", Expect: "stall", Nodes: []string{"H", "a"}, StartMs: 1600, EndMs: 2600},
	}
	return b
}

func clone(t *testing.T, b *Bundle) *Bundle {
	raw, err := json.Marshal(b)
	require.NoError(t, err)
	var out Bundle
	require.NoError(t, json.Unmarshal(raw, &out))
	return &out
}

func TestCheckAcceptsACleanBundle(t *testing.T) {
	b := goodBundle(t)
	rep := Check(b)
	require.NoError(t, rep.Err())
	require.Equal(t, InBound, rep.ComputedClass)
	require.Equal(t, 9, rep.Attempts, "eight votes and one timeout were examined") // the counters say what was examined
	require.Equal(t, 9, rep.Signed)
	require.Equal(t, 9, rep.Deliveries)
	require.Len(t, rep.Windows, 2)
	require.EqualValues(t, 550, rep.Windows[0].LastNthMs, "third commit latency is recomputed from the observation times")
	require.NoError(t, rep.ExpectEquivocators())
	// the file round trip keeps the verdict
	path := filepath.Join(t.TempDir(), "b.json")
	require.NoError(t, b.Save(path))
	loaded, err := Load(path)
	require.NoError(t, err)
	require.NoError(t, Check(loaded).Err())
}

func TestCheckRefusesEachDeliberateCorruption(t *testing.T) {
	good := goodBundle(t)
	tamper := func(mut func(*Bundle)) *Bundle {
		b := clone(t, good)
		mut(b)
		return b
	}
	flip := func(raw []byte) []byte {
		out := bytes.Clone(raw)
		out[len(out)/2] ^= 0xff
		return out
	}
	cases := []struct {
		name string
		b    *Bundle
		want error
	}{
		{"unsupported version", tamper(func(b *Bundle) { b.Version = 9 }), ErrFormat},
		{"claimed quorum differs", tamper(func(b *Bundle) { b.Epochs[0].Quorum = 6 }), ErrArithmetic},
		{"zero weight member", tamper(func(b *Bundle) { b.Epochs[0].Members[1].Weight = 0 }), ErrManifest},
		{"shared key", tamper(func(b *Bundle) { b.Epochs[0].Members[2].PubKey = b.Epochs[0].Members[1].PubKey }), ErrManifest},
		{"Byzantine name that is no member", tamper(func(b *Bundle) { b.Byzantine = []string{"ghost"} }), ErrByzantineName},
		{"claimed IN-BOUND with Byzantine weight 6", tamper(func(b *Bundle) { b.Byzantine = []string{"H"} }), ErrClass},
		{"claimed OUTSIDE with nothing Byzantine", tamper(func(b *Bundle) { b.Class = OutsideAssumptions }), ErrClass},
		{"repeated send ID", tamper(func(b *Bundle) { b.Events[2].SendID = b.Events[0].SendID }), ErrDuplicateSend},
		{"delivery without an attempt", tamper(func(b *Bundle) { b.Events[1].SendID = 999 }), ErrNoAttempt},
		{"delivered bytes differ", tamper(func(b *Bundle) { b.Events[1].Raw = flip(b.Events[1].Raw) }), ErrTampered},
		{"attempt without an outcome", tamper(func(b *Bundle) { b.Events[1].Kind = "hold" }), ErrNoOutcome},
		{"attempt without the serialized message", tamper(func(b *Bundle) { b.Events[0].Raw = nil }), ErrNoRaw},
		{"bytes do not decode", tamper(func(b *Bundle) { b.Events[0].Raw = []byte{0xff, 0x00} }), ErrDecode},
		{"claimed round differs from the bytes", tamper(func(b *Bundle) { b.Events[0].Round = 77 }), ErrClaim},
		{"claimed author differs from the bytes", tamper(func(b *Bundle) { b.Events[0].Author = "id-a" }), ErrClaim},
		{"epoch outside the manifest", tamper(func(b *Bundle) { b.Epochs[0].Epoch = 3 }), ErrUnknownEpoch},
		{"author that is no member", tamper(func(b *Bundle) { b.Epochs[0].Members[0].ID = "someone-else" }), ErrUnknownAuthor},
		{"signature of another key", tamper(func(b *Bundle) {
			m := b.Epochs[0].Members
			m[0].PubKey, m[1].PubKey = m[1].PubKey, m[0].PubKey
		}), ErrSignature},
		{"wrong signing domain", tamper(func(b *Bundle) { b.Epochs[0].Network = 6 }), ErrSignature},
		{"two nodes disagree on a block", tamper(func(b *Bundle) { b.Chains[1].Blocks[1].Hash = []byte{0xee} }), ErrChainConflict},
		{"two nodes share no round", tamper(func(b *Bundle) {
			for i := range b.Chains[1].Blocks {
				b.Chains[1].Blocks[i].Round += 100
				b.Chains[1].Blocks[i].Parent += 100
			}
		}), ErrChainShared},
		{"block that extends no lower round", tamper(func(b *Bundle) { b.Chains[0].Blocks[0].Parent = 5 }), ErrChainParent},
		{"too few commits inside the deadline", tamper(func(b *Bundle) { b.Chains[0].Observed[2].AtMs = 2100 }), ErrNoProgress},
		{"gap above the frozen bound", tamper(func(b *Bundle) { b.Frozen.MaxCommitGapMs = 100 }), ErrCommitGap},
		{"commit inside a stall window", tamper(func(b *Bundle) { b.Chains[1].Observed = append(b.Chains[1].Observed, Observe{8, 2000}) }), ErrStalled},
		{"progress window without a frozen deadline", tamper(func(b *Bundle) { b.Frozen.DeadlineMs = 0 }), ErrWindow},
		{"unknown window kind", tamper(func(b *Bundle) { b.Windows[0].Expect = "maybe" }), ErrWindow},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := Check(tc.b).Err()
			require.ErrorIs(t, err, tc.want)
		})
	}
}

// A forged send is flagged by the checker; it is a violation unless the run declared exactly that many injections.
func TestCheckCountsDeclaredInjections(t *testing.T) {
	b := goodBundle(t)
	var forged []byte
	for i := range b.Events {
		if b.Events[i].Kind == "attempt" && b.Events[i].Class == "vote" {
			var v abdrc.VoteMsg
			require.NoError(t, types.Cbor.Unmarshal(b.Events[i].Raw, &v))
			v.Signature[0] ^= 0xff
			var err error
			forged, err = types.Cbor.Marshal(&v)
			require.NoError(t, err)
			break
		}
	}
	send(b, "vote", 2, 5, "H", forged)
	last := len(b.Events) - 1
	require.NotEqual(t, b.Events[0].Raw, b.Events[last].Raw)
	require.ErrorIs(t, Check(clone(t, b)).Err(), ErrSignature, "the reason of the flagged send is kept")
	undeclared := Check(clone(t, b))
	require.ErrorIs(t, undeclared.Err(), ErrMalformedCount, "a forged send nobody declared is a violation")
	require.Len(t, undeclared.Malformed, 1)
	b.Injected = 1
	declared := Check(b)
	require.NoError(t, declared.Err())
	require.Len(t, declared.Malformed, 1)
	b.Injected = 2
	require.ErrorIs(t, Check(b).Err(), ErrMalformedCount, "a declared injection that was not found is a violation too")
}

// An honest member who signs two statements is caught, a declared Byzantine one is only classified; the exact equivocator set is
// a separate claim.
func TestCheckClassifiesEquivocation(t *testing.T) {
	s := newSigners(t)
	build := func(byz ...string) *Bundle {
		b := &Bundle{Version: Version, Scenario: "synthetic", Coverage: "ORACLE-ONLY", Class: InBound, Epochs: []Epoch{s.epoch(t, 2)}, Byzantine: byz}
		for _, n := range s.names {
			send(b, "vote", 2, 5, n, s.vote(t, n, 2, 5, 7))
		}
		send(b, "vote", 2, 5, "a", s.vote(t, "a", 2, 5, 9)) // a second statement of a
		send(b, "vote", 2, 5, "b", s.vote(t, "b", 2, 5, 7)) // identical rebroadcast of b
		return b
	}
	honest := Check(build())
	require.ErrorIs(t, honest.Err(), ErrHonestDoubleSig)
	require.Contains(t, honest.Equivocated, "a")
	require.NotContains(t, honest.Equivocated, "b", "an identical rebroadcast is not an equivocation")

	declared := Check(build("a", "c"))
	require.NoError(t, declared.Err(), "weight 2 declared Byzantine is in bound and the equivocation is classified")
	require.NoError(t, declared.ExpectEquivocators("a"))
	require.ErrorIs(t, declared.ExpectEquivocators("a", "c"), ErrEquivocator)
	require.ErrorIs(t, declared.ExpectEquivocators(), ErrEquivocator)

	heavy := build("H", "a")
	heavy.Class = OutsideAssumptions
	require.NoError(t, Check(heavy).Err(), "Byzantine weight 7 is outside the assumptions and is labelled so")
	require.Equal(t, OutsideAssumptions, Check(heavy).ComputedClass)
}
