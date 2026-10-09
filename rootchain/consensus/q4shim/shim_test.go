package q4shim

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"

	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
)

// fakeInner records what the shim hands to the wrapped network.
type fakeInner struct {
	mu   sync.Mutex
	sent []sentMsg
	in   chan any
	fail error
}

type sentMsg struct {
	to  peer.ID
	msg any
}

func testPeer(t *testing.T) peer.ID {
	t.Helper()
	priv, _, err := libp2pcrypto.GenerateEd25519Key(nil)
	require.NoError(t, err)
	id, err := peer.IDFromPrivateKey(priv)
	require.NoError(t, err)
	return id
}

func newFakeInner() *fakeInner { return &fakeInner{in: make(chan any, 16)} }

func (f *fakeInner) Send(_ context.Context, msg any, receivers ...peer.ID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return f.fail
	}
	for _, r := range receivers {
		f.sent = append(f.sent, sentMsg{r, msg})
	}
	return nil
}

func (f *fakeInner) ReceivedChannel() <-chan any { return f.in }

func (f *fakeInner) got() []sentMsg {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]sentMsg(nil), f.sent...)
}

func (f *fakeInner) rounds(to peer.ID) (out []uint64) {
	for _, s := range f.got() {
		if s.to != to {
			continue
		}
		switch m := s.msg.(type) {
		case *abdrc.VoteMsg:
			out = append(out, m.VoteInfo.RoundNumber)
		case *abdrc.TimeoutMsg:
			out = append(out, m.Timeout.Round)
		}
	}
	return out
}

var testCfg = votesig.Config{Scheme: votesig.SchemeDomainBound, Network: 5, Genesis: sha256.Sum256([]byte("q4shim-test"))}

func testSigning(epoch uint64) (votesig.Config, error) { return testCfg, nil }

func legacyVote(t *testing.T, signer abcrypto.Signer, author string, round uint64) *abdrc.VoteMsg {
	t.Helper()
	info := &drctypes.RoundInfo{RoundNumber: round, Epoch: 1, Timestamp: 1111, ParentRoundNumber: round - 1, CurrentRootHash: bytes.Repeat([]byte{0xaa}, 32)}
	h, err := info.Hash(crypto.SHA256)
	require.NoError(t, err)
	v := &abdrc.VoteMsg{VoteInfo: info, LedgerCommitInfo: &types.UnicitySeal{Version: 1, PreviousHash: h}, Author: author}
	require.NoError(t, v.Sign(signer))
	return v
}

func boundVote(t *testing.T, signer abcrypto.Signer, author string, round uint64) *abdrc.VoteMsg {
	t.Helper()
	info := &drctypes.RoundInfo{Version: 1, RoundNumber: round, Epoch: 2, Timestamp: 1111, ParentRoundNumber: round - 1, CurrentRootHash: bytes.Repeat([]byte{0xaa}, 32)}
	vi := votesig.VoteInfo{Epoch: 2, Round: round, Parent: round - 1, Timestamp: 1111}
	copy(vi.Exec[:], info.CurrentRootHash)
	h, err := testCfg.VoteInfoHash(vi)
	require.NoError(t, err)
	v := &abdrc.VoteMsg{VoteInfo: info, LedgerCommitInfo: &types.UnicitySeal{Version: 1, PreviousHash: h[:]}, Author: author}
	require.NoError(t, v.SignDomainBound(signer, testCfg))
	return v
}

func boundTimeout(t *testing.T, signer abcrypto.Signer, author string, round uint64) *abdrc.TimeoutMsg {
	t.Helper()
	info := &drctypes.RoundInfo{Version: 1, RoundNumber: round - 1, ParentRoundNumber: round - 2, Epoch: 2, Timestamp: 1, CurrentRootHash: bytes.Repeat([]byte{1}, 32)}
	h, err := info.Hash(crypto.SHA256)
	require.NoError(t, err)
	qc := &drctypes.QuorumCert{VoteInfo: info, LedgerCommitInfo: &types.UnicitySeal{Version: 1, PreviousHash: h}, Signatures: map[string]hex.Bytes{}}
	m := abdrc.NewTimeoutMsg(drctypes.NewTimeout(round, 2, qc), author, nil)
	require.NoError(t, m.SignDomainBound(signer, testCfg))
	return m
}

func mustVerifier(t *testing.T, s abcrypto.Signer) abcrypto.Verifier {
	t.Helper()
	v, err := s.Verifier()
	require.NoError(t, err)
	return v
}

func newSigner(t *testing.T) abcrypto.Signer {
	t.Helper()
	s, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	return s
}

func TestDescribe(t *testing.T) {
	s := newSigner(t)
	t.Run("a legacy vote's statement is the seal bytes it signs", func(t *testing.T) {
		v := legacyVote(t, s, "a", 7)
		m, err := Describe(v, nil)
		require.NoError(t, err)
		want, err := v.LedgerCommitInfo.SigBytes()
		require.NoError(t, err)
		require.Equal(t, want, m.Statement)
		require.Equal(t, Msg{Class: Vote, Type: "vote", Epoch: 1, Round: 7, Author: "a", Scheme: votesig.SchemeLegacy}, Msg{m.Class, m.Type, m.Epoch, m.Round, m.Author, m.Scheme, nil, nil})
		require.NoError(t, mustVerifier(t, s).VerifyBytes(v.Signature, m.Statement))
	})
	t.Run("a scheme 2 vote's statement is its PV and verifies under the signature", func(t *testing.T) {
		v := boundVote(t, s, "a", 7)
		m, err := Describe(v, testSigning)
		require.NoError(t, err)
		require.EqualValues(t, votesig.SchemeDomainBound, m.Scheme)
		require.NoError(t, mustVerifier(t, s).VerifyBytes(v.Signature, m.Statement))
	})
	t.Run("a scheme 2 timeout's statement is its PT and verifies under the signature", func(t *testing.T) {
		tm := boundTimeout(t, s, "a", 9)
		m, err := Describe(tm, testSigning)
		require.NoError(t, err)
		require.Equal(t, Timeout, m.Class)
		require.NoError(t, mustVerifier(t, s).VerifyBytes(tm.Signature, m.Statement))
	})
	t.Run("a scheme 2 message without a signing source has no statement", func(t *testing.T) {
		_, err := Describe(boundVote(t, s, "a", 7), nil)
		require.ErrorIs(t, err, ErrStatement)
		_, err = Describe(boundTimeout(t, s, "a", 7), nil)
		require.ErrorIs(t, err, ErrStatement)
	})
	t.Run("a message without a body is refused with its sentinel", func(t *testing.T) {
		_, err := Describe(&abdrc.VoteMsg{}, nil)
		require.ErrorIs(t, err, ErrStatement)
		_, err = Describe(&abdrc.TimeoutMsg{}, nil)
		require.ErrorIs(t, err, ErrStatement)
		_, err = Describe(&abdrc.ProposalMsg{}, nil)
		require.ErrorIs(t, err, ErrStatement)
	})
	t.Run("other message classes are passed over", func(t *testing.T) {
		m, err := Describe(&abdrc.StateRequestMsg{}, nil)
		require.NoError(t, err)
		require.Equal(t, Other, m.Class)
	})
}

func TestCopy(t *testing.T) {
	s := newSigner(t)
	for name, msg := range map[string]any{"legacy vote": legacyVote(t, s, "a", 3), "scheme 2 vote": boundVote(t, s, "a", 3), "scheme 2 timeout": boundTimeout(t, s, "a", 3)} {
		t.Run(name, func(t *testing.T) {
			m, err := Describe(msg, testSigning)
			require.NoError(t, err)
			cp, err := Copy(m)
			require.NoError(t, err)
			again, err := types.Cbor.Marshal(cp)
			require.NoError(t, err)
			require.Equal(t, m.Raw, again, "the copy is the recorded bytes")
		})
	}
	t.Run("bytes that do not decode are refused", func(t *testing.T) {
		m, err := Describe(legacyVote(t, s, "a", 3), nil)
		require.NoError(t, err)
		m.Raw = m.Raw[:len(m.Raw)-3]
		_, err = Copy(m)
		require.ErrorIs(t, err, ErrCopy)
	})
	t.Run("bytes that decode to a message that encodes differently are refused", func(t *testing.T) {
		m, err := Describe(legacyVote(t, s, "a", 3), nil)
		require.NoError(t, err)
		m.Raw = append(m.Raw, 0xf6) // trailing item: not the canonical encoding of what it decodes to
		_, err = Copy(m)
		require.ErrorIs(t, err, ErrCopy)
	})
}

type fixture struct {
	t     *testing.T
	inner *fakeInner
	net   *Net
	self  peer.ID
	a, b  peer.ID
	s     abcrypto.Signer
}

func newFixture(t *testing.T, mut ...func(*Config)) *fixture {
	t.Helper()
	f := &fixture{t: t, inner: newFakeInner(), self: testPeer(t), a: testPeer(t), b: testPeer(t), s: newSigner(t)}
	cfg := Config{Self: f.self, Signing: testSigning, Signer: f.s, KeepRaw: true}
	for _, m := range mut {
		m(&cfg)
	}
	f.net = New(f.inner, cfg)
	t.Cleanup(f.net.Close)
	return f
}

func (f *fixture) apply(c Control) {
	f.t.Helper()
	require.NoError(f.t, f.net.Apply(context.Background(), c))
}

func (f *fixture) send(msg any, to ...peer.ID) {
	f.t.Helper()
	require.NoError(f.t, f.net.Send(context.Background(), msg, to...))
}

func kinds(tr []Event) (out []string) {
	for _, e := range tr {
		out = append(out, e.Kind)
	}
	return out
}

func TestRules(t *testing.T) {
	ctx := context.Background()
	t.Run("pass is the default and a trace pairs each attempt with its delivery", func(t *testing.T) {
		f := newFixture(t)
		f.send(boundVote(t, f.s, f.self.String(), 3), f.a, f.b)
		require.Equal(t, []uint64{3}, f.inner.rounds(f.a))
		require.Equal(t, []uint64{3}, f.inner.rounds(f.b))
		require.Equal(t, []string{"attempt", "deliver", "attempt", "deliver"}, kinds(f.net.Trace()))
		require.NoError(t, f.net.Finish())
	})
	t.Run("drop is directional and traced", func(t *testing.T) {
		f := newFixture(t)
		f.apply(Control{Rules: []Rule{{Name: "cut-a", To: []string{f.a.String()}, Class: Vote, Action: Drop, Require: true}}})
		f.send(boundVote(t, f.s, f.self.String(), 3), f.a, f.b)
		require.Empty(t, f.inner.rounds(f.a))
		require.Equal(t, []uint64{3}, f.inner.rounds(f.b))
		require.Equal(t, []string{"attempt", "drop", "attempt", "deliver"}, kinds(f.net.Trace()))
		require.Equal(t, 1, f.net.Hits("cut-a"))
		require.NoError(t, f.net.Finish())
	})
	t.Run("a rule for one class leaves the others alone", func(t *testing.T) {
		f := newFixture(t)
		f.apply(Control{Rules: []Rule{{Name: "votes", Class: Vote, Action: Drop}}})
		f.send(boundTimeout(t, f.s, f.self.String(), 4), f.a)
		require.Equal(t, []uint64{4}, f.inner.rounds(f.a))
	})
	t.Run("epoch and round bounds select", func(t *testing.T) {
		f := newFixture(t)
		f.apply(Control{Rules: []Rule{{Name: "window", Epoch: 2, RoundMin: 4, RoundMax: 5, Action: Drop}}})
		for _, r := range []uint64{3, 4, 5, 6} {
			f.send(boundVote(t, f.s, f.self.String(), r), f.a)
		}
		require.Equal(t, []uint64{3, 6}, f.inner.rounds(f.a))
	})
	t.Run("self delivery is preserved unless targeted", func(t *testing.T) {
		f := newFixture(t)
		f.apply(Control{Rules: []Rule{{Name: "all", Action: Drop}}})
		f.send(boundVote(t, f.s, f.self.String(), 3), f.self)
		require.Equal(t, []uint64{3}, f.inner.rounds(f.self))
		f.apply(Control{Rules: []Rule{{Name: "all", Action: Drop, Self: true}}})
		f.send(boundVote(t, f.s, f.self.String(), 4), f.self)
		require.Equal(t, []uint64{3}, f.inner.rounds(f.self))
	})
	t.Run("hold keeps a message until its release, in the chosen order", func(t *testing.T) {
		for order, want := range map[Order][]uint64{FIFO: {5, 3, 4}, LIFO: {4, 3, 5}, RoundAsc: {3, 4, 5}, RoundDsc: {5, 4, 3}} {
			f := newFixture(t)
			f.apply(Control{Rules: []Rule{{Name: "hold", To: []string{f.a.String()}, Action: Hold}}})
			for _, r := range []uint64{5, 3, 4} {
				f.send(boundVote(t, f.s, f.self.String(), r), f.a)
			}
			require.Empty(t, f.inner.rounds(f.a))
			require.Equal(t, 3, f.net.Held("hold"))
			n, err := f.net.ReleaseHeld(ctx, "hold", order)
			require.NoError(t, err)
			require.Equal(t, 3, n)
			require.Equal(t, want, f.inner.rounds(f.a), "order %s", order)
			require.Zero(t, f.net.Held("hold"))
			f.send(boundVote(t, f.s, f.self.String(), 9), f.a)
			require.Equal(t, append(want, 9), f.inner.rounds(f.a), "a released rule passes what it matches afterwards")
		}
	})
	t.Run("a released message is the recorded bytes even if the sender mutated its message", func(t *testing.T) {
		f := newFixture(t)
		f.apply(Control{Rules: []Rule{{Name: "hold", Action: Hold}}})
		v := boundVote(t, f.s, f.self.String(), 3)
		recorded, err := types.Cbor.Marshal(v)
		require.NoError(t, err)
		f.send(v, f.a)
		v.VoteInfo.RoundNumber = 99
		v.Author = "mutated"
		_, err = f.net.ReleaseHeld(ctx, "hold", FIFO)
		require.NoError(t, err)
		got := f.inner.got()
		require.Len(t, got, 1)
		raw, err := types.Cbor.Marshal(got[0].msg)
		require.NoError(t, err)
		require.Equal(t, recorded, raw)
		require.NotSame(t, v, got[0].msg)
	})
	t.Run("duplicate delivers the same bytes twice", func(t *testing.T) {
		f := newFixture(t)
		f.apply(Control{Rules: []Rule{{Name: "dup", Class: Timeout, Action: Duplicate}}})
		f.send(boundTimeout(t, f.s, f.self.String(), 6), f.a)
		got := f.inner.got()
		require.Len(t, got, 2)
		x, _ := types.Cbor.Marshal(got[0].msg)
		y, _ := types.Cbor.Marshal(got[1].msg)
		require.Equal(t, x, y)
		require.Equal(t, []string{"attempt", "deliver", "deliver"}, kinds(f.net.Trace()))
	})
	t.Run("a trigger arms a later rule only after the observed event", func(t *testing.T) {
		f := newFixture(t)
		f.apply(Control{
			Triggers: []Trigger{{Name: "r4", Class: Vote, RoundMin: 4, Require: true}},
			Rules:    []Rule{{Name: "after-r4", Class: Vote, Action: Drop, After: "r4", Require: true}},
		})
		f.send(boundVote(t, f.s, f.self.String(), 3), f.a)
		f.send(boundVote(t, f.s, f.self.String(), 4), f.a) // fires the trigger; not itself dropped
		f.send(boundVote(t, f.s, f.self.String(), 5), f.a)
		require.Equal(t, []uint64{3, 4}, f.inner.rounds(f.a))
		require.NoError(t, f.net.Finish())
	})
	t.Run("a required trigger that never fires and a required rule that never matches fail the scenario", func(t *testing.T) {
		f := newFixture(t)
		f.apply(Control{Triggers: []Trigger{{Name: "never", Class: Vote, RoundMin: 100, Require: true}}, Rules: []Rule{{Name: "unmatched", Epoch: 9, Action: Drop, Require: true}}})
		f.send(boundVote(t, f.s, f.self.String(), 3), f.a)
		err := f.net.Finish()
		require.ErrorIs(t, err, ErrTriggerNotFired)
		require.ErrorIs(t, err, ErrRuleNotHit)
	})
	t.Run("a message the shim cannot describe is passed on and fails the scenario", func(t *testing.T) {
		f := newFixture(t, func(c *Config) { c.Signing = nil })
		f.send(boundVote(t, f.s, f.self.String(), 3), f.a)
		require.Equal(t, []uint64{3}, f.inner.rounds(f.a), "the message is not lost")
		require.ErrorIs(t, f.net.Finish(), ErrStatement)
	})
	t.Run("the wrapped network refusing a receiver is traced, not hidden", func(t *testing.T) {
		f := newFixture(t)
		f.inner.fail = os.ErrClosed
		f.send(boundVote(t, f.s, f.self.String(), 3), f.a)
		require.Contains(t, kinds(f.net.Trace()), "fault")
		require.NotContains(t, kinds(f.net.Trace()), "deliver")
	})
}

func TestReplay(t *testing.T) {
	f := newFixture(t)
	f.apply(Control{Rules: []Rule{{Name: "cut", To: []string{f.a.String()}, Class: Vote, RoundMin: 4, Action: Drop}}})
	var msgs []*abdrc.VoteMsg
	for _, r := range []uint64{3, 4, 5} {
		msgs = append(msgs, boundVote(t, f.s, f.self.String(), r))
		f.send(msgs[len(msgs)-1], f.a, f.b)
	}
	log := f.net.Decisions()

	r := newFixture(t)
	r.self, r.a, r.b, r.s = f.self, f.a, f.b, f.s
	r.net = New(r.inner, Config{Self: f.self, Signing: testSigning, Replay: &log})
	t.Cleanup(r.net.Close)
	for _, m := range msgs {
		r.send(m, r.a, r.b)
	}
	require.Equal(t, f.inner.rounds(f.a), r.inner.rounds(r.a))
	require.Equal(t, f.inner.rounds(f.b), r.inner.rounds(r.b))

	t.Run("a message the log has no decision for fails", func(t *testing.T) {
		err := r.net.Send(context.Background(), boundVote(t, f.s, f.self.String(), 8), r.a)
		require.ErrorIs(t, err, ErrNoDecision)
		require.ErrorIs(t, r.net.Finish(), ErrNoDecision)
	})
}

func TestEquivocation(t *testing.T) {
	t.Run("a scheme 2 state variant is a second validly signed statement for the same round", func(t *testing.T) {
		f := newFixture(t)
		require.NoError(t, f.net.SetEquivocations([]Equivocation{{Name: "byz", Recipients: []string{f.a.String(), f.b.String()}, Variant: "state", Require: true}}))
		honest := boundVote(t, f.s, f.self.String(), 5)
		f.send(honest, f.a)
		got := f.inner.got()
		require.Len(t, got, 3, "the honest vote to a, then the variants to a and b")
		hm, err := Describe(got[0].msg, testSigning)
		require.NoError(t, err)
		for _, s := range got[1:] {
			vm, err := Describe(s.msg, testSigning)
			require.NoError(t, err)
			require.Equal(t, hm.Round, vm.Round)
			require.Equal(t, hm.Author, vm.Author)
			require.NotEqual(t, hm.Statement, vm.Statement, "a different statement for the same author and round")
			require.NoError(t, mustVerifier(t, f.s).VerifyBytes(s.msg.(*abdrc.VoteMsg).Signature, vm.Statement), "validly signed by the node's key")
		}
		require.Equal(t, 2, f.net.Sent("byz"))
		f.send(boundVote(t, f.s, f.self.String(), 5), f.b)
		require.Len(t, f.inner.got(), 4, "the round is answered once")
		require.NoError(t, f.net.Finish())
	})
	t.Run("a legacy state variant is signed over its own seal", func(t *testing.T) {
		f := newFixture(t)
		require.NoError(t, f.net.SetEquivocations([]Equivocation{{Name: "byz", Recipients: []string{f.a.String()}, Variant: "state"}}))
		f.send(legacyVote(t, f.s, f.self.String(), 5), f.b)
		got := f.inner.got()
		require.Len(t, got, 2)
		v := got[1].msg.(*abdrc.VoteMsg)
		vm, err := Describe(v, nil)
		require.NoError(t, err)
		require.NoError(t, mustVerifier(t, f.s).VerifyBytes(v.Signature, vm.Statement))
		h, err := v.VoteInfo.Hash(crypto.SHA256)
		require.NoError(t, err)
		require.Equal(t, h, []byte(v.LedgerCommitInfo.PreviousHash), "the seal names the variant's own vote info")
	})
	t.Run("a rebroadcast repeats the honest bytes", func(t *testing.T) {
		f := newFixture(t)
		require.NoError(t, f.net.SetEquivocations([]Equivocation{{Name: "byz", Recipients: []string{f.a.String()}, Variant: "rebroadcast"}}))
		f.send(boundVote(t, f.s, f.self.String(), 5), f.b)
		got := f.inner.got()
		x, _ := types.Cbor.Marshal(got[0].msg)
		y, _ := types.Cbor.Marshal(got[1].msg)
		require.Equal(t, x, y)
	})
	t.Run("only the node's own votes are answered", func(t *testing.T) {
		f := newFixture(t)
		require.NoError(t, f.net.SetEquivocations([]Equivocation{{Name: "byz", Recipients: []string{f.a.String()}, Variant: "state"}}))
		f.send(boundVote(t, f.s, "someone-else", 5), f.b)
		require.Len(t, f.inner.got(), 1)
		require.Zero(t, f.net.Sent("byz"))
		require.ErrorIs(t, f.net.Finish(), nil)
	})
	t.Run("a required equivocation that never happened fails the scenario", func(t *testing.T) {
		f := newFixture(t)
		require.NoError(t, f.net.SetEquivocations([]Equivocation{{Name: "byz", Recipients: []string{f.a.String()}, Variant: "state", Require: true}}))
		require.ErrorIs(t, f.net.Finish(), ErrRuleNotHit)
	})
	t.Run("without a signer there is no Byzantine adapter", func(t *testing.T) {
		f := newFixture(t, func(c *Config) { c.Signer = nil })
		require.NoError(t, f.net.SetEquivocations([]Equivocation{{Name: "byz", Recipients: []string{f.a.String()}, Variant: "state"}}))
		err := f.net.Send(context.Background(), boundVote(t, f.s, f.self.String(), 5), f.b)
		require.ErrorIs(t, err, ErrNoSigner)
	})
	t.Run("an unknown variant or an empty recipient list is refused", func(t *testing.T) {
		f := newFixture(t)
		require.ErrorIs(t, f.net.SetEquivocations([]Equivocation{{Name: "x", Recipients: []string{f.a.String()}, Variant: "forge"}}), ErrBadControl)
		require.ErrorIs(t, f.net.SetEquivocations([]Equivocation{{Name: "x", Variant: "state"}}), ErrBadControl)
	})
}

func TestControl(t *testing.T) {
	ctx := context.Background()
	bad := map[string]Control{
		"unknown action":     {Rules: []Rule{{Name: "r", Action: "explode"}}},
		"duplicate rule":     {Rules: []Rule{{Name: "r", Action: Drop}, {Name: "r", Action: Hold}}},
		"unnamed rule":       {Rules: []Rule{{Action: Drop}}},
		"unknown trigger":    {Rules: []Rule{{Name: "r", Action: Drop, After: "nope"}}},
		"duplicate trigger":  {Triggers: []Trigger{{Name: "t"}, {Name: "t"}}},
		"unnamed trigger":    {Triggers: []Trigger{{}}},
		"unknown order":      {Releases: []Release{{ID: "1", Rule: "r", Order: "random"}}},
		"release without id": {Releases: []Release{{Rule: "r"}}},
	}
	for name, c := range bad {
		t.Run("invalid: "+name+" changes nothing", func(t *testing.T) {
			f := newFixture(t)
			f.apply(Control{Gen: 1, Rules: []Rule{{Name: "keep", Action: Drop}}})
			require.ErrorIs(t, f.net.Apply(ctx, c), ErrBadControl)
			f.send(boundVote(t, f.s, f.self.String(), 3), f.a)
			require.Empty(t, f.inner.rounds(f.a), "the previous rules are still in force")
			require.EqualValues(t, 1, f.net.Status().Gen)
		})
	}
	t.Run("a release is performed once however often the document is applied", func(t *testing.T) {
		f := newFixture(t)
		c := Control{Gen: 1, Rules: []Rule{{Name: "h", Action: Hold}}}
		f.apply(c)
		f.send(boundVote(t, f.s, f.self.String(), 3), f.a)
		c.Gen, c.Releases = 2, []Release{{ID: "go", Rule: "h", Order: FIFO}}
		f.apply(c)
		f.apply(c)
		require.Equal(t, []uint64{3}, f.inner.rounds(f.a), "delivered once")
	})
	t.Run("rules that keep their name keep their counters", func(t *testing.T) {
		f := newFixture(t)
		c := Control{Gen: 1, Rules: []Rule{{Name: "d", Action: Drop}}}
		f.apply(c)
		f.send(boundVote(t, f.s, f.self.String(), 3), f.a)
		c.Gen = 2
		f.apply(c)
		require.Equal(t, 1, f.net.Hits("d"))
	})
	t.Run("the status reports what was injected", func(t *testing.T) {
		f := newFixture(t)
		f.apply(Control{Gen: 7, Rules: []Rule{{Name: "h", Action: Hold}}, Triggers: []Trigger{{Name: "t"}}})
		f.send(boundVote(t, f.s, f.self.String(), 3), f.a)
		st := f.net.Status()
		require.EqualValues(t, 7, st.Gen)
		require.Equal(t, map[string]int{"h": 1}, st.Rules)
		require.Equal(t, map[string]int{"h": 1}, st.Held)
		require.Equal(t, map[string]int{"t": 1}, st.Triggers)
	})
}

func TestWatch(t *testing.T) {
	f := newFixture(t)
	dir := t.TempDir()
	control, status := filepath.Join(dir, "control.json"), filepath.Join(dir, "status.json")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { f.net.Watch(ctx, control, status, 10*time.Millisecond); close(done) }()
	defer func() { cancel(); <-done }()

	write := func(v any) {
		b, err := json.Marshal(v)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(control, b, 0o600))
	}
	gen := func() uint64 {
		var st Status
		b, err := os.ReadFile(status)
		if err != nil || json.Unmarshal(b, &st) != nil {
			return 0
		}
		return st.Gen
	}
	write(Control{Gen: 3, Rules: []Rule{{Name: "cut", Action: Drop}}})
	require.Eventually(t, func() bool { return gen() == 3 }, 5*time.Second, 10*time.Millisecond, "the shim read the document and said so")
	f.send(boundVote(t, f.s, f.self.String(), 3), f.a)
	require.Empty(t, f.inner.rounds(f.a))

	t.Run("an unknown field is a fault and keeps the rules", func(t *testing.T) {
		require.NoError(t, os.WriteFile(control, []byte(`{"gen":4,"rulez":[]}`), 0o600))
		require.Eventually(t, func() bool { return len(f.net.Faults()) > 0 }, 5*time.Second, 10*time.Millisecond)
		require.ErrorIs(t, f.net.Faults()[0], ErrBadControl)
		require.EqualValues(t, 3, f.net.Status().Gen)
	})
}

func TestReceiveIsRecorded(t *testing.T) {
	f := newFixture(t)
	v := boundVote(t, f.s, "peer-a", 6)
	f.inner.in <- v
	select {
	case got := <-f.net.ReceivedChannel():
		require.Same(t, v, got, "the message is passed on untouched")
	case <-time.After(5 * time.Second):
		t.Fatal("nothing received")
	}
	tr := f.net.Trace()
	require.Equal(t, "recv", tr[len(tr)-1].Kind)
	require.EqualValues(t, 6, tr[len(tr)-1].Round)
	require.Equal(t, "peer-a", tr[len(tr)-1].Author)
}

// The documents the live lane's shell library writes are read by the shim's own strict decoder and installed: a field or action the
// library invents is a failure here, before a lane is run.
func TestLaneControlDocumentsAreReadByTheShim(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash")
	}
	dir := t.TempDir()
	out, err := exec.Command(bash, "../../../scripts/lib/q4-lib.sh", "--selftest-docs", dir).CombinedOutput()
	require.NoError(t, err, string(out))
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	require.NoError(t, err)
	require.Len(t, files, 4)
	for _, file := range files {
		t.Run(filepath.Base(file), func(t *testing.T) {
			raw, err := os.ReadFile(file)
			require.NoError(t, err)
			var c Control
			dec := json.NewDecoder(bytes.NewReader(raw))
			dec.DisallowUnknownFields()
			require.NoError(t, dec.Decode(&c))
			f := newFixture(t)
			if len(c.Releases) > 0 { // a release names a rule that exists
				f.apply(Control{Rules: []Rule{{Name: c.Releases[0].Rule, Action: Hold}}})
			}
			require.NoError(t, f.net.Apply(context.Background(), c))
		})
	}
}

// The lane's offline trace checker (python) reads exactly what the wired shim writes: it accepts a run whose only equivocator is the
// declared Byzantine root, and rejects the same run when the equivocator is not declared and when a delivery carries other bytes.
func TestTraceCheckerReadsTheShimTrace(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("no python3")
	}
	write := func(t *testing.T, tamper bool) (dir string, self peer.ID) {
		dir = t.TempDir()
		var lines [][]byte
		f := newFixture(t, func(c *Config) { c.Trace = func(ev Event) { b, _ := json.Marshal(ev); lines = append(lines, b) } })
		require.NoError(t, f.net.SetEquivocations([]Equivocation{{Name: "byz", Recipients: []string{f.a.String()}, Variant: "state"}}))
		for r := uint64(3); r < 6; r++ {
			f.send(boundVote(t, f.s, f.self.String(), r), f.a, f.b)
		}
		root := filepath.Join(dir, "root1")
		require.NoError(t, os.MkdirAll(root, 0o755))
		var out []byte
		for _, l := range lines {
			if tamper {
				var ev map[string]any
				require.NoError(t, json.Unmarshal(l, &ev))
				if ev["kind"] == "deliver" && ev["rawSha256"] != nil {
					ev["rawSha256"] = "00"
					l, _ = json.Marshal(ev)
					tamper = false
				}
			}
			out = append(out, l...)
			out = append(out, '\n')
		}
		require.NoError(t, os.WriteFile(filepath.Join(root, "trace.jsonl"), out, 0o600))
		st, err := json.Marshal(f.net.Status())
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(root, "status.json"), st, 0o600))
		return dir, f.self
	}
	run := func(dir string, args ...string) (string, error) {
		out, err := exec.Command(py, append([]string{"../../../scripts/q4-trace-check.py", dir, "--roots", "1"}, args...)...).CombinedOutput()
		return string(out), err
	}
	t.Run("the declared Byzantine root is the only equivocator", func(t *testing.T) {
		dir, self := write(t, false)
		out, err := run(dir, "--byzantine", "1", "--peer", "1="+self.String())
		require.NoError(t, err, out)
		require.Contains(t, out, `"verdict": "PASS"`)
	})
	t.Run("an undeclared equivocator fails", func(t *testing.T) {
		dir, self := write(t, false)
		out, err := run(dir, "--peer", "1="+self.String())
		require.Error(t, err)
		require.Contains(t, out, "equivocators")
	})
	t.Run("a delivery with other bytes fails", func(t *testing.T) {
		dir, self := write(t, true)
		out, err := run(dir, "--byzantine", "1", "--peer", "1="+self.String())
		require.Error(t, err)
		require.Contains(t, out, "other bytes")
	})
	// the per-row Byzantine windows: when each row armed its adapters and when it had cleared them
	window := func(t *testing.T, dir string, roots []int, shift time.Duration, width time.Duration) string {
		raw, err := os.ReadFile(filepath.Join(dir, "root1", "trace.jsonl"))
		require.NoError(t, err)
		var first time.Time
		for _, l := range bytes.Split(bytes.TrimSpace(raw), []byte("\n")) {
			var ev struct {
				Kind string    `json:"kind"`
				Time time.Time `json:"time"`
			}
			require.NoError(t, json.Unmarshal(l, &ev))
			if ev.Kind == "equivocate" {
				first = ev.Time
				break
			}
		}
		require.False(t, first.IsZero(), "the fixture produced no equivocation")
		start := first.Add(shift)
		line, err := json.Marshal(map[string]any{"tag": "row", "roots": roots, "from": start.Format(time.RFC3339Nano), "to": start.Add(width).Format(time.RFC3339Nano)})
		require.NoError(t, err)
		path := filepath.Join(dir, "windows.jsonl")
		require.NoError(t, os.WriteFile(path, append(line, '\n'), 0o600))
		return path
	}
	t.Run("an equivocation inside the window armed for its root passes", func(t *testing.T) {
		dir, self := write(t, false)
		out, err := run(dir, "--byzantine", "1", "--peer", "1="+self.String(), "--byz-windows", window(t, dir, []int{1}, -time.Second, time.Hour))
		require.NoError(t, err, out)
		require.Contains(t, out, `"verdict": "PASS"`)
		require.Contains(t, out, `"equivocated"`)
	})
	t.Run("an equivocation by a root the window did not arm fails", func(t *testing.T) {
		dir, self := write(t, false)
		out, err := run(dir, "--byzantine", "1", "--peer", "1="+self.String(), "--byz-windows", window(t, dir, []int{2}, -time.Second, time.Hour))
		require.Error(t, err)
		require.Contains(t, out, "outside every window armed for it")
		require.Contains(t, out, "armed but equivocated nothing")
	})
	t.Run("an equivocation after its window was cleared fails", func(t *testing.T) {
		dir, self := write(t, false)
		out, err := run(dir, "--byzantine", "1", "--peer", "1="+self.String(), "--byz-windows", window(t, dir, []int{1}, -time.Hour, time.Minute))
		require.Error(t, err)
		require.Contains(t, out, "outside every window armed for it")
	})
}
