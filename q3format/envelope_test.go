package q3format

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// claimed fills the link's claim with the activation the history derives for it.
func (w *world) claimed(sp spec) Link {
	w.t.Helper()
	l := w.link(sp)
	next, err := w.h.WithV3(l)
	require.NoError(w.t, err)
	l.Claim = next.Tip().claim()
	return l
}

func envelopeOf(links ...Link) Envelope {
	return Envelope{RootInput: fill(1)[:8], Transitions: [][]byte{{1}, {2}}, TargetParent: fill(0x88), Links: links}
}

// rawEnvelope assembles an envelope's fields so a test can break exactly one of them.
func rawEnvelope(e Envelope, mutate func(f []any)) []byte {
	trans := make([]any, len(e.Transitions))
	for i, t := range e.Transitions {
		trans[i] = t
	}
	links := make([]any, len(e.Links))
	for i, l := range e.Links {
		links[i] = []any{l.Body.Encode(), l.Claim.items(), evidenceItems(l.Evidence), l.Proof, receiptItems(l.Receipts)}
	}
	var block any
	if len(e.BlockID) != 0 {
		block = e.BlockID
	}
	f := []any{envelopeDomain, uint64(EnvelopeVersion), e.RootInput, trans, e.TargetParent, block, links}
	if mutate != nil {
		mutate(f)
	}
	return enc(f...)
}

func TestEnvelopeRoundTrip(t *testing.T) {
	w := newWorld(t, 0)
	e := envelopeOf(w.claimed(spec{}))
	e.BlockID = fill(0x99)
	raw, err := e.Encode()
	require.NoError(t, err)
	got, err := DecodeEnvelope(raw)
	require.NoError(t, err)
	again, err := got.Encode()
	require.NoError(t, err)
	require.Equal(t, raw, again)
	require.Equal(t, e.Links[0].Claim, got.Links[0].Claim)
	require.Equal(t, e.Links[0].Evidence, got.Links[0].Evidence)
	require.Equal(t, e.Links[0].Receipts, got.Links[0].Receipts)
	require.Equal(t, e.Links[0].Proof, got.Links[0].Proof)
	require.Equal(t, e.Links[0].Body.Identity(), got.Links[0].Body.Identity())
	require.Equal(t, e.BlockID, got.BlockID)
	require.Equal(t, rawEnvelope(e, nil), raw, "the test assembler agrees with Encode")

	build, err := envelopeOf().Encode()
	require.NoError(t, err)
	got, err = DecodeEnvelope(build)
	require.NoError(t, err)
	require.Empty(t, got.BlockID, "a build job has no block")
	require.Empty(t, got.Links, "an envelope may only reference retained history")
}

func TestEnvelopeVector(t *testing.T) {
	raw, err := os.ReadFile("testdata/vectors.json")
	require.NoError(t, err)
	var want map[string]string
	require.NoError(t, json.Unmarshal(raw, &want))
	wire, err := hex.DecodeString(want["envelope"])
	require.NoError(t, err)
	got, err := DecodeEnvelope(wire)
	require.NoError(t, err)
	b := vectorBody(t)
	id := b.Identity()
	require.Equal(t, id, got.Links[0].Body.Identity())
	require.Equal(t, Claim{Epoch: 2, Start: 25, BodyID: id, CommitID: arr32(0x99), PriorVersion: 1, PriorID: arr32(0x11)}, got.Links[0].Claim)
	again, err := got.Encode()
	require.NoError(t, err)
	require.Equal(t, wire, again, "Go and the independent generator emit the same bytes")
}

func TestVerifyEnvelope(t *testing.T) {
	w := newWorld(t, 0)
	l := w.claimed(spec{})
	e := envelopeOf(l)

	h, err := w.h.VerifyEnvelope(e)
	require.NoError(t, err)
	require.Equal(t, uint64(2), h.Tip().Epoch())
	require.Equal(t, uint64(1), w.h.Tip().Epoch(), "the verified history is not touched")
	require.Equal(t, l.Claim, h.Tip().claim())

	t.Run("a link for a retained epoch is a reference", func(t *testing.T) {
		again, err := h.VerifyEnvelope(e)
		require.NoError(t, err)
		require.Equal(t, h.Tip().claim(), again.Tip().claim())
		require.Len(t, again.entries, 2, "nothing is appended twice")
		empty, err := w.h.VerifyEnvelope(envelopeOf())
		require.NoError(t, err)
		require.Equal(t, w.h, empty)
	})
	t.Run("conflict with a retained epoch", func(t *testing.T) {
		w2 := newWorld(t, 0)
		w2.h = w.h
		w2.signers[1] = w.signers[1]
		other := w2.claimed(spec{activate: 26})
		_, err := h.VerifyEnvelope(envelopeOf(other))
		require.ErrorIs(t, err, ErrConflict)
		for name, mutate := range map[string]func(*Claim){
			"start":  func(c *Claim) { c.Start++ },
			"commit": func(c *Claim) { c.CommitID = arr32(1) },
		} {
			bad := l
			mutate(&bad.Claim)
			_, err := h.VerifyEnvelope(envelopeOf(bad))
			require.ErrorIs(t, err, ErrConflict, name)
		}
	})
	t.Run("the claim must be the derived activation", func(t *testing.T) {
		for name, mutate := range map[string]func(*Claim){
			"epoch":         func(c *Claim) { c.Epoch++ },
			"start":         func(c *Claim) { c.Start++ },
			"body":          func(c *Claim) { c.BodyID = arr32(1) },
			"commit id":     func(c *Claim) { c.CommitID = arr32(1) },
			"prior version": func(c *Claim) { c.PriorVersion = 2 },
			"prior id":      func(c *Claim) { c.PriorID = arr32(1) },
		} {
			bad := l
			mutate(&bad.Claim)
			_, err := w.h.VerifyEnvelope(envelopeOf(bad))
			require.ErrorIs(t, err, ErrBinding, name)
		}
	})
	t.Run("missing and unauthenticated history", func(t *testing.T) {
		skip := w.link(spec{body: func(b *BodyV3) { b.Epoch = 3 }})
		_, err := w.h.VerifyEnvelope(envelopeOf(skip))
		require.ErrorIs(t, err, ErrMissingHistory, "a segment cannot start above the verified tip: it is never an anchor")
		bad := l
		bad.Proof = bytes.Clone(l.Proof)
		bad.Proof[len(bad.Proof)-1] ^= 1
		_, err = w.h.VerifyEnvelope(envelopeOf(bad))
		require.ErrorIs(t, err, ErrFormat, "a corrupted proof is not canonical")
		require.NotErrorIs(t, err, ErrActivation)
		forged := w.link(spec{signedBy: []string{"a"}}) // well-formed, but one of four is not the old committee's quorum
		_, err = w.h.VerifyEnvelope(envelopeOf(forged))
		require.ErrorIs(t, err, ErrActivation, "an unauthenticated proof")
		require.NotErrorIs(t, err, ErrFormat)
	})
}

func TestEnvelopeDecodeRefusals(t *testing.T) {
	w := newWorld(t, 0)
	l := w.claimed(spec{})
	e := envelopeOf(l)
	good := rawEnvelope(e, nil)
	_, err := DecodeEnvelope(good)
	require.NoError(t, err, "acceptance control")

	t.Run("bytes", func(t *testing.T) {
		_, err := DecodeEnvelope(append(bytes.Clone(good), 0))
		require.ErrorIs(t, err, ErrFormat)
		for _, n := range []int{0, 1, len(good) / 2, len(good) - 1} {
			_, err := DecodeEnvelope(good[:n])
			require.ErrorIs(t, err, ErrFormat, "%d bytes", n)
		}
		_, err = DecodeEnvelope(make([]byte, MaxEnvelopeBytes+1))
		require.ErrorIs(t, err, ErrTooLarge)
	})
	t.Run("version and domain", func(t *testing.T) {
		_, err := DecodeEnvelope(rawEnvelope(e, func(f []any) { f[1] = uint64(2) }))
		require.ErrorIs(t, err, ErrVersion)
		_, err = DecodeEnvelope(rawEnvelope(e, func(f []any) { f[0] = "UNICITY_Q3_EXECUTION_PROOF_V2" }))
		require.ErrorIs(t, err, ErrVersion)
	})
	t.Run("limits", func(t *testing.T) {
		for name, mutate := range map[string]func([]any){
			"root input":     func(f []any) { f[2] = make([]byte, maxRootInput+1) },
			"transitions":    func(f []any) { f[3] = make([]any, MaxTransitions+1) },
			"one transition": func(f []any) { f[3] = []any{make([]byte, maxTransition+1)} },
			"links":          func(f []any) { f[6] = make([]any, MaxLinks+1) },
			"proof":          func(f []any) { f[6].([]any)[0].([]any)[3] = make([]byte, MaxOldCommitProof+1) },
			"receipts":       func(f []any) { f[6].([]any)[0].([]any)[4] = make([]any, MaxMembers+1) },
			"evidence":       func(f []any) { f[6].([]any)[0].([]any)[2].([]any)[0] = make([]byte, maxEvidence+1) },
			"body":           func(f []any) { f[6].([]any)[0].([]any)[0] = make([]byte, maxBodyLen+1) },
			"target parent":  func(f []any) { f[4] = fill(1)[:31] },
			"block identity": func(f []any) { f[5] = fill(1)[:31] },
		} {
			_, err := DecodeEnvelope(rawEnvelope(e, mutate))
			if name == "target parent" || name == "block identity" {
				require.ErrorIs(t, err, ErrFormat, name)
				continue
			}
			require.ErrorIs(t, err, ErrTooLarge, name)
		}
	})
	t.Run("shape", func(t *testing.T) {
		for name, mutate := range map[string]func([]any){
			"six fields":    func(f []any) { f[6] = nil },
			"link of six":   func(f []any) { l := f[6].([]any); l[0] = append(l[0].([]any), uint64(0)) },
			"claim of 7":    func(f []any) { l := f[6].([]any)[0].([]any); l[1] = append(l[1].([]any), uint64(0)) },
			"evidence of 4": func(f []any) { l := f[6].([]any)[0].([]any); l[2] = append(l[2].([]any), []byte{1}) },
			"claim arity":   func(f []any) { l := f[6].([]any)[0].([]any); l[1] = l[1].([]any)[:5] },
			"link arity":    func(f []any) { f[6].([]any)[0] = f[6].([]any)[0].([]any)[:4] },
			"proof kind":    func(f []any) { f[6].([]any)[0].([]any)[3] = "x" },
			"claim kind":    func(f []any) { f[6].([]any)[0].([]any)[1].([]any)[0] = "x" },
			"receipt kind":  func(f []any) { f[6].([]any)[0].([]any)[4] = []any{[]any{uint64(1), []byte{1}}} },
		} {
			_, err := DecodeEnvelope(rawEnvelope(e, mutate))
			require.ErrorIs(t, err, ErrFormat, name)
		}
		_, err := DecodeEnvelope(enc(envelopeDomain, uint64(1), e.RootInput, []any{}, e.TargetParent, nil, []any{}, uint64(0)))
		require.ErrorIs(t, err, ErrFormat, "a trailing field")
	})
	t.Run("embedded body", func(t *testing.T) {
		b := l.Body
		b.RootThreshold = 8
		bad := e
		bad.Links = []Link{l}
		bad.Links[0].Body = b
		_, err := DecodeEnvelope(rawEnvelope(bad, nil))
		require.ErrorIs(t, err, ErrBody)
	})
	t.Run("links are consecutive epochs", func(t *testing.T) {
		at := func(epoch uint64) Link {
			x := l
			x.Body.Epoch = epoch
			return x
		}
		for name, links := range map[string][]Link{
			"repeated":    {at(2), at(2)},
			"skipping":    {at(2), at(4)},
			"descending":  {at(3), at(2)},
			"conflicting": {at(2), func() Link { x := at(2); x.Body.EarliestActivation++; return x }()},
		} {
			_, err := DecodeEnvelope(rawEnvelope(envelopeOf(links...), nil))
			require.ErrorIs(t, err, ErrEnvelope, name)
		}
		_, err := DecodeEnvelope(rawEnvelope(envelopeOf(at(2), at(3), at(4)), nil))
		require.NoError(t, err, "acceptance control")
	})
	t.Run("encode refuses what decode refuses", func(t *testing.T) {
		bad := envelopeOf(l)
		bad.TargetParent = fill(1)[:5]
		_, err := bad.Encode()
		require.ErrorIs(t, err, ErrFormat)
		many := envelopeOf()
		many.Links = make([]Link, MaxLinks+1)
		_, err = many.Encode()
		require.ErrorIs(t, err, ErrTooLarge)
		many = envelopeOf()
		many.Transitions = make([][]byte, MaxTransitions+1)
		_, err = many.Encode()
		require.ErrorIs(t, err, ErrTooLarge)
	})
}

// The limits against maximum-size valid fixtures: 64 links of realistic proofs fit the 16 MiB envelope; 64 links of
// maximum-size proofs do not, so the per-proof and per-envelope limits are only consistent while proofs stay small.
func TestEnvelopeLimitsAgainstMaximumFixtures(t *testing.T) {
	w := newWorld(t, 0)
	base := w.claimed(spec{})
	links := func(proof int) []Link {
		out := make([]Link, MaxLinks)
		for i := range out {
			out[i] = base
			out[i].Body.Epoch = uint64(2 + i)
			out[i].Proof = bytes.Repeat([]byte{7}, proof)
		}
		return out
	}
	e := envelopeOf(links(200 << 10)...)
	raw, err := e.Encode()
	require.NoError(t, err)
	require.Less(t, len(raw), MaxEnvelopeBytes)
	got, err := DecodeEnvelope(raw)
	require.NoError(t, err)
	require.Len(t, got.Links, MaxLinks)

	_, err = envelopeOf(links(MaxOldCommitProof)...).Encode()
	require.ErrorIs(t, err, ErrTooLarge, "64 maximum-size proofs exceed the envelope limit")
	one := envelopeOf(links(MaxOldCommitProof)[:1]...)
	_, err = one.Encode()
	require.NoError(t, err, "one maximum-size proof is allowed")
}
