package q3format

import (
	"bytes"
	"crypto"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/handoff"
	testtrustbase "github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	"github.com/unicitynetwork/bft-core/m2contract"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"
)

type signers map[string]abcrypto.Signer

func newSigners(t *testing.T, ids ...string) signers {
	t.Helper()
	out := signers{}
	for _, id := range ids {
		s, err := abcrypto.NewInMemorySecp256K1Signer()
		require.NoError(t, err)
		out[id] = s
	}
	return out
}

func (s signers) key(t *testing.T, id string) []byte {
	v, err := s[id].Verifier()
	require.NoError(t, err)
	k, err := v.MarshalPublicKey()
	require.NoError(t, err)
	return k
}

// genesisTB is a signed unit epoch-1 trust base of the given committee, starting at round start.
func genesisTB(t *testing.T, s signers, start uint64) *types.RootTrustBaseV1 {
	t.Helper()
	var nodes []*types.NodeInfo
	for id, sg := range s {
		v, err := sg.Verifier()
		require.NoError(t, err)
		nodes = append(nodes, testtrustbase.NewNodeInfoFromVerifier(t, id, v))
	}
	tb, err := types.NewTrustBase(testNetwork, nodes, types.WithEpochStart(start))
	require.NoError(t, err)
	for id, sg := range s {
		require.NoError(t, tb.Sign(id, sg))
	}
	return tb
}

// commitProof builds an old-committee commit proof for rec, signed by the named members of tb.
func commitProof(t *testing.T, tb *types.RootTrustBaseV1, s signers, rec evmroot.OrderedHandoffRecord, signedBy ...string) handoff.OldCommitProof {
	t.Helper()
	net := tb.NetworkID
	parent, err := storage.NewGenesisBlock(net, crypto.SHA256, storage.ProfileHandoff)
	require.NoError(t, err)
	zero := make([]byte, 32)
	steps := []struct {
		round       uint64
		kind, phase string
		frozen, tr  []byte
	}{{2, "prepare", "prepared", zero, zero}, {3, "freeze", "frozen", rec.FrozenID, zero}, {4, rec.Kind, map[string]string{"commit": "committed", "freeze": "frozen"}[rec.Kind], rec.FrozenID, rec.SuccessorTRHash}}
	for _, st := range steps {
		ordered := rec
		ordered.OrderedRound, ordered.Kind, ordered.FrozenID, ordered.SuccessorTRHash = st.round, st.kind, st.frozen, st.tr
		previous := parent.ShardState.Control
		parent.ShardState.Control = &evmroot.ControlState{Network: rec.Network, Epoch: rec.Epoch, PredecessorBodyID: rec.PredecessorBodyID,
			Attempt: rec.Attempt, Phase: st.phase, OrderedRound: st.round, RecordBytes: ordered.Bytes(), PreviousDigest: previous.Digest()}
	}
	control := *parent.ShardState.Control
	tree, _, err := parent.ShardState.UnicityTree(crypto.SHA256)
	require.NoError(t, err)
	path, err := tree.Certificate(evmroot.D4ControlPartition)
	require.NoError(t, err)
	stamp := types.NewTimestamp()
	vote := &rctypes.RoundInfo{Version: 1, RoundNumber: 5, Epoch: rec.Epoch, Timestamp: stamp, ParentRoundNumber: 4, CurrentRootHash: tree.RootHash()}
	voteHash, err := vote.Hash(crypto.SHA256)
	require.NoError(t, err)
	seal := &types.UnicitySeal{Version: 1, NetworkID: net, RootChainRoundNumber: 4, Epoch: rec.Epoch, Timestamp: stamp, Hash: tree.RootHash(), PreviousHash: voteHash}
	signed, err := seal.SigBytes()
	require.NoError(t, err)
	qc := &rctypes.QuorumCert{VoteInfo: vote, LedgerCommitInfo: seal, Signatures: map[string]hex.Bytes{}}
	for _, id := range signedBy {
		sig, err := s[id].SignBytes(signed)
		require.NoError(t, err)
		qc.Signatures[id] = sig
	}
	return handoff.OldCommitProof{Profile: evmroot.D4Profile, Record: rec, Control: control, ControlPath: path, CommitQC: qc}
}

// world is a history and the signers of each of its committees.
type world struct {
	t       *testing.T
	h       *History
	signers map[uint64]signers
}

func newWorld(t *testing.T, start uint64) *world {
	s := newSigners(t, "a", "b", "c", "d")
	h, err := NewHistory(genesisTB(t, s, start))
	require.NoError(t, err)
	return &world{t: t, h: h, signers: map[uint64]signers{1: s}}
}

// spec shapes one link; every hook runs before the thing it changes is hashed or signed.
type spec struct {
	body      func(*BodyV3)
	record    func(*evmroot.OrderedHandoffRecord)
	evidence  func(*Evidence)
	proof     func(*handoff.OldCommitProof)
	receipts  func([]Receipt) []Receipt
	signedBy  []string
	activate  uint64
	aMin      uint64
	committee signers
}

func (w *world) link(sp spec) Link {
	t, tip := w.t, w.h.Tip()
	if sp.activate == 0 {
		sp.activate = 25
	}
	if sp.aMin == 0 {
		sp.aMin = 20
	}
	if sp.signedBy == nil {
		sp.signedBy = []string{"a", "b", "c"}
	}
	next := sp.committee
	if next == nil {
		next = newSigners(t, "n1", "n2", "n3", "n4")
	}
	w.signers[tip.epoch+1] = next
	prior, err := Prior{Network: w.h.network, Epoch: tip.epoch, BodyVersion: tip.version, Identity: tip.bodyID[:]}.Hash()
	require.NoError(t, err)
	b := BodyV3{Network: w.h.network, Epoch: tip.epoch + 1, EarliestActivation: sp.aMin, RootThreshold: 7, StateSummary: fill(0x22), PredecessorHash: prior,
		Config: Q3Config(w.h.network, w.h.genesis)}
	for i, id := range []string{"n1", "n2", "n3", "n4"} {
		b.Members = append(b.Members, evmroot.Member{StakingID: "s" + id, NodeID: id, ConsensusKey: next.key(t, id), Weight: []uint64{6, 1, 1, 1}[i]})
	}
	ev := Evidence{Summary: fill(0x55), FrozenParent: fill(0x66), CandidateDigest: fill(0x44)}
	if sp.evidence != nil {
		sp.evidence(&ev)
	}
	const attempt = 3
	b.ChangeRecordHash = evmroot.D4CandidateContextHash(w.h.network, tip.bodyID[:], attempt, fill(0x44), b.EarliestActivation)
	if sp.body != nil {
		sp.body(&b)
	}
	id := b.Identity()
	rec := evmroot.OrderedHandoffRecord{Network: w.h.network, Epoch: tip.epoch, Attempt: attempt, OrderedRound: 4, ActivationRound: sp.activate,
		PredecessorBodyID: tip.bodyID[:], NextBodyID: id[:], SuccessorTRHash: fill(0x77), Kind: "commit",
		FrozenID: evmroot.D4FrozenID(id[:], fill(0x55), fill(0x66), fill(0x44), attempt, tip.bodyID[:])}
	if sp.record != nil {
		sp.record(&rec)
	}
	p := commitProof(t, tip.tb, w.signers[tip.epoch], rec, sp.signedBy...)
	if sp.proof != nil {
		sp.proof(&p)
	}
	raw, err := types.Cbor.Marshal(p)
	require.NoError(t, err)
	ctx := ContextFor(b, attempt, arr32(0x44))
	var rs []Receipt
	for _, m := range b.Members {
		r, err := SignReceipt(ctx, m.NodeID, next[m.NodeID])
		require.NoError(t, err)
		rs = append(rs, r)
	}
	if sp.receipts != nil {
		rs = sp.receipts(rs)
	}
	return Link{Body: b, Evidence: ev, Proof: raw, Receipts: rs}
}

func (w *world) append(sp spec) *History {
	w.t.Helper()
	next, err := w.h.WithV3(w.link(sp))
	require.NoError(w.t, err)
	return next
}

func TestWithV3MintsTheActivation(t *testing.T) {
	w := newWorld(t, 0)
	l := w.link(spec{})
	h, err := w.h.WithV3(l)
	require.NoError(t, err)
	e := h.Tip()
	require.Equal(t, uint64(2), e.Epoch())
	require.Equal(t, uint64(25), e.Start())
	require.Equal(t, uint64(3), e.Version())
	require.Equal(t, uint64(2), e.Scheme())
	require.Equal(t, l.Body.Identity(), e.BodyID())
	cfg, ok := e.Config()
	require.True(t, ok)
	require.Equal(t, l.Body.Config, cfg)
	epoch, round := e.Anchor()
	require.Equal(t, [2]uint64{2, 24}, [2]uint64{epoch, round}, "the successor is anchored at (E, A*-1)")
	require.NotEqual(t, [32]byte{}, e.ActivationCommitID())
	require.NotEqual(t, e.BodyID(), e.AnchorID(), "the epoch-anchor id is neither the body identity nor the tuple identity")
	require.NotEqual(t, cfg.Identity(), e.AnchorID())
	require.Equal(t, uint64(1), w.h.Tip().Epoch(), "the history it extended is untouched")

	// the claim and the anchor are derived again here, from the proof and the genesis, not read back from the code under test
	p, err := decodeProof(l.Proof)
	require.NoError(t, err)
	genesisID := w.h.Genesis()
	body := l.Body.Identity()
	require.Equal(t, Claim{Epoch: 2, Start: 25, BodyID: body, CommitID: [32]byte(p.Record.ID()), PriorVersion: 1, PriorID: genesisID}, e.claim())
	require.Equal(t, [32]byte(p.Record.ID()), e.ActivationCommitID())
	anchor := evmroot.EpochGenesis{Network: testNetwork, Epoch: 2, Start: 25, OrderedRound: p.Record.OrderedRound, NextBodyID: body[:], RecordID: p.Record.ID(),
		Root: p.CommitQC.LedgerCommitInfo.Hash, ControlDigest: p.Control.Digest(), FrozenID: p.Record.FrozenID, SuccessorTRHash: p.Record.SuccessorTRHash}
	require.Equal(t, [32]byte(anchor.ID()), e.AnchorID())

	g, err := h.ForEpoch(1)
	require.NoError(t, err)
	require.Equal(t, uint64(1), g.Scheme(), "legacy history is explicit scheme 1")
	_, ok = g.Config()
	require.False(t, ok)
}

func TestResolver(t *testing.T) {
	w := newWorld(t, 0)
	h := w.append(spec{})
	_, err := h.ForEpoch(3)
	require.ErrorIs(t, err, ErrUnknownEpoch)
	_, err = h.ForEpoch(0)
	require.ErrorIs(t, err, ErrUnknownEpoch)
	for round, want := range map[uint64]uint64{0: 1, 24: 1, 25: 2, 1 << 40: 2} {
		e, err := h.ForRound(round)
		require.NoError(t, err)
		require.Equal(t, want, e.Epoch(), "round %d", round)
	}
	late := newWorld(t, 30).h
	_, err = late.ForRound(29)
	require.ErrorIs(t, err, ErrUnknownEpoch, "before the genesis epoch's start nothing is covered")

	require.NoError(t, h.Ordinary(1, 24))
	require.NoError(t, h.Ordinary(2, 25))
	require.NoError(t, h.Ordinary(2, 1<<40))
	require.ErrorIs(t, h.Ordinary(1, 25), ErrOutsideInterval, "ordinary old work after the boundary")
	require.ErrorIs(t, h.Ordinary(2, 24), ErrOutsideInterval, "successor work before A*")
	require.ErrorIs(t, h.Ordinary(3, 100), ErrUnknownEpoch)
	require.Equal(t, w.h.network, h.Network())
	require.Equal(t, w.h.genesis, h.Genesis())
	g, err := h.ForEpoch(1)
	require.NoError(t, err)
	epoch, round := g.Anchor()
	require.Equal(t, [2]uint64{1, 0}, [2]uint64{epoch, round}, "the genesis epoch has no predecessor to anchor on")
}

func TestActivationRefusals(t *testing.T) {
	w := newWorld(t, 0)
	_, err := w.h.WithV3(w.link(spec{}))
	require.NoError(t, err, "acceptance control")

	other := func(b byte) []byte { return fill(b) }
	for name, tc := range map[string]struct {
		sp   spec
		want error
		msg  string // when set, the refusal must be this one and not another overlapping check
	}{
		// the committed record must be the previous committee's commit
		"uncommitted freeze record": {spec{record: func(r *evmroot.OrderedHandoffRecord) { r.Kind = "freeze" }}, ErrActivation, ""},
		"quorum by weight is short": {spec{signedBy: []string{"a", "b"}}, ErrActivation, ""},
		"unknown signers": {spec{signedBy: []string{"a", "b", "c"}, proof: func(p *handoff.OldCommitProof) {
			s := newSigners(t, "a", "b", "c")
			signed, err := p.CommitQC.LedgerCommitInfo.SigBytes()
			require.NoError(t, err)
			for id, sg := range s {
				p.CommitQC.Signatures[id], err = sg.SignBytes(signed)
				require.NoError(t, err)
			}
		}}, ErrActivation, ""},
		"forged control leaf": {spec{proof: func(p *handoff.OldCommitProof) { p.Control.PreviousDigest = other(1) }}, ErrActivation, ""},
		"record epoch":        {spec{record: func(r *evmroot.OrderedHandoffRecord) { r.Epoch = 2 }}, ErrActivation, ""},
		"record network":      {spec{record: func(r *evmroot.OrderedHandoffRecord) { r.Network = 6 }}, ErrActivation, ""},
		// the authenticated record must bind what it is presented with
		"another body": {spec{record: func(r *evmroot.OrderedHandoffRecord) { r.NextBodyID = other(1) }}, ErrBinding, "another body"},
		"another predecessor": {spec{body: func(b *BodyV3) {
			b.ChangeRecordHash = evmroot.D4CandidateContextHash(b.Network, other(1), 3, fill(0x44), b.EarliestActivation)
		}, record: func(r *evmroot.OrderedHandoffRecord) {
			r.PredecessorBodyID = other(1)
			r.FrozenID = evmroot.D4FrozenID(r.NextBodyID, fill(0x55), fill(0x66), fill(0x44), 3, other(1))
		}}, ErrBinding, "another predecessor"},
		"A* before A_min":   {spec{activate: 19}, ErrBinding, "before A_min"},
		"another frozen id": {spec{record: func(r *evmroot.OrderedHandoffRecord) { r.FrozenID = other(1) }}, ErrBinding, "frozen identity"},
		"another summary":   {spec{evidence: func(e *Evidence) { e.Summary = other(1) }}, ErrBinding, "frozen identity"},
		"another parent":    {spec{evidence: func(e *Evidence) { e.FrozenParent = other(1) }}, ErrBinding, "frozen identity"},
		"another candidate": {spec{body: func(b *BodyV3) {
			b.ChangeRecordHash = evmroot.D4CandidateContextHash(b.Network, b.PredecessorHash, 3, other(1), b.EarliestActivation)
		}}, ErrBinding, "candidate context"},
		"another attempt": {spec{body: func(b *BodyV3) {
			tip := w.h.Tip()
			b.ChangeRecordHash = evmroot.D4CandidateContextHash(b.Network, tip.bodyID[:], 4, fill(0x44), b.EarliestActivation)
		}}, ErrBinding, "candidate context"},
		"short candidate": {spec{evidence: func(e *Evidence) { e.CandidateDigest = e.CandidateDigest[:31] }}, ErrBinding, "incomplete or oversize"},
		"no summary":      {spec{evidence: func(e *Evidence) { e.Summary = nil }}, ErrBinding, "incomplete or oversize"},
		"no parent":       {spec{evidence: func(e *Evidence) { e.FrozenParent = nil }}, ErrBinding, "incomplete or oversize"},
		"long summary":    {spec{evidence: func(e *Evidence) { e.Summary = make([]byte, maxField+1) }}, ErrBinding, "incomplete or oversize"},
		"long parent":     {spec{evidence: func(e *Evidence) { e.FrozenParent = make([]byte, maxField+1) }}, ErrBinding, "incomplete or oversize"},
		// the authority decides the network, not the link
		"network":        {spec{body: func(b *BodyV3) { b.Network, b.Config = 6, Q3Config(6, b.Config.Genesis) }}, ErrNetwork, ""},
		"tuple network":  {spec{body: func(b *BodyV3) { b.Config = Q3Config(6, b.Config.Genesis) }}, ErrBody, ""},
		"genesis":        {spec{body: func(b *BodyV3) { b.Config.Genesis = arr32(9) }}, ErrGenesis, ""},
		"predecessor":    {spec{body: func(b *BodyV3) { b.PredecessorHash = fill(1) }}, ErrPrior, ""},
		"epoch gap":      {spec{body: func(b *BodyV3) { b.Epoch = 3 }}, ErrMissingHistory, ""},
		"epoch repeated": {spec{body: func(b *BodyV3) { b.Epoch = 1 }}, ErrBody, ""},
		"invalid body":   {spec{body: func(b *BodyV3) { b.RootThreshold = 8 }}, ErrBody, ""},
		// readiness
		"missing receipt":   {spec{receipts: func(r []Receipt) []Receipt { return r[:3] }}, ErrReceiptMissing, ""},
		"duplicate receipt": {spec{receipts: func(r []Receipt) []Receipt { return append(r, r[0]) }}, ErrReceiptDuplicate, ""},
	} {
		_, err := w.h.WithV3(w.link(tc.sp))
		require.ErrorIs(t, err, tc.want, name)
		if tc.msg != "" {
			require.ErrorContains(t, err, tc.msg, name)
		}
	}
	_, err = w.h.WithV3(w.link(spec{activate: 20}))
	require.NoError(t, err, "A* equal to A_min is allowed")
	// the refusals are isolated: the committed-record refusals are not binding refusals
	_, err = w.h.WithV3(w.link(spec{signedBy: []string{"a", "b"}}))
	require.NotErrorIs(t, err, ErrBinding)
	_, err = w.h.WithV3(w.link(spec{record: func(r *evmroot.OrderedHandoffRecord) { r.Kind = "freeze" }}))
	require.ErrorIs(t, err, handoff.ErrProof, "the verifier's own refusal is kept")
}

func TestActivationProofShape(t *testing.T) {
	w := newWorld(t, 0)
	l := w.link(spec{})
	for name, tc := range map[string]struct {
		proof []byte
		want  error
	}{
		"empty":        {nil, ErrTooLarge},
		"oversize":     {make([]byte, MaxOldCommitProof+1), ErrTooLarge},
		"not cbor":     {[]byte{0xff, 0xff}, ErrFormat},
		"trailing":     {append(bytes.Clone(l.Proof), 0), ErrFormat},
		"noncanonical": {append([]byte{0x9b, 0, 0, 0, 0, 0, 0, 0, 7}, l.Proof[1:]...), ErrFormat},
	} {
		bad := l
		bad.Proof = tc.proof
		_, err := w.h.WithV3(bad)
		require.ErrorIs(t, err, tc.want, name)
	}
}

func TestActivationNeedsAStartAfterTheEpochStart(t *testing.T) {
	w := newWorld(t, 30) // the genesis epoch starts at 30; A* = 25 is after A_min but not after 30
	_, err := w.h.WithV3(w.link(spec{}))
	require.ErrorIs(t, err, ErrBinding)
	w2 := newWorld(t, 24)
	_, err = w2.h.WithV3(w2.link(spec{}))
	require.NoError(t, err, "acceptance control: 25 > 24")
	w3 := newWorld(t, 25)
	_, err = w3.h.WithV3(w3.link(spec{}))
	require.ErrorIs(t, err, ErrBinding, "A* equal to the epoch start is not after it")
}

func TestNoFallbackToSchemeOne(t *testing.T) {
	w := newWorld(t, 0)
	w.h = w.append(spec{})
	require.Equal(t, uint64(2), w.h.Tip().Scheme())
	l := w.link(spec{aMin: 21, activate: 40, signedBy: []string{"n1", "n2"}})
	_, err := w.h.WithV3(l)
	require.ErrorIs(t, err, ErrScheme, "a scheme-2 epoch has no commit verifier yet, and scheme 1 is not substituted")
	_, err = w.h.WithV2(evmroot.TrustBaseBodyV2{}, nil)
	require.ErrorIs(t, err, ErrHistory, "no V2 epoch follows V3")
}

func TestStartingAHistory(t *testing.T) {
	s := newSigners(t, "a", "b", "c", "d")
	g := genesisTB(t, s, 0)
	_, err := NewHistory(g)
	require.NoError(t, err, "acceptance control")
	_, err = NewHistory(nil)
	require.ErrorIs(t, err, ErrHistory)
	late := genesisTB(t, s, 0)
	late.Epoch = 2
	_, err = NewHistory(late)
	require.ErrorIs(t, err, ErrHistory, "only the epoch-1 genesis starts a history")
	unsigned := genesisTB(t, s, 0)
	unsigned.Signatures = map[string]hex.Bytes{}
	_, err = NewHistory(unsigned)
	require.ErrorIs(t, err, ErrHistory)
	weighted := genesisTB(t, s, 0)
	weighted.RootNodes[0].Stake = 2
	_, err = NewHistory(weighted)
	require.ErrorIs(t, err, ErrHistory, "the genesis is a unit committee")
	h, err := NewHistory(g)
	require.NoError(t, err)
	id, err := g.Hash(crypto.SHA256)
	require.NoError(t, err)
	genesisID := h.Genesis()
	require.Equal(t, id, genesisID[:])
	require.Equal(t, uint64(testNetwork), h.Network())
}

// v2 is a V2 successor of the world's tip, unit weights of a new committee, with its commit proof signed by signedBy.
func (w *world) v2(second signers, aMin, activate uint64, signedBy ...string) (evmroot.TrustBaseBodyV2, []byte) {
	t, tip := w.t, w.h.Tip()
	var members evmroot.WeightSet
	for _, id := range []string{"e", "f", "g", "h"} {
		members = append(members, evmroot.Member{StakingID: id, NodeID: id, ConsensusKey: second.key(t, id), Weight: 1})
	}
	pred := tip.bodyID[:]
	if tip.version == 1 {
		var err error
		pred, err = evmroot.FirstV2PredecessorHash(evmroot.V1Anchor{Version: 1, NetworkID: testNetwork, Epoch: 1, HashIncludingSigs: tip.bodyID[:]})
		require.NoError(t, err)
	}
	body := evmroot.TrustBaseBodyV2{Version: 2, NetworkID: testNetwork, Epoch: tip.epoch + 1, EarliestActivation: aMin, Members: members, RootThreshold: 3,
		StateSummary: fill(1), ChangeRecordHash: fill(2), PredecessorHash: pred}
	id := body.Identity()
	rec := evmroot.OrderedHandoffRecord{Network: testNetwork, Epoch: tip.epoch, Attempt: 1, OrderedRound: 4, ActivationRound: activate, PredecessorBodyID: tip.bodyID[:],
		NextBodyID: id[:], FrozenID: fill(3), SuccessorTRHash: fill(4), Kind: "commit"}
	raw, err := types.Cbor.Marshal(commitProof(t, tip.tb, w.signers[tip.epoch], rec, signedBy...))
	require.NoError(t, err)
	w.signers[tip.epoch+1] = second
	return body, raw
}

// A chain that already took a V2 handoff reaches its first V3 link through the existing verifier.
func TestV2ThenV3(t *testing.T) {
	w := newWorld(t, 0)
	second := newSigners(t, "e", "f", "g", "h")
	v2, raw := w.v2(second, 10, 12, "a", "b", "c")
	h, err := w.h.WithV2(v2, raw)
	require.NoError(t, err)
	require.Equal(t, [3]uint64{2, 12, 1}, [3]uint64{h.Tip().Epoch(), h.Tip().Start(), h.Tip().Scheme()})
	require.Equal(t, uint64(2), h.Tip().Version())

	t.Run("refusals", func(t *testing.T) {
		_, err := w.h.WithV2(v2, nil)
		require.ErrorIs(t, err, ErrTooLarge)
		bad := v2
		bad.Members = append(evmroot.WeightSet(nil), v2.Members...)
		bad.Members[0].Weight = 2
		_, err = w.h.WithV2(bad, raw)
		require.ErrorIs(t, err, m2contract.ErrNonUnitWeight)
		bad = v2
		bad.PredecessorHash = fill(9)
		_, err = w.h.WithV2(bad, raw)
		require.ErrorIs(t, err, ErrActivation)
		_, short := w.v2(second, 10, 12, "a", "b")
		_, err = w.h.WithV2(v2, short)
		require.ErrorIs(t, err, ErrActivation, "two of four unit signers are not a quorum")
		late := newWorld(t, 12)
		body, proof := late.v2(newSigners(t, "e", "f", "g", "h"), 10, 12, "a", "b", "c")
		_, err = late.h.WithV2(body, proof)
		require.ErrorIs(t, err, ErrBinding, "A* must follow the epoch start")
	})

	// the first V3 link over a V2 prior uses the tagged V2 predecessor
	w.h = h
	l := w.link(spec{signedBy: []string{"e", "f", "g"}, activate: 40, aMin: 30})
	prior, err := Prior{Network: testNetwork, Epoch: 2, BodyVersion: 2, Identity: func() []byte { id := v2.Identity(); return id[:] }()}.Hash()
	require.NoError(t, err)
	require.Equal(t, prior, l.Body.PredecessorHash)
	_, err = h.WithV3(w.link(spec{signedBy: []string{"e", "f", "g"}, body: func(b *BodyV3) { b.Epoch = 2 }}))
	require.ErrorIs(t, err, ErrHistory, "an epoch that does not follow the tip, neither a gap nor a V3 repeat")
	require.NotErrorIs(t, err, ErrMissingHistory)
	h3, err := h.WithV3(l)
	require.NoError(t, err)
	require.Equal(t, [3]uint64{3, 40, 2}, [3]uint64{h3.Tip().Epoch(), h3.Tip().Start(), h3.Tip().Scheme()})
	g1, _ := h3.ForEpoch(1)
	g2, _ := h3.ForEpoch(2)
	require.Equal(t, [2]uint64{1, 1}, [2]uint64{g1.Scheme(), g2.Scheme()})
}
