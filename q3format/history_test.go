package q3format

import (
	"bytes"
	"crypto"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/handoff"
	testtrustbase "github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
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

// commitProof builds a legacy (scheme 1) old-committee commit proof for rec, signed by the named members of tb.
func commitProof(t *testing.T, tb *types.RootTrustBaseV1, s signers, rec evmroot.OrderedHandoffRecord, signedBy ...string) handoff.OldCommitProof {
	t.Helper()
	return commitProofCfg(t, tb, s, rec, votesig.Config{}, signedBy...)
}

// commitProofCfg builds the commit proof by the rule of the old epoch's signing configuration: for scheme 2 a domain-bound
// certificate whose vote signatures are over PV and whose seal signatures are the same signers' over the native seal bytes.
func commitProofCfg(t *testing.T, tb *types.RootTrustBaseV1, s signers, rec evmroot.OrderedHandoffRecord, cfg votesig.Config, signedBy ...string) handoff.OldCommitProof {
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
	seal := &types.UnicitySeal{Version: 1, NetworkID: net, RootChainRoundNumber: 4, Epoch: rec.Epoch, Timestamp: stamp, Hash: tree.RootHash()}
	qc := &rctypes.QuorumCert{VoteInfo: vote, LedgerCommitInfo: seal, Signatures: map[string]hex.Bytes{}}
	if cfg.Scheme == votesig.SchemeDomainBound {
		vote.Timestamp = 0 // a scheme 2 vote info carries no timestamp
		vi := votesig.VoteInfo{Epoch: vote.Epoch, Round: vote.RoundNumber, Parent: vote.ParentRoundNumber}
		copy(vi.Exec[:], vote.CurrentRootHash)
		vh, err := cfg.VoteInfoHash(vi)
		require.NoError(t, err)
		seal.PreviousHash = vh[:]
		pv, sealBytes, _, err := rctypes.DomainBoundStatement(cfg, vote, seal, true)
		require.NoError(t, err)
		qc.Scheme, qc.SealSignatures = votesig.SchemeDomainBound, map[string]hex.Bytes{}
		for _, id := range signedBy {
			var err error
			if qc.Signatures[id], err = s[id].SignBytes(pv); err != nil {
				t.Fatal(err)
			}
			if qc.SealSignatures[id], err = s[id].SignBytes(sealBytes); err != nil {
				t.Fatal(err)
			}
		}
		return handoff.OldCommitProof{Profile: evmroot.D4Profile, Record: rec, Control: control, ControlPath: path, CommitQC: qc}
	}
	voteHash, err := vote.Hash(crypto.SHA256)
	require.NoError(t, err)
	seal.PreviousHash = voteHash
	signed, err := seal.SigBytes()
	require.NoError(t, err)
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
		sp.signedBy = []string{"a", "b", "c"} // a unit committee of four: three reach the threshold
		if tip.epoch > 1 {
			sp.signedBy = []string{"n1", "n2"} // weights (6,1,1,1), threshold 7: the heavy member and one light one
		}
	}
	oldCfg, err := w.h.Signing(tip.epoch)
	require.NoError(t, err)
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
	p := commitProofCfg(t, tip.tb, w.signers[tip.epoch], rec, oldCfg, sp.signedBy...)
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

// A second handoff is verified by the first activated epoch's own rule: scheme 2, weighted, strict about both signature maps.
// Every refusal differs from the accepted control in one thing only.
func TestSuccessiveHandoffUnderSchemeTwo(t *testing.T) {
	w := newWorld(t, 0)
	w.h = w.append(spec{})
	require.Equal(t, uint64(2), w.h.Tip().Scheme())

	l := w.link(spec{aMin: 30, activate: 40, committee: newSigners(t, "n1", "n2", "n3", "n4")})
	h, err := w.h.WithV3(l)
	require.NoError(t, err, "acceptance control: heavy plus one light is weight 7 of 9")
	require.Equal(t, [3]uint64{3, 40, 2}, [3]uint64{h.Tip().Epoch(), h.Tip().Start(), h.Tip().Scheme()})
	require.Equal(t, w.h.Tip().BodyID(), [32]byte(l.Body.PredecessorHash), "a V3 predecessor is named by its body identity directly")
	require.Equal(t, uint64(3), h.Tip().Version())
	epoch2, err := h.ForEpoch(2)
	require.NoError(t, err)
	require.Equal(t, w.h.Tip().Claim(), epoch2.Claim(), "the earlier epoch is untouched")
	l.Claim = h.Tip().Claim()
	again, err := h.VerifyEnvelope(Envelope{Links: []Link{l}})
	require.NoError(t, err, "a retained link is checked under the same rule")
	require.Equal(t, h.Tip().Claim(), again.Tip().Claim())

	refuse := func(name string, sp spec, want ...error) {
		t.Run(name, func(t *testing.T) {
			sp.aMin, sp.activate = 30, 40
			_, err := w.h.WithV3(w.link(sp))
			require.ErrorIs(t, err, ErrActivation)
			for _, e := range want {
				require.ErrorIs(t, err, e)
			}
		})
	}
	refuse("heavy alone is weight 6 of 7", spec{signedBy: []string{"n1"}}, handoff.ErrProof)
	refuse("three light members are weight 3", spec{signedBy: []string{"n2", "n3", "n4"}}, handoff.ErrProof)
	refuse("a signature of the wrong member", spec{signedBy: []string{"n1", "n2"}, proof: func(p *handoff.OldCommitProof) {
		p.CommitQC.Signatures["n2"], p.CommitQC.Signatures["n3"] = p.CommitQC.Signatures["n3"], p.CommitQC.Signatures["n2"]
	}}, handoff.ErrProof)
	refuse("the seal signatures are missing", spec{proof: func(p *handoff.OldCommitProof) { p.CommitQC.SealSignatures = nil }}, handoff.ErrProof)
	refuse("the signer sets differ", spec{signedBy: []string{"n1", "n2", "n3"}, proof: func(p *handoff.OldCommitProof) {
		delete(p.CommitQC.SealSignatures, "n3")
	}}, handoff.ErrProof, votesig.ErrSignerSets)
	refuse("a legacy-form certificate of a scheme 2 epoch", spec{proof: func(p *handoff.OldCommitProof) { p.CommitQC.Scheme = votesig.SchemeLegacy }}, handoff.ErrProof, votesig.ErrScheme)
	t.Run("the unit committee of the genesis epoch cannot sign for epoch 2", func(t *testing.T) {
		l := w.link(spec{aMin: 30, activate: 40, signedBy: []string{"n1", "n2"}})
		l.Proof = oldEpochProof(t, w, l)
		_, err := w.h.WithV3(l)
		require.ErrorIs(t, err, ErrActivation)
	})
	t.Run("a forged proof for a retained link is a conflict", func(t *testing.T) {
		bad := l
		p, err := decodeProof(l.Proof)
		require.NoError(t, err)
		p.CommitQC.Signatures = map[string]hex.Bytes{"n1": p.CommitQC.Signatures["n1"]}
		p.CommitQC.SealSignatures = map[string]hex.Bytes{"n1": p.CommitQC.SealSignatures["n1"]}
		bad.Proof, err = types.Cbor.Marshal(p)
		require.NoError(t, err)
		_, err = h.VerifyEnvelope(Envelope{Links: []Link{bad}})
		require.ErrorIs(t, err, ErrConflict)
		require.ErrorIs(t, err, ErrActivation)
	})
}

// oldEpochProof is the link's proof re-signed in scheme 1 by the genesis committee, which is not epoch 2's committee.
func oldEpochProof(t *testing.T, w *world, l Link) []byte {
	t.Helper()
	p, err := decodeProof(l.Proof)
	require.NoError(t, err)
	q := commitProof(t, w.h.Tip().tb, w.signers[1], p.Record, "a", "b", "c")
	raw, err := types.Cbor.Marshal(q)
	require.NoError(t, err)
	return raw
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

// A previous epoch whose scheme has no verifier here is refused, never verified as scheme 1.
func TestAnUnverifiableSchemeIsRefusedNotDefaulted(t *testing.T) {
	w := newWorld(t, 0)
	w.h = w.append(spec{})
	l := w.link(spec{aMin: 30, activate: 40})
	_, err := w.h.WithV3(l)
	require.NoError(t, err, "acceptance control")
	odd := w.h.Tip()
	cfg := *odd.config
	cfg.SigningScheme = 3
	odd.config = &cfg
	odds := &History{network: w.h.network, genesis: w.h.genesis, entries: []Entry{w.h.entries[0], odd}}
	_, err = odds.verifyCommit(odd, handoff.OldCommitProof{})
	require.ErrorIs(t, err, ErrScheme)
}
