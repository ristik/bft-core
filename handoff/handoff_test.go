package handoff

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/unicitynetwork/bft-core/evmroot"
)

var proof = []byte("proof")

type expected struct {
	id    [32]byte
	round uint64
}
type verifier struct {
	context      Context
	allowed      map[string]expected
	root, digest [32]byte
	seal         uint64
	deny         bool
}

func (v *verifier) result(kind string, id [32]byte, p []byte) (VerifiedRecord, error) {
	want, ok := v.allowed[kind]
	if v.deny || !ok || want.id != id || !bytes.Equal(p, proof) {
		return VerifiedRecord{}, ErrProof
	}
	return VerifiedRecord{Context: v.context, Kind: kind, RecordID: id, OrderRound: want.round, CommitSealRound: v.seal, StateRoot: v.root, ControlDigest: v.digest, SignerEpoch: v.context.Epoch}, nil
}
func (v *verifier) VerifyOrdered(_ Context, kind string, id [32]byte, p []byte) (VerifiedRecord, error) {
	return v.result(kind, id, p)
}
func (v *verifier) VerifyFinal(_ Context, id [32]byte, p []byte) (VerifiedRecord, error) {
	return v.result("commit", id, p)
}
func (v *verifier) VerifyEndorse(id [32]byte, p []byte) error {
	if v.deny || v.allowed["freeze"].id != id || !bytes.Equal(p, proof) {
		return ErrNoQuorum
	}
	return nil
}

type ackVerifier struct {
	context Context
	id      [32]byte
	deny    bool
}

func (a *ackVerifier) VerifyAck(_ Context, id [32]byte, p []byte) (VerifiedRecord, error) {
	if a.deny || a.id != id || !bytes.Equal(p, proof) {
		return VerifiedRecord{}, ErrProof
	}
	return VerifiedRecord{Context: a.context, Kind: "ack", RecordID: id, OrderRound: 10, CommitSealRound: 11, StateRoot: fill(0x44), ControlDigest: fill(0x55), SignerEpoch: a.context.Epoch + 1}, nil
}
func fill(x byte) [32]byte {
	var a [32]byte
	for i := range a {
		a[i] = x
	}
	return a
}
func must(t *testing.T, e error) {
	t.Helper()
	if e != nil {
		t.Fatal(e)
	}
}
func want(t *testing.T, e, target error) {
	t.Helper()
	if !errors.Is(e, target) {
		t.Fatalf("got %v, want %v", e, target)
	}
}

type setup struct {
	m        *Machine
	old      *verifier
	ackV     *ackVerifier
	body     evmroot.TrustBaseBodyV2
	freeze   FreezeRecord
	commit   CommitRecord
	ack      AckRecord
	verified evmroot.VerifiedHandoff
	genesis  evmroot.EpochGenesis
	snapshot evmroot.FullSnapshot
}

func fixture(t *testing.T) setup {
	t.Helper()
	c := Context{Network: 3, Epoch: 7, Attempt: 0, MinActivation: 10, Partition: 1, Shard: []byte{0}, Predecessor: fill(0xe7), Candidate: fill(0xca)}
	members := evmroot.WeightSet{{StakingID: "stake-a", NodeID: "root-a", ConsensusKey: append([]byte{2}, bytes.Repeat([]byte{1}, 32)...), Weight: 1}}
	body := evmroot.TrustBaseBodyV2{Version: evmroot.TrustBaseVersion, NetworkID: 3, Epoch: 8, EarliestActivation: 10, Members: members, RootThreshold: 1, StateSummary: bytes.Repeat([]byte{0x5a}, 32), ChangeRecordHash: bytes.Repeat([]byte{0x77}, 32), PredecessorHash: c.Predecessor[:]}
	bid := body.Identity()
	f := FreezeRecord{Context: c, Body: bid, Summary: fill(0x11), Parent: fill(0x22)}
	f.FrozenID = hash("UNICITY_HANDOFF_FROZEN", f.Body[:], f.Summary[:], f.Parent[:], c.Candidate[:], c.Attempt, c.Predecessor[:])
	r := CommitRecord{FrozenID: f.FrozenID, Body: f.Body, Round: 6, Activation: 10, SuccessorTR: fill(0x33)}
	r.ID = r.RecordID(c)
	a := AckRecord{FrozenID: f.FrozenID, CommitID: r.ID, FrozenParent: f.Parent, SuccessorParent: f.Parent, SuccessorTR: r.SuccessorTR, EVMRound: 41}
	rec := r.D4Record(c)
	ctl := evmroot.ControlState{Network: c.Network, Epoch: c.Epoch, Attempt: c.Attempt, OrderedRound: r.Round, PredecessorBodyID: c.Predecessor[:], Phase: "committed", RecordBytes: rec.Bytes(), PreviousDigest: bytes.Repeat([]byte{0x66}, 32)}
	s := evmroot.FullSnapshot{Control: ctl}
	root, e := s.Root()
	must(t, e)
	v := evmroot.VerifiedHandoff{RecordID: rec.ID(), Root: root, ControlDigest: ctl.Digest(), OrderRound: r.Round, CommitSealRound: 7, Epoch: c.Epoch, Record: rec, Snapshot: s}
	g, e := evmroot.DeriveEpochGenesis(v, body)
	must(t, e)
	ov := &verifier{context: c, allowed: map[string]expected{
		"prepare": {hash("UNICITY_HANDOFF_PREPARE", c.Candidate[:], c.Attempt), 1},
		"freeze":  {f.FrozenID, 2}, "commit": {r.ID, r.Round}, "abort": {hash("UNICITY_HANDOFF_ABORT", c.Candidate[:], c.Attempt), 3},
	}, seal: 7}
	copy(ov.root[:], root)
	copy(ov.digest[:], ctl.Digest())
	av := &ackVerifier{context: c, id: hash("UNICITY_HANDOFF_ACK_ID", a.CommitID[:], a.SuccessorParent[:], a.EVMRound)}
	return setup{New(c, ov, av), ov, av, body, f, r, a, v, g, s}
}
func (s setup) prepare(t *testing.T) { t.Helper(); must(t, s.m.Prepare(proof)) }
func (s setup) freezeStep(t *testing.T) {
	t.Helper()
	s.prepare(t)
	must(t, s.m.FreezeWith(s.freeze, s.body, s.freeze.Parent, proof))
}
func (s setup) endorse(t *testing.T) { t.Helper(); s.freezeStep(t); must(t, s.m.Endorse(proof)) }
func (s setup) commitStep(t *testing.T) {
	t.Helper()
	s.endorse(t)
	must(t, s.m.CommitWith(s.commit, proof))
}
func (s setup) finalized(t *testing.T) { t.Helper(); s.commitStep(t); must(t, s.m.Finalize(proof)) }
func (s setup) bootstrapped(t *testing.T) {
	t.Helper()
	s.finalized(t)
	must(t, s.m.Bootstrap(s.verified, s.body, s.genesis, s.snapshot))
}

func TestCommitRecordIDBindsOrderRound(t *testing.T) {
	s := fixture(t)
	s.endorse(t)
	r := s.commit
	r.Round++
	// The test verifier is configured for the changed round and the original ID.
	// Only the RecordID recomputation can reject this substitution.
	s.old.allowed["commit"] = expected{r.ID, r.Round}
	want(t, s.m.CommitWith(r, proof), ErrBody)
	if r.RecordID(s.m.Context) == r.ID {
		t.Fatal("order round omitted from ID")
	}
}
func TestTypedProofBindings(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*VerifiedRecord)
	}{
		{"kind", func(v *VerifiedRecord) { v.Kind = "abort" }},
		{"id", func(v *VerifiedRecord) { v.RecordID = fill(9) }},
		{"order", func(v *VerifiedRecord) { v.OrderRound++ }},
		{"seal", func(v *VerifiedRecord) { v.CommitSealRound = 0 }},
		{"root", func(v *VerifiedRecord) { v.StateRoot = [32]byte{} }},
		{"digest", func(v *VerifiedRecord) { v.ControlDigest = [32]byte{} }},
		{"epoch", func(v *VerifiedRecord) { v.SignerEpoch++ }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := fixture(t)
			s.commitStep(t)
			// The final verifier's returned fields are checked by a wrapper.
			w := &mutatingOld{verifier: s.old, change: tc.mutate}
			s.m.old = w
			want(t, s.m.Finalize(proof), ErrProof)
		})
	}
}

type mutatingOld struct {
	*verifier
	change func(*VerifiedRecord)
}

func (m *mutatingOld) VerifyFinal(c Context, id [32]byte, p []byte) (VerifiedRecord, error) {
	v, e := m.verifier.VerifyFinal(c, id, p)
	if e == nil {
		m.change(&v)
	}
	return v, e
}
func (m *mutatingOld) VerifyOrdered(c Context, kind string, id [32]byte, p []byte) (VerifiedRecord, error) {
	v, e := m.verifier.VerifyOrdered(c, kind, id, p)
	if e == nil {
		m.change(&v)
	}
	return v, e
}

type mutatingAck struct {
	*ackVerifier
	change func(*VerifiedRecord)
}

func (m *mutatingAck) VerifyAck(c Context, id [32]byte, p []byte) (VerifiedRecord, error) {
	v, e := m.ackVerifier.VerifyAck(c, id, p)
	if e == nil {
		m.change(&v)
	}
	return v, e
}

func TestCommitWithRejectsVerifierOrderRound(t *testing.T) {
	s := fixture(t)
	s.endorse(t)
	s.m.old = &mutatingOld{verifier: s.old, change: func(v *VerifiedRecord) { v.OrderRound-- }}
	want(t, s.m.CommitWith(s.commit, proof), ErrProof)
}

func TestAckTypedResultGuards(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*VerifiedRecord)
	}{
		{"signer_epoch", func(v *VerifiedRecord) { v.SignerEpoch++ }},
		{"kind", func(v *VerifiedRecord) { v.Kind = "commit" }},
		{"order_floor", func(v *VerifiedRecord) { v.OrderRound-- }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := fixture(t)
			s.bootstrapped(t)
			must(t, s.m.Activate(s.commit.Activation))
			s.m.ack = &mutatingAck{ackVerifier: s.ackV, change: tc.change}
			want(t, s.m.Acknowledge(s.ack, proof), ErrProof)
		})
	}
}

func TestBootstrapCanonicalFields(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*setup)
	}{
		{"genesis_network", func(s *setup) { s.genesis.Network++ }},
		{"genesis_order", func(s *setup) { s.genesis.OrderedRound++ }},
		{"genesis_control_digest", func(s *setup) { s.genesis.ControlDigest[0] ^= 1 }},
		{"genesis_successor_tr", func(s *setup) { s.genesis.SuccessorTRHash[0] ^= 1 }},
		{"genesis_frozen_id", func(s *setup) { s.genesis.FrozenID[0] ^= 1 }},
		{"genesis_next_body", func(s *setup) { s.genesis.NextBodyID[0] ^= 1 }},
		{"verified_record_tr", func(s *setup) { s.verified.Record.SuccessorTRHash[0] ^= 1 }},
		{"verified_record_rebound", func(s *setup) {
			s.verified.Record.SuccessorTRHash[0] ^= 1
			var e error
			s.genesis, e = evmroot.DeriveEpochGenesis(s.verified, s.body)
			if e != nil {
				panic(e)
			}
		}},
		{"verified_record_round", func(s *setup) { s.verified.Record.OrderedRound++ }},
		{"verified_record_attempt", func(s *setup) { s.verified.Record.Attempt++ }},
		{"verified_record_frozen", func(s *setup) { s.verified.Record.FrozenID[0] ^= 1 }},
		{"verified_seal_round", func(s *setup) { s.verified.CommitSealRound++ }},
		{"body", func(s *setup) { s.body.EarliestActivation++ }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := fixture(t)
			s.finalized(t)
			tc.change(&s)
			want(t, s.m.Bootstrap(s.verified, s.body, s.genesis, s.snapshot), ErrProof)
			if s.m.Genesis != nil {
				t.Fatal("invalid genesis installed")
			}
		})
	}
}

func TestBootstrapMachineBindings(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Machine)
	}{
		{"frozen_id", func(m *Machine) { m.Freeze.FrozenID[0] ^= 1 }},
		{"next_body", func(m *Machine) { m.Commit.Body[0] ^= 1 }},
		{"commit_seal_round", func(m *Machine) { m.Verified.CommitSealRound++ }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := fixture(t)
			s.finalized(t)
			tc.change(s.m)
			if s.m.bootstrapMachineFields(s.verified, s.genesis) {
				t.Fatal("changed machine field accepted")
			}
			want(t, s.m.Bootstrap(s.verified, s.body, s.genesis, s.snapshot), ErrProof)
		})
	}
}

func TestBootstrapInstallOnce(t *testing.T) {
	s := fixture(t)
	s.finalized(t)
	must(t, s.m.Bootstrap(s.verified, s.body, s.genesis, s.snapshot))
	must(t, s.m.Bootstrap(s.verified, s.body, s.genesis, s.snapshot))
	must(t, s.m.Activate(s.commit.Activation))
	want(t, s.m.Bootstrap(s.verified, s.body, s.genesis, s.snapshot), ErrProof)
}

func TestControlPartitionRefusedByContextCodecs(t *testing.T) {
	s := fixture(t)
	c := s.m.Context
	c.Partition = uint32(evmroot.D4ControlPartition)
	_, e := c.Encode()
	want(t, e, ErrCodec)
	_, e = DecodeContext(mustEncode(t, c))
	want(t, e, ErrCodec)
}

func TestExactRejectsOversizeCanonicalInput(t *testing.T) {
	b, e := enc("OVERSIZE", bytes.Repeat([]byte{1}, MaxEncodedLength))
	must(t, e)
	if len(b) <= MaxEncodedLength {
		t.Fatal("test input is not over limit")
	}
	_, e = exact(b, 2, "OVERSIZE")
	want(t, e, ErrCodec)
}
func TestFinalizeRefusesMissingAndForgedProof(t *testing.T) {
	s := fixture(t)
	s.commitStep(t)
	want(t, s.m.Finalize(nil), ErrProof)
	want(t, s.m.Finalize([]byte("forged")), ErrProof)
	if s.m.Final || s.m.Verified != nil {
		t.Fatal("forged proof finalized")
	}
}
func TestVerifierMatchesKindAndID(t *testing.T) {
	s := fixture(t)
	_, e := s.old.VerifyOrdered(s.m.Context, "abort", s.old.allowed["prepare"].id, proof)
	want(t, e, ErrProof)
	_, e = s.old.VerifyOrdered(s.m.Context, "prepare", fill(9), proof)
	want(t, e, ErrProof)
}
func TestBootstrapRequiresVerifiedGenesisAndSnapshot(t *testing.T) {
	s := fixture(t)
	s.finalized(t)
	want(t, s.m.Activate(10), ErrProof)
	g := s.genesis
	g.Start++
	want(t, s.m.Bootstrap(s.verified, s.body, g, s.snapshot), ErrProof)
	bad := s.snapshot
	bad.Control.OrderedRound++
	want(t, s.m.Bootstrap(s.verified, s.body, s.genesis, bad), ErrProof)
	must(t, s.m.Bootstrap(s.verified, s.body, s.genesis, s.snapshot))
	must(t, s.m.Activate(10))
	if !s.m.Authorized(10) || s.m.Authorized(9) {
		t.Fatal("wrong activation authority")
	}
	must(t, s.m.Acknowledge(s.ack, proof))
}
func TestRefusals(t *testing.T) {
	t.Run("body", func(t *testing.T) {
		s := fixture(t)
		s.prepare(t)
		f := s.freeze
		f.Body = fill(9)
		want(t, s.m.FreezeWith(f, s.body, f.Parent, proof), ErrBody)
	})
	t.Run("parent", func(t *testing.T) {
		s := fixture(t)
		s.prepare(t)
		want(t, s.m.FreezeWith(s.freeze, s.body, fill(9), proof), ErrParent)
	})
	t.Run("shard", func(t *testing.T) {
		s := fixture(t)
		s.prepare(t)
		f := s.freeze
		f.Context.Shard = []byte{9}
		want(t, s.m.FreezeWith(f, s.body, f.Parent, proof), ErrShard)
	})
	t.Run("proof", func(t *testing.T) { s := fixture(t); s.endorse(t); want(t, s.m.CommitWith(s.commit, nil), ErrProof) })
	t.Run("abort", func(t *testing.T) {
		s := fixture(t)
		s.prepare(t)
		must(t, s.m.Abort(proof))
		want(t, s.m.Activate(100), ErrAborted)
	})
	t.Run("late_abort", func(t *testing.T) { s := fixture(t); s.commitStep(t); want(t, s.m.Abort(proof), ErrPhase) })
	t.Run("two_successors", func(t *testing.T) {
		s := fixture(t)
		s.commitStep(t)
		r := s.commit
		r.ID = fill(9)
		want(t, s.m.CommitWith(r, proof), ErrSuccessor)
	})
	t.Run("ack_parent", func(t *testing.T) {
		s := fixture(t)
		s.bootstrapped(t)
		must(t, s.m.Activate(10))
		a := s.ack
		a.SuccessorParent = fill(9)
		want(t, s.m.Acknowledge(a, proof), ErrParent)
	})
	t.Run("ack_verifier", func(t *testing.T) {
		s := fixture(t)
		s.bootstrapped(t)
		must(t, s.m.Activate(10))
		s.ackV.deny = true
		want(t, s.m.Acknowledge(s.ack, proof), ErrProof)
	})
	t.Run("rest", func(t *testing.T) { s := fixture(t); want(t, s.m.LocalProposal(), ErrProposal) })
}
func TestBoundedCodecs(t *testing.T) {
	s := fixture(t)
	for _, decode := range []func([]byte) error{
		func(b []byte) error { _, e := DecodeContext(b); return e }, func(b []byte) error { _, e := DecodeFreeze(b); return e },
		func(b []byte) error { _, e := DecodeCommit(b); return e }, func(b []byte) error { _, e := DecodeAck(b); return e },
	} {
		want(t, decode(bytes.Repeat([]byte{0}, MaxEncodedLength+1)), ErrCodec)
	}
	s.m.Context.Shard = bytes.Repeat([]byte{1}, MaxShardLength+1)
	_, e := s.m.Context.Encode()
	want(t, e, ErrCodec)
	s.freeze.Context = s.m.Context
	_, e = s.freeze.Encode()
	want(t, e, ErrCodec)
	_, e = DecodeContext(mustEncode(t, Context{Network: 3, Epoch: 7, Partition: 1, Shard: bytes.Repeat([]byte{1}, MaxShardLength+1)}))
	want(t, e, ErrCodec)
}
func mustEncode(t *testing.T, c Context) []byte {
	t.Helper()
	b, e := enc("UNICITY_HANDOFF_CONTEXT", Version, c.Network, c.Epoch, c.Attempt, c.MinActivation, uint64(c.Partition), c.Shard, c.Predecessor[:], c.Candidate[:])
	must(t, e)
	return b
}
func TestVectors(t *testing.T) {
	s := fixture(t)
	inputs := map[string]func() ([]byte, error){"context": s.m.Context.Encode, "freeze": s.freeze.Encode, "commit": s.commit.Encode, "ack": s.ack.Encode,
		"epoch_genesis": func() ([]byte, error) {
			g := evmroot.EpochGenesis{Network: 3, Epoch: 8, Start: 10, OrderedRound: 6, NextBodyID: s.commit.Body[:], RecordID: s.commit.ID[:], Root: bytes.Repeat([]byte{0x44}, 32), ControlDigest: bytes.Repeat([]byte{0x55}, 32), FrozenID: s.freeze.FrozenID[:], SuccessorTRHash: s.commit.SuccessorTR[:]}
			return g.Bytes(), nil
		},
	}
	raw, e := os.ReadFile("testdata/wire.json")
	must(t, e)
	var vectors map[string]string
	must(t, json.Unmarshal(raw, &vectors))
	for name, fn := range inputs {
		b, e := fn()
		must(t, e)
		if hex.EncodeToString(b) != vectors[name] {
			t.Fatalf("%s changed", name)
		}
	}
	g := evmroot.EpochGenesis{Network: 3, Epoch: 8, Start: 10, OrderedRound: 6, NextBodyID: s.commit.Body[:], RecordID: s.commit.ID[:], Root: bytes.Repeat([]byte{0x44}, 32), ControlDigest: bytes.Repeat([]byte{0x55}, 32), FrozenID: s.freeze.FrozenID[:], SuccessorTRHash: s.commit.SuccessorTR[:]}
	if hex.EncodeToString(g.ID()) != vectors["genesis_id"] {
		t.Fatal("GenesisID changed")
	}
	for name, h := range vectors {
		if name == "genesis_id" {
			continue
		}
		b, e := hex.DecodeString(h)
		must(t, e)
		bad := append(bytes.Clone(b), 0)
		switch name {
		case "context":
			_, e = DecodeContext(bad)
		case "freeze":
			_, e = DecodeFreeze(bad)
		case "commit":
			_, e = DecodeCommit(bad)
		case "ack":
			_, e = DecodeAck(bad)
		default:
			continue
		}
		want(t, e, ErrCodec)
	}
}
func TestD4PhaseInterleavings(t *testing.T) {
	for _, steps := range [][]string{{"prepare", "freeze", "endorse", "commit"}, {"prepare", "abort"}, {"prepare", "freeze", "abort"}, {"prepare", "freeze", "endorse", "abort"}} {
		s := fixture(t)
		c := s.m.Context
		model := evmroot.NewHandoff(evmroot.Candidate{Network: c.Network, OldEpoch: c.Epoch, NextEpoch: c.Epoch + 1, Attempt: c.Attempt, MinActivation: c.MinActivation, PredecessorHash: c.Predecessor[:], CandidateHash: c.Candidate[:]}, 0)
		for _, step := range steps {
			switch step {
			case "prepare":
				must(t, s.m.Prepare(proof))
				must(t, model.Prepare())
			case "freeze":
				must(t, s.m.FreezeWith(s.freeze, s.body, s.freeze.Parent, proof))
				must(t, model.Freeze(s.freeze.Summary[:], s.freeze.Parent[:], s.body))
			case "endorse":
				must(t, s.m.Endorse(proof))
				must(t, model.Endorse(1, 1))
			case "commit":
				must(t, s.m.CommitWith(s.commit, proof))
				must(t, model.Commit(s.commit.Round, s.commit.Activation, s.commit.SuccessorTR[:]))
			case "abort":
				must(t, s.m.Abort(proof))
				must(t, model.Abort())
			}
			if uint8(s.m.Phase) != uint8(model.Phase) {
				t.Fatalf("%v: machine=%v model=%v", steps, s.m.Phase, model.Phase)
			}
			if s.m.Authorized(100) || model.Verified != nil || model.Anchor != nil {
				t.Fatal("unverified interleaving gained authority")
			}
		}
	}
}
func TestActivatedInterval(t *testing.T) {
	s := fixture(t)
	_, e := s.m.ActivatedInterval(s.body, 0)
	want(t, e, ErrNotFinal)
	s.finalized(t)
	in, e := s.m.ActivatedInterval(s.body, 0)
	must(t, e)
	if in.Activation.EpochStart != 10 || !bytes.Equal(in.Activation.ActivationCommitID, s.commit.ID[:]) {
		t.Fatal("wrong interval")
	}
}
