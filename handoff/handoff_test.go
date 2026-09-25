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

type verifier struct{ deny bool }

func (v verifier) VerifyOrdered(_ string, _ [32]byte, p []byte) error {
	if v.deny || !bytes.Equal(p, []byte("root-qc")) {
		return ErrProof
	}
	return nil
}
func (v verifier) VerifyEndorse(_ [32]byte, p []byte) error {
	if v.deny || !bytes.Equal(p, []byte("root-qc")) {
		return ErrNoQuorum
	}
	return nil
}
func (v verifier) VerifyFinal(_ [32]byte, _ uint64, p []byte) error {
	if v.deny || !bytes.Equal(p, []byte("root-qc")) {
		return ErrProof
	}
	return nil
}

var proof = []byte("root-qc")

func fill(x byte) [32]byte {
	var a [32]byte
	for i := range a {
		a[i] = x
	}
	return a
}
func fixture() (*Machine, evmroot.TrustBaseBodyV2, FreezeRecord, CommitRecord, AckRecord) {
	c := Context{Network: 3, Epoch: 8, Attempt: 0, MinActivation: 10, Partition: 1, Shard: []byte{0}, Predecessor: fill(0xe7), Candidate: fill(0xca)}
	m := New(c, verifier{})
	members := evmroot.WeightSet{{StakingID: "stake-a", NodeID: "root-a", ConsensusKey: append([]byte{2}, bytes.Repeat([]byte{1}, 32)...), Weight: 1}}
	body := evmroot.TrustBaseBodyV2{Version: evmroot.TrustBaseVersion, NetworkID: 3, Epoch: 8, EarliestActivation: 10, Members: members, RootThreshold: 1, StateSummary: bytes.Repeat([]byte{0x5a}, 32), ChangeRecordHash: bytes.Repeat([]byte{0x77}, 32), PredecessorHash: c.Predecessor[:]}
	id := body.Identity()
	f := FreezeRecord{Context: c, Body: id, Summary: fill(0x11), Parent: fill(0x22)}
	f.FrozenID = hash("UNICITY_HANDOFF_FROZEN", f.Body[:], f.Summary[:], f.Parent[:], c.Candidate[:], c.Attempt, c.Predecessor[:])
	r := CommitRecord{FrozenID: f.FrozenID, Body: f.Body, Round: 6, Activation: 10, SuccessorTR: fill(0x33)}
	r.ID = hash("UNICITY_HANDOFF_COMMIT", r.FrozenID[:], r.Activation, r.SuccessorTR[:], c.Attempt, c.Predecessor[:])
	a := AckRecord{FrozenID: f.FrozenID, CommitID: r.ID, FrozenParent: f.Parent, SuccessorParent: f.Parent, SuccessorTR: r.SuccessorTR, EVMRound: 41}
	return m, body, f, r, a
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
func prepared(t *testing.T) (*Machine, evmroot.TrustBaseBodyV2, FreezeRecord, CommitRecord, AckRecord) {
	t.Helper()
	m, b, f, c, a := fixture()
	must(t, m.Prepare(proof))
	return m, b, f, c, a
}
func frozen(t *testing.T) (*Machine, CommitRecord, AckRecord) {
	t.Helper()
	m, b, f, c, a := prepared(t)
	must(t, m.FreezeWith(f, b, f.Parent, proof))
	return m, c, a
}
func endorsed(t *testing.T) (*Machine, CommitRecord, AckRecord) {
	t.Helper()
	m, c, a := frozen(t)
	must(t, m.Endorse(proof))
	return m, c, a
}
func committed(t *testing.T) (*Machine, AckRecord) {
	t.Helper()
	m, c, a := endorsed(t)
	must(t, m.CommitWith(c, proof))
	return m, a
}
func TestRefusals(t *testing.T) {
	t.Run("forged body", func(t *testing.T) {
		m, b, f, _, _ := prepared(t)
		f.Body = fill(9)
		f.FrozenID = hash("UNICITY_HANDOFF_FROZEN", f.Body[:], f.Summary[:], f.Parent[:], m.Context.Candidate[:], m.Context.Attempt, m.Context.Predecessor[:])
		want(t, m.FreezeWith(f, b, f.Parent, proof), ErrBody)
	})
	t.Run("omitted body", func(t *testing.T) {
		m, b, f, _, _ := prepared(t)
		f.Body = [32]byte{}
		f.FrozenID = hash("UNICITY_HANDOFF_FROZEN", f.Body[:], f.Summary[:], f.Parent[:], m.Context.Candidate[:], m.Context.Attempt, m.Context.Predecessor[:])
		want(t, m.FreezeWith(f, b, f.Parent, proof), ErrBody)
	})
	t.Run("reordered body", func(t *testing.T) {
		m, b, f, _, _ := prepared(t)
		f.Summary, f.Parent = f.Parent, f.Summary
		want(t, m.FreezeWith(f, b, f.Parent, proof), ErrBody)
	})
	t.Run("stale parent", func(t *testing.T) {
		m, b, f, _, _ := prepared(t)
		want(t, m.FreezeWith(f, b, fill(8), proof), ErrParent)
	})
	t.Run("wrong shard", func(t *testing.T) {
		m, b, f, _, _ := prepared(t)
		f.Context.Shard = []byte{9}
		want(t, m.FreezeWith(f, b, f.Parent, proof), ErrShard)
	})
	t.Run("two successors", func(t *testing.T) {
		m, c, _ := endorsed(t)
		must(t, m.CommitWith(c, proof))
		c.SuccessorTR = fill(4)
		c.ID = fill(4)
		want(t, m.CommitWith(c, proof), ErrSuccessor)
	})
	t.Run("abort then activate", func(t *testing.T) {
		m, _, _, _, _ := prepared(t)
		must(t, m.Abort(proof))
		want(t, m.Activate(100), ErrAborted)
	})
	t.Run("late abort", func(t *testing.T) { m, _ := committed(t); want(t, m.Abort(proof), ErrPhase) })
	t.Run("commit without proof", func(t *testing.T) { m, c, _ := endorsed(t); want(t, m.CommitWith(c, nil), ErrProof) })
	t.Run("forged proof", func(t *testing.T) { m, c, _ := endorsed(t); want(t, m.CommitWith(c, []byte("forged")), ErrProof) })
	t.Run("rest insertion", func(t *testing.T) {
		m, _, _, _, _ := prepared(t)
		want(t, m.LocalProposal(), ErrProposal)
		if m.Phase != Prepared {
			t.Fatal(m.Phase)
		}
	})
	t.Run("old quorum lost", func(t *testing.T) {
		m, _, _ := frozen(t)
		want(t, m.Endorse(nil), ErrNoQuorum)
		if m.Authorized(100) {
			t.Fatal("new authorized")
		}
	})
	t.Run("not final", func(t *testing.T) { m, _ := committed(t); want(t, m.Activate(10), ErrNotFinal) })
	t.Run("ack wrong parent", func(t *testing.T) {
		m, a := committed(t)
		must(t, m.Finalize(proof))
		must(t, m.Activate(10))
		a.SuccessorParent = fill(5)
		want(t, m.Acknowledge(a, proof), ErrParent)
	})
}
func TestVectors(t *testing.T) {
	m, _, f, c, a := fixture()
	inputs := map[string]func() ([]byte, error){"context": m.Context.Encode, "freeze": f.Encode, "commit": c.Encode, "ack": a.Encode}
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
	for name, h := range vectors {
		b, e := hex.DecodeString(h)
		must(t, e)
		switch name {
		case "context":
			_, e = DecodeContext(b)
		case "freeze":
			_, e = DecodeFreeze(b)
		case "commit":
			_, e = DecodeCommit(b)
		case "ack":
			_, e = DecodeAck(b)
		}
		must(t, e)
		bad := append(append([]byte(nil), b...), 0)
		switch name {
		case "context":
			_, e = DecodeContext(bad)
		case "freeze":
			_, e = DecodeFreeze(bad)
		case "commit":
			_, e = DecodeCommit(bad)
		case "ack":
			_, e = DecodeAck(bad)
		}
		want(t, e, ErrCodec)
	}
}
func TestD4ScenarioConformance(t *testing.T) {
	var vectors struct {
		Scenarios []struct {
			Name  string `json:"name"`
			Steps []struct {
				Step string `json:"step"`
			} `json:"steps"`
			Final string `json:"final_phase"`
		} `json:"scenarios"`
	}
	raw, e := os.ReadFile("../evmroot/testdata/d4-vectors.json")
	must(t, e)
	must(t, json.Unmarshal(raw, &vectors))
	for _, s := range vectors.Scenarios {
		t.Run(s.Name, func(t *testing.T) {
			m, b, f, c, a := fixture()
			switch s.Name {
			case "asymmetric_delivery":
				must(t, m.Prepare(proof))
				must(t, m.FreezeWith(f, b, f.Parent, proof))
				must(t, m.Endorse(proof))
			case "crash_at_prepared":
				must(t, m.Prepare(proof))
			case "crash_at_frozen":
				must(t, m.Prepare(proof))
				must(t, m.FreezeWith(f, b, f.Parent, proof))
			case "crash_at_endorsed":
				must(t, m.Prepare(proof))
				must(t, m.FreezeWith(f, b, f.Parent, proof))
				must(t, m.Endorse(proof))
			case "crash_at_committed":
				must(t, m.Prepare(proof))
				must(t, m.FreezeWith(f, b, f.Parent, proof))
				must(t, m.Endorse(proof))
				must(t, m.CommitWith(c, proof))
			}
			for _, st := range s.Steps {
				switch st.Step {
				case "prepare":
					must(t, m.Prepare(proof))
				case "freeze":
					must(t, m.FreezeWith(f, b, f.Parent, proof))
				case "endorse", "endorse_at_threshold":
					must(t, m.Endorse(proof))
				case "endorse_below_threshold", "endorse_fails_forever":
					want(t, m.Endorse(nil), ErrNoQuorum)
				case "commit", "commit_A_star_ge_observed":
					if st.Step == "commit_A_star_ge_observed" {
						c.Round = 50
						c.Activation = 60
						c.ID = hash("UNICITY_HANDOFF_COMMIT", c.FrozenID[:], c.Activation, c.SuccessorTR[:], m.Context.Attempt, m.Context.Predecessor[:])
						a.CommitID = c.ID
					}
					must(t, m.CommitWith(c, proof))
				case "finalize_commit":
					must(t, m.Finalize(proof))
				case "activate_at_boundary", "activate_at_A_star":
					must(t, m.Activate(c.Activation))
				case "acknowledge":
					must(t, m.Acknowledge(a, proof))
				case "abort":
					must(t, m.Abort(proof))
				case "abort_after_commit_rejected":
					want(t, m.Abort(proof), ErrPhase)
				case "activate_rejected":
					want(t, m.Activate(100), ErrAborted)
				case "try_activate_without_commit", "activate_still_impossible", "round_passes_A_min_no_commit", "skip_to_activate":
					want(t, m.Activate(100), ErrPhase)
				case "skip_to_endorse":
					want(t, m.Endorse(proof), ErrPhase)
				case "skip_to_commit":
					want(t, m.CommitWith(c, proof), ErrPhase)
				case "resume_finalize_and_activate":
					must(t, m.Finalize(proof))
					must(t, m.Activate(10))
				case "local_rest_insertion":
					want(t, m.LocalProposal(), ErrProposal)
				case "clock_reaches_proposed_start":
					if m.Authorized(100) {
						t.Fatal("clock activated")
					}
				}
			}
			names := []string{"idle", "prepared", "frozen", "endorsed", "committed", "activated", "acknowledged", "aborted"}
			if names[m.Phase] != s.Final {
				t.Fatalf("got %s want %s", names[m.Phase], s.Final)
			}
			for _, round := range []uint64{0, 9, 10, 60, 100} {
				wantNew := m.Phase >= Committed && m.Phase <= Acknowledged && round >= m.Commit.Activation
				if m.Authorized(round) != wantNew {
					t.Fatal("authorization mismatch")
				}
			}
		})
	}
}

func TestActivatedInterval(t *testing.T) {
	m, b, _, _, _ := fixture()
	_, e := m.ActivatedInterval(b, 0)
	want(t, e, ErrNotFinal)
	m, b, f, c, _ := prepared(t)
	must(t, m.FreezeWith(f, b, f.Parent, proof))
	must(t, m.Endorse(proof))
	must(t, m.CommitWith(c, proof))
	must(t, m.Finalize(proof))
	in, e := m.ActivatedInterval(b, 0)
	must(t, e)
	if in.Activation.EpochStart != 10 || !bytes.Equal(in.Activation.ActivationCommitID, c.ID[:]) {
		t.Fatal("wrong activation record")
	}
}
