package evmroot

import (
	"bytes"
	"os"
	"testing"
)

func TestD4_AllScenariosMeetExpectations(t *testing.T) {
	for _, s := range D4Scenarios() {
		if !s.PhaseOK {
			t.Errorf("%s: final phase %s, want %s", s.Name, s.FinalPhase, s.WantPhase)
		}
		if !s.InvariantsOK {
			t.Errorf("%s: invariant violations: %+v", s.Name, s.Violations)
		}
	}
}

func TestD4_NoActivationWithoutCommit(t *testing.T) {
	// Prepare / freeze / endorse: Activate must fail with the no-commit error.
	oldT := RootQuorumThreshold(func() uint64 { w, _ := d3Assignment().TotalWeight(); return w }())
	h := freshHandoff()
	if err := h.Activate(1 << 20); err == nil {
		t.Fatal("idle handoff activated")
	}
	_ = h.Prepare()
	if err := h.Activate(1 << 20); err != errNoCommit {
		t.Fatalf("prepared: want errNoCommit, got %v", err)
	}
	_ = h.Freeze(rep(1, 32), rep(2, 32), body(h))
	if err := h.Activate(1 << 20); err != errNoCommit {
		t.Fatalf("frozen: want errNoCommit, got %v", err)
	}
	_ = h.Endorse(oldT, oldT)
	if err := h.Activate(1 << 20); err != errNoCommit {
		t.Fatalf("endorsed: want errNoCommit, got %v", err)
	}
}

func TestD4_EndorsementBindsNoFutureState(t *testing.T) {
	h := freshHandoff()
	_ = h.Prepare()
	_ = h.Freeze(rep(1, 32), rep(2, 32), body(h))
	dom := h.EndorsementDomainFor()
	if dom.ActivationRound != 0 || dom.SuccessorTRHash != nil {
		t.Fatal("endorsement domain carries post-commit fields")
	}
	if !FieldsAreKnown(dom) {
		t.Fatal("endorsement domain rejected as unknown despite being complete")
	}
}

func TestD4_ActivationRoundMustBeFinalUnderPipelining(t *testing.T) {
	oldT := RootQuorumThreshold(func() uint64 { w, _ := d3Assignment().TotalWeight(); return w }())
	h := freshHandoff()
	_ = h.Prepare()
	_ = h.Freeze(rep(1, 32), rep(2, 32), body(h))
	_ = h.Endorse(oldT, oldT)
	// commitRound 20, pipeline 3 -> A* must be >= 23; also >= MinActivation (10).
	if err := h.Commit(20, 22, rep(3, 32)); err != errActivationRoot {
		t.Fatalf("accepted A* below commit+pipeline: %v", err)
	}
	if err := h.Commit(20, 23, rep(3, 32)); err != nil {
		t.Fatalf("rejected a valid A*: %v", err)
	}
}

func TestD4_NoOverlapNoGapAtBoundary(t *testing.T) {
	oldT := RootQuorumThreshold(func() uint64 { w, _ := d3Assignment().TotalWeight(); return w }())
	h := freshHandoff()
	_ = h.Prepare()
	_ = h.Freeze(rep(1, 32), rep(2, 32), body(h))
	_ = h.Endorse(oldT, oldT)
	_ = h.Commit(6, 12, rep(3, 32)) // A* = 12
	if h.Authorized(11) != OldAssignment {
		t.Fatal("round below A* not authorised by the old set")
	}
	if h.Authorized(12) != NewAssignment {
		t.Fatal("round at A* not authorised by the new set")
	}
	if h.Authorized(13) != NewAssignment {
		t.Fatal("round above A* not authorised by the new set")
	}
}

func TestD4_CommittedCannotAbortAbortedCannotActivate(t *testing.T) {
	oldT := RootQuorumThreshold(func() uint64 { w, _ := d3Assignment().TotalWeight(); return w }())
	// committed -> abort rejected
	h := freshHandoff()
	_ = h.Prepare()
	_ = h.Freeze(rep(1, 32), rep(2, 32), body(h))
	_ = h.Endorse(oldT, oldT)
	_ = h.Commit(6, 10, rep(3, 32))
	if err := h.Abort("late"); err == nil {
		t.Fatal("aborted a committed handoff")
	}
	// aborted -> activate rejected
	g := freshHandoff()
	_ = g.Prepare()
	_ = g.Abort("replaced")
	if err := g.Activate(1 << 20); err == nil {
		t.Fatal("activated an aborted handoff")
	}
}

func TestD4_OnlyCanonicalPhaseOrderCommits(t *testing.T) {
	c := BuildD4Vectors().Interleavings
	if !c.OnlyCanonicalCommits {
		t.Fatalf("orders reaching committed: %v (want only the canonical order)", c.ReachedCommitted)
	}
	if !c.NoEarlyNewAuthorization {
		t.Fatalf("orders authorising the new set before commit: %v", c.NewAuthorizedEarly)
	}
}

func TestD4_VectorsMatchGolden(t *testing.T) {
	const path = "testdata/d4-vectors.json"
	got, err := MarshalD4Vectors(BuildD4Vectors())
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s (run: go run ./evmroot/cmd/d4vectors -update): %v", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s is stale — regenerate with: go run ./evmroot/cmd/d4vectors -update", path)
	}
}
