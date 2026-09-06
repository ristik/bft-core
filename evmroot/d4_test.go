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

func TestD4_FreezeBindsFrozenStateIntoEndorsedIdentity(t *testing.T) {
	// Two handoffs freeze the SAME body but with different frozen summaries
	// / EVM parents. Their endorsement domains must differ, so one
	// endorsement cannot authorise divergent handoff states.
	a := freshHandoff()
	_ = a.Prepare()
	if err := a.Freeze(rep(0x11, 32), rep(0x22, 32), body(a)); err != nil {
		t.Fatal(err)
	}
	b := freshHandoff()
	_ = b.Prepare()
	if err := b.Freeze(rep(0x99, 32), rep(0x22, 32), body(b)); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a.FrozenID, b.FrozenID) {
		t.Fatal("different frozen summaries produced the same FrozenID")
	}
	if bytes.Equal(a.EndorsementDomainFor().FrozenID, b.EndorsementDomainFor().FrozenID) {
		t.Fatal("different frozen state produced the same endorsement identity")
	}
	// Freeze rejects a body whose EpochStart is not the candidate A_min
	// (A* is not known until commit) and a body with the wrong predecessor.
	c := freshHandoff()
	_ = c.Prepare()
	badBody := body(c)
	badBody.EarliestActivation = 999 // not A_min
	if err := c.Freeze(rep(1, 32), rep(2, 32), badBody); err == nil {
		t.Fatal("Freeze accepted a body with EpochStart != A_min")
	}
}

func TestD4_ActivationRequiresFinalizedCommit(t *testing.T) {
	oldT := RootQuorumThreshold(func() uint64 { w, _ := d3Assignment().TotalWeight(); return w }())
	h := freshHandoff()
	_ = h.Prepare()
	_ = h.Freeze(rep(1, 32), rep(2, 32), body(h))
	_ = h.Endorse(oldT, oldT)
	_ = h.Commit(6, 10, rep(3, 32))
	// A* reached but commit not final under the root rule.
	if err := h.Activate(10); err != errCommitNotFinal {
		t.Fatalf("activated on round count alone: %v", err)
	}
	// A merely-larger round is NOT finality: an unrelated higher-round QC
	// (wrong parent) and a timeout-gap QC (non-consecutive) are both
	// rejected.
	unrelated := h.DescendantCommitQC(oldT)
	unrelated.ParentCommitID = rep(0x7A, 32)
	if err := h.FinalizeCommit(unrelated, oldT); err != errFinalityLink {
		t.Fatalf("an unrelated higher-round QC finalised the commit: %v", err)
	}
	gap := h.DescendantCommitQC(oldT)
	gap.Round = h.CommitRound + 2
	if err := h.FinalizeCommit(gap, oldT); err != errFinalityGap {
		t.Fatalf("a timeout-gap QC finalised the commit: %v", err)
	}
	weak := h.DescendantCommitQC(oldT)
	weak.QuorumWeight = oldT - 1
	if err := h.FinalizeCommit(weak, oldT); err != errFinalityQuorum {
		t.Fatalf("a below-quorum descendant finalised the commit: %v", err)
	}
	if err := h.FinalizeCommit(h.DescendantCommitQC(oldT), oldT); err != nil {
		t.Fatal(err)
	}
	if err := h.Activate(10); err != nil {
		t.Fatalf("activation rejected after finalize: %v", err)
	}
	// The bootstrap step is now explicit: a finalised commit yields the
	// first successor proposal, built on the finalised committed root, not
	// on a new-set round.
	sp, ok := h.FirstSuccessorProposal()
	if !ok || len(sp.Leader) == 0 || len(sp.BuildsOnRoot) != 32 || sp.ProposedRound != h.ActivationRound {
		t.Fatalf("first successor proposal not well-formed: %+v ok=%v", sp, ok)
	}
	if !bytes.Equal(sp.FinalityQC.CommittedRootHash, sp.BuildsOnRoot) {
		t.Fatal("successor proposal does not build on the finalised committed root")
	}
}

func TestD4_MultiReplicaGlobalInvariants(t *testing.T) {
	runs := D4MultiReplicaRuns()
	sawByzantineEquivocation := false
	sawCounterexample := false
	sawLiveness := false
	for _, m := range runs {
		if !m.PropertyHeld {
			t.Errorf("%s: modelled safety property does not hold: %+v", m.Name, m.Violations)
		}
		if m.Exploration != nil && m.Exploration.ByzantineWeight > 0 {
			sawByzantineEquivocation = true
			if m.Exploration.ByzantineWeight > m.Exploration.FaultyWeightBound {
				t.Errorf("%s: Byzantine weight %d exceeds f_W %d — outside the model's assumption",
					m.Name, m.Exploration.ByzantineWeight, m.Exploration.FaultyWeightBound)
			}
			if m.Exploration.MaxSimultaneousQuorums > 1 {
				t.Errorf("%s: Byzantine equivocation split a quorum (max %d simultaneous)",
					m.Name, m.Exploration.MaxSimultaneousQuorums)
			}
			if !m.Exploration.ByzantineOnBoth {
				t.Errorf("%s: Byzantine signers were not placed on both statements", m.Name)
			}
		}
		if m.IsCounterexample {
			sawCounterexample = true
			if !m.ConflictDetected {
				t.Errorf("%s: conflicting per-replica commit tuples were not flagged", m.Name)
			}
		}
		if m.Name == "conditional_liveness_all_delivered" {
			sawLiveness = true
			if m.G5Liveness != "reached" {
				t.Fatalf("conditional-liveness run did not reach: %s", m.G5Liveness)
			}
		}
	}
	if !sawByzantineEquivocation {
		t.Fatal("no run models Byzantine signer equivocation — the fault is assumed away")
	}
	if !sawCounterexample {
		t.Fatal("no conflicting-activation-round counterexample in the suite")
	}
	if !sawLiveness {
		t.Fatal("no conditional-liveness run in the suite")
	}
}

func TestD4_HandoffProgressAndAbortModel(t *testing.T) {
	runs := D4ProgressRuns()
	names := map[string]bool{}
	for _, p := range runs {
		names[p.Name] = true
		if !p.Holds {
			t.Errorf("%s: progress/abort property does not hold: %+v", p.Name, p)
		}
	}
	// The reviewer's split counterexample must be covered and resolved.
	if !names["no_honest_split_byzantine_withholding"] {
		t.Fatal("the honest-weight-split scenario is not modelled")
	}
	if !names["view_change_carries_lock"] || !names["commit_then_abort_cannot_reach_quorum"] ||
		!names["combined_delay_restart_commit_vs_abort"] {
		t.Fatal("view-change lock / commit-vs-abort / combined schedule runs missing")
	}
	// Directly: a quorum forms for exactly one FrozenID with b/e Byzantine
	// and withholding, and none forms for the other.
	for _, p := range runs {
		if p.Name == "no_honest_split_byzantine_withholding" {
			if !p.QuorumFormed || !p.SplitAvoided || len(p.EndorsedFrozenIDs) != 1 {
				t.Fatalf("honest weight was split or no quorum formed: %+v", p)
			}
		}
		if p.Name == "combined_delay_restart_commit_vs_abort" && p.AbortReachedQuorum {
			t.Fatal("an abort of a committed attempt reached a quorum in the combined schedule")
		}
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
