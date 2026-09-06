package evmroot

import (
	"fmt"
	"sort"
)

// D4 adversarial multi-replica model.
//
// The first-review model used a *global signer lock* — no signer, honest
// or Byzantine, could ever be counted for two conflicting statements. The
// re-review (#80) rejected that: it assumes away the very fault the handoff
// has to survive. This model instead states the fault and shows safety
// holds anyway:
//
//   - HONEST signers have durable local state and sign at most ONE of two
//     conflicting statements (a per-honest-signer lock, not a global one).
//   - BYZANTINE signers — an explicit set whose authenticated weight is
//     ≤ f_W = W − ⌊2W/3⌋−1 — equivocate freely: they sign BOTH statements.
//   - Every quorum is the weight of the *actual distinct authenticated
//     signer set* via WeightSet.SignerWeight, never a supplied cumulative
//     number.
//
// The safety properties are the quorum-intersection facts that survive
// Byzantine equivocation:
//
//   G2  over EVERY assignment of the honest signers, at most one of two
//       conflicting statements reaches an endorsement / commit quorum
//       (⌊2W/3⌋+1). Two >2/3 subsets share >1/3 weight; honest weight
//       alone exceeds f_W, so it cannot be split across both statements.
//       Applied to: two FrozenIDs, two CommitRecordIDs (conflicting A*),
//       and a commit vs an abort of the same attempt.
//   G3  per-replica commit tuples (replica, FrozenID, A*, commitRound,
//       CommitRecordID) are kept un-deduplicated and must all agree; the
//       conflicting-A* counterexample is carried as a negative run the
//       tuple check is required to flag.
//   G4  activation requires FinalizeCommit(descendantRound > commitRound)
//       — the root 2-chain rule, not a round count.
//   G5  (conditional liveness) with every record delivered and no abort,
//       every replica reaches acknowledged.
//
// G1 ("no signer ever equivocates") is deliberately NOT a property here:
// Byzantine signers do equivocate, and safety must not depend on their
// not doing so.
//
// Normative source: docs/design/d4-epoch-handoff-state-machine.md §4,
// docs/adr/0006-epoch-handoff-state-machine.md.

// d4Signers is the model's outgoing assignment (D3's d3Assignment: weights
// 10/6/5/2/1, W=24, endorsement threshold ⌊2W/3⌋+1 = 17, f_W = 24−17 = 7).
func d4Signers() (ws WeightSet, threshold, faultyBound uint64) {
	ws = d3Assignment()
	w, _ := ws.TotalWeight()
	return ws, RootQuorumThreshold(w), FaultyWeightBound(w)
}

func mustW(ws WeightSet) uint64 { w, _ := ws.TotalWeight(); return w }

func joinSorted(s []string) string {
	c := append([]string(nil), s...)
	sort.Strings(c)
	return join(c, ",")
}

// quorumExploration is the exhaustive per-honest-assignment search for a
// split quorum between two conflicting statements X and Y.
type quorumExploration struct {
	Statements             [2]string `json:"statements"`
	HonestSigners          []string  `json:"honest_signers"`
	ByzantineSigners       []string  `json:"byzantine_signers"`
	ByzantineWeight        uint64    `json:"byzantine_weight"`
	FaultyWeightBound      uint64    `json:"faulty_weight_bound"`
	Threshold              uint64    `json:"quorum_threshold"`
	HonestAssignments      int       `json:"honest_assignments_enumerated"`
	MaxSimultaneousQuorums int       `json:"max_simultaneous_quorums"`
	ByzantineOnBoth        bool      `json:"byzantine_signed_both_statements"`
	MaxMinSideWeight       uint64    `json:"max_min_side_weight"` // best simultaneous pressure on both sides
	ClosestSplit           string    `json:"closest_split_to_a_double_quorum"`
}

// exploreQuorumIntersection enumerates every assignment of each honest
// signer to {X, Y, abstain} (3^|honest|), with the Byzantine signers on
// BOTH X and Y, and reports the largest number of the two statements that
// simultaneously reach `threshold` distinct authenticated signer weight.
// For a sound quorum rule that maximum is 1.
func exploreQuorumIntersection(labels [2]string, ws WeightSet, threshold uint64, honest, byz []string) quorumExploration {
	n := len(honest)
	pow := 1
	for i := 0; i < n; i++ {
		pow *= 3
	}
	maxQ := 0
	var maxMin uint64
	closest := "no assignment puts weight on both sides"
	for mask := 0; mask < pow; mask++ {
		xs := append([]string(nil), byz...)
		ys := append([]string(nil), byz...)
		m := mask
		for i := 0; i < n; i++ {
			switch m % 3 {
			case 0:
				xs = append(xs, honest[i])
			case 1:
				ys = append(ys, honest[i])
			}
			m /= 3
		}
		xw, xok := ws.SignerWeight(xs)
		yw, yok := ws.SignerWeight(ys)
		q := 0
		if xok && xw >= threshold {
			q++
		}
		if yok && yw >= threshold {
			q++
		}
		if q > maxQ {
			maxQ = q
		}
		if xok && yok {
			mn := yw
			if xw < yw {
				mn = xw
			}
			if mn > maxMin {
				maxMin = mn
				closest = fmt.Sprintf("%s={%s} w=%d ; %s={%s} w=%d (threshold %d)",
					labels[0], joinSorted(xs), xw, labels[1], joinSorted(ys), yw, threshold)
			}
		}
	}
	bw, _ := ws.SignerWeight(byz)
	return quorumExploration{
		Statements: labels, HonestSigners: honest, ByzantineSigners: byz, ByzantineWeight: bw,
		FaultyWeightBound: FaultyWeightBound(mustW(ws)), Threshold: threshold,
		HonestAssignments: pow, MaxSimultaneousQuorums: maxQ,
		ByzantineOnBoth: len(byz) > 0, MaxMinSideWeight: maxMin, ClosestSplit: closest,
	}
}

// honestComplement returns the assignment members not in byz, sorted.
func honestComplement(ws WeightSet, byz []string) []string {
	drop := map[string]struct{}{}
	for _, b := range byz {
		drop[b] = struct{}{}
	}
	var h []string
	for _, m := range ws {
		if _, isByz := drop[m.NodeID]; !isByz {
			h = append(h, m.NodeID)
		}
	}
	sort.Strings(h)
	return h
}

// --- per-replica commit tuples -------------------------------------------

type commitTuple struct {
	Replica      string `json:"replica"`
	FrozenID     string `json:"frozen_id"`
	AStar        uint64 `json:"a_star"`
	CommitRound  uint64 `json:"commit_round"`
	CommitRecord string `json:"commit_record_id"`
}

// commitReplica drives one replica's Handoff prepare→commit for a given A*
// and commit round and returns its commit tuple. Nothing is deduplicated:
// each replica keeps its own tuple so a disagreement is visible.
func commitReplica(id string, c Candidate, aStar, commitRound uint64) commitTuple {
	ws, threshold, _ := d4Signers()
	h := NewHandoff(c, 1)
	_ = h.Prepare()
	_ = h.Freeze(rep(0x11, 32), rep(0x22, 32), sampleHandoffBody(c.PredecessorHash, c.MinActivation))
	qw, _ := ws.SignerWeight([]string{"root-a", "root-b", "root-c"}) // 10+6+5 = 21 ≥ 17
	_ = h.Endorse(qw, threshold)
	_ = h.Commit(commitRound, aStar, rep(0x33, 32))
	return commitTuple{
		Replica:      id,
		FrozenID:     fmt.Sprintf("%x", h.FrozenID[:8]),
		AStar:        h.ActivationRound,
		CommitRound:  h.CommitRound,
		CommitRecord: fmt.Sprintf("%x", h.CommitRecordID[:8]),
	}
}

func tuplesAgree(ts []commitTuple) bool {
	if len(ts) == 0 {
		return false
	}
	for i := 1; i < len(ts); i++ {
		if ts[i].FrozenID != ts[0].FrozenID || ts[i].AStar != ts[0].AStar ||
			ts[i].CommitRound != ts[0].CommitRound || ts[i].CommitRecord != ts[0].CommitRecord {
			return false
		}
	}
	return true
}

func distinctTuples(ts []commitTuple) int {
	seen := map[string]struct{}{}
	for _, t := range ts {
		seen[fmt.Sprintf("%s|%d|%d|%s", t.FrozenID, t.AStar, t.CommitRound, t.CommitRecord)] = struct{}{}
	}
	return len(seen)
}

// --- result type -------------------------------------------------------

// MultiReplicaResult is one adversarial run.
type MultiReplicaResult struct {
	Name             string               `json:"name"`
	Note             string               `json:"note"`
	Kind             string               `json:"kind"` // quorum | tuples | finality | liveness
	IsCounterexample bool                 `json:"is_counterexample"`
	Exploration      *quorumExploration   `json:"quorum_exploration,omitempty"`
	CommitTuples     []commitTuple        `json:"per_replica_commit_tuples,omitempty"`
	DistinctTuples   int                  `json:"distinct_commit_tuples,omitempty"`
	Violations       []InvariantViolation `json:"violations,omitempty"`

	// Readable sub-verdicts (n/a dimensions stay true so the aggregate AND
	// in d4vectors.go is meaningful):
	G2QuorumUnique    bool `json:"g2_at_most_one_statement_reaches_quorum"`
	G3TuplesAgree     bool `json:"g3_all_replica_commit_tuples_agree"`
	G4FinalCommit     bool `json:"g4_no_activation_without_finalized_commit"`
	ByzantineModelled bool `json:"byzantine_equivocation_modelled"`
	ConflictDetected  bool `json:"conflict_detected_by_tuple_check"`

	// PropertyHeld is the run's single pass/fail: the modelled safety
	// property for a normal run, or "the counterexample was flagged" for a
	// counterexample run.
	PropertyHeld bool   `json:"property_held"`
	G5Liveness   string `json:"g5_liveness,omitempty"`
}

func newQuorumRun(name, note string, byz []string, labels [2]string) MultiReplicaResult {
	ws, threshold, _ := d4Signers()
	honest := honestComplement(ws, byz)
	ex := exploreQuorumIntersection(labels, ws, threshold, honest, byz)
	held := ex.MaxSimultaneousQuorums <= 1 && ex.ByzantineWeight <= ex.FaultyWeightBound
	return MultiReplicaResult{
		Name: name, Note: note, Kind: "quorum",
		Exploration:       &ex,
		G2QuorumUnique:    ex.MaxSimultaneousQuorums <= 1,
		G3TuplesAgree:     true,
		G4FinalCommit:     true,
		ByzantineModelled: len(byz) > 0,
		PropertyHeld:      held,
	}
}

// D4MultiReplicaRuns builds the adversarial exploration set.
func D4MultiReplicaRuns() []MultiReplicaResult {
	c := Candidate{Network: 3, NextEpoch: 8, Attempt: 0, PredecessorHash: rep(0xE7, 32), MinActivation: 10, CandidateHash: rep(0xCA, 32)}
	var out []MultiReplicaResult

	// 1. Endorsement quorum, no Byzantine signers: two competing FrozenIDs,
	//    honest signers split every possible way, at most one reaches 17.
	out = append(out, newQuorumRun("endorsement_quorum_honest_only",
		"Two competing FrozenIDs X and Y. Every honest signer signs at most one (durable local state). Over all 3^5 = 243 assignments, at most one FrozenID reaches ⌊2W/3⌋+1 = 17.",
		nil, [2]string{"frozenX", "frozenY"}))

	// 2. Byzantine weight 6 (< f_W = 7) equivocating on BOTH FrozenIDs.
	out = append(out, newQuorumRun("endorsement_quorum_byzantine_below_bound",
		"root-c (5) + root-e (1) = 6 ≤ f_W = 7 are Byzantine and sign BOTH X and Y. Honest signers (a,b,d = weight 18) still cannot be split to give both X and Y ≥ 17. Max simultaneous quorums stays 1.",
		[]string{"root-c", "root-e"}, [2]string{"frozenX", "frozenY"}))

	// 3. Byzantine weight exactly at the bound.
	out = append(out, newQuorumRun("endorsement_quorum_byzantine_at_bound",
		"root-b (6) + root-e (1) = 7 = f_W are Byzantine and sign both. Honest weight (a,c,d = 17) is a single quorum's worth and indivisible across two statements — one quorum at most.",
		[]string{"root-b", "root-e"}, [2]string{"frozenX", "frozenY"}))

	// 4. Same arithmetic at the COMMIT layer: two CommitRecordIDs that
	//    differ only in A* each need an old-quorum QC. G2 ⇒ at most one A*
	//    is ever certified — this is the mechanism behind finding 1.
	out = append(out, newQuorumRun("commit_quorum_conflicting_activation_rounds",
		"Two CommitRecordIDs for the same FrozenID with A*=12 and A*=15. Each needs its own old-quorum QC over UNICITY_HANDOFF_COMMIT. Byzantine set (weight 6) signs both; at most one reaches 17, so two conflicting activation rounds cannot both be certified.",
		[]string{"root-c", "root-e"}, [2]string{"commit_Astar_12", "commit_Astar_15"}))

	// 5. Commit vs abort of the same attempt: mutually exclusive.
	out = append(out, newQuorumRun("commit_versus_abort_exclusion",
		"An old-quorum commit and an old-quorum abort of attempt j. Byzantine signers (weight 6) sign both; honest signers sign one. At most one reaches quorum, so a committed handoff and an abort cannot both take effect.",
		[]string{"root-c", "root-e"}, [2]string{"commit_j", "abort_j"}))

	// 6. Per-replica commit tuples: three replicas commit the SAME certified
	//    record; every tuple agrees.
	ts := []commitTuple{
		commitReplica("A", c, 12, 6),
		commitReplica("B", c, 12, 6),
		commitReplica("C", c, 12, 6),
	}
	out = append(out, MultiReplicaResult{
		Name: "replica_commit_tuples_agree", Kind: "tuples",
		Note:         "Three replicas apply the same certified commit record. Their (FrozenID, A*, commitRound, CommitRecordID) tuples are kept separately and all agree.",
		CommitTuples: ts, DistinctTuples: distinctTuples(ts),
		G2QuorumUnique: true, G3TuplesAgree: tuplesAgree(ts), G4FinalCommit: true,
		PropertyHeld: tuplesAgree(ts),
	})

	// 7. COUNTEREXAMPLE: replica A is fed a commit with A*=12, replica B one
	//    with A*=15, same FrozenID. A sound model keeps both tuples and
	//    flags the disagreement (the earlier map-keyed-by-FrozenID model
	//    silently kept only the last). Runs 2–4 are why only one of these
	//    can ever carry a real old-quorum QC.
	cx := []commitTuple{
		commitReplica("A", c, 12, 6),
		commitReplica("B", c, 15, 6),
	}
	out = append(out, MultiReplicaResult{
		Name: "conflicting_activation_round_counterexample", Kind: "tuples", IsCounterexample: true,
		Note:         "Same FrozenID committed with A*=12 to replica A and A*=15 to replica B. The per-replica tuples differ (A*, CommitRecordID) and the check flags it. This can only arise if two conflicting old-quorum QCs were produced — commit_quorum_conflicting_activation_rounds shows that is impossible.",
		CommitTuples: cx, DistinctTuples: distinctTuples(cx),
		G2QuorumUnique: true, G3TuplesAgree: tuplesAgree(cx), G4FinalCommit: true,
		ConflictDetected: !tuplesAgree(cx),
		PropertyHeld:     !tuplesAgree(cx),
	})

	// 8. Activation requires a finalized commit (root 2-chain), not a round
	//    count.
	fr := freshHandoff()
	_ = fr.Prepare()
	_ = fr.Freeze(rep(0x11, 32), rep(0x22, 32), body(fr))
	_, thr, _ := d4Signers()
	_ = fr.Endorse(thr, thr)
	_ = fr.Commit(6, 12, rep(0x33, 32))
	var fv []InvariantViolation
	roundReachedNoFinal := fr.Activate(12) // A* reached, commit not final
	if roundReachedNoFinal == nil {
		fv = append(fv, InvariantViolation{"g4", "activated on observedRootRound ≥ A* without a finalized commit"})
	}
	// An unrelated higher-round QC (wrong parent) must NOT finalise.
	unrelated := fr.DescendantCommitQC(thr)
	unrelated.ParentCommitID = rep(0x7A, 32)
	if fr.FinalizeCommit(unrelated, thr) == nil {
		fv = append(fv, InvariantViolation{"g4", "an unrelated higher-round QC was accepted as finality evidence"})
	}
	// A timeout-gap QC (non-consecutive round) must NOT finalise.
	gap := fr.DescendantCommitQC(thr)
	gap.Round = fr.CommitRound + 2
	if fr.FinalizeCommit(gap, thr) == nil {
		fv = append(fv, InvariantViolation{"g4", "a timeout-gap QC was accepted as finality evidence"})
	}
	// The real descendant 2-chain QC finalises it.
	if fr.FinalizeCommit(fr.DescendantCommitQC(thr), thr) != nil {
		fv = append(fv, InvariantViolation{"g4", "the real descendant 2-chain QC was rejected"})
	}
	afterFinal := fr.Activate(12)
	if afterFinal != nil {
		fv = append(fv, InvariantViolation{"g4", "activation rejected after a descendant commit finalized it: " + afterFinal.Error()})
	}
	sp, spOK := fr.FirstSuccessorProposal()
	if !spOK || len(sp.Leader) == 0 || !bytesEqual(sp.BuildsOnRoot, sp.FinalityQC.CommittedRootHash) || sp.ProposedRound != fr.ActivationRound {
		fv = append(fv, InvariantViolation{"g4", "first successor proposal does not build on the finalised committed root at A*"})
	}
	out = append(out, MultiReplicaResult{
		Name: "activation_requires_finalized_commit", Kind: "finality",
		Note:           "observedRootRound ≥ A* is not enough, and a larger round number is not finality. FinalizeCommit takes a DESCENDANT CommitQC and checks: ParentCommitID == this CommitRecordID, Round == CommitRound+1 (no timeout gap), QuorumWeight ≥ old threshold, a 32-byte committed root hash. An unrelated higher-round QC and a timeout-gap QC are both rejected. The first successor proposal is produced by the committed successor-TR leader and builds on the FINALISED committed root — not on a new-set round, none of which exists yet — at A*.",
		Violations:     fv,
		G2QuorumUnique: true, G3TuplesAgree: true, G4FinalCommit: len(fv) == 0,
		PropertyHeld: len(fv) == 0,
	})

	// 9. Conditional liveness: every record delivered, no abort ⇒ every
	//    replica reaches acknowledged.
	live := true
	for _, id := range []string{"A", "B", "C"} {
		h := NewHandoff(c, 1)
		_ = h.Prepare()
		_ = h.Freeze(rep(0x11, 32), rep(0x22, 32), body(h))
		_ = h.Endorse(thr, thr)
		_ = h.Commit(6, 12, rep(0x33, 32))
		_ = h.FinalizeCommit(h.DescendantCommitQC(thr), thr)
		_ = h.Activate(12)
		_ = h.Acknowledge(13)
		if h.Phase != PhaseAcknowledged {
			live = false
			_ = id
		}
	}
	out = append(out, MultiReplicaResult{
		Name: "conditional_liveness_all_delivered", Kind: "liveness",
		Note:           "With every handoff record delivered to every replica and no abort, all replicas reach acknowledged.",
		G2QuorumUnique: true, G3TuplesAgree: true, G4FinalCommit: true,
		PropertyHeld: live,
		G5Liveness:   map[bool]string{true: "reached", false: "held-safe"}[live],
	})

	return out
}
