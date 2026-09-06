package evmroot

import (
	"fmt"
	"sort"
)

// D4 handoff progress / abort model — rev 2 (fourth review, #80).
//
// The third-review version modelled a bespoke "handoff view-change"
// protocol with a lock rule. The re-review showed that model does not hold
// for its own callable state machine: a Byzantine handoff leader can send
// X to signer a and Y to signers c/d within one "view", and an honest
// signer that "follows the leader" accepts whatever it received — the split
// the model claimed to exclude. And "merely following a leader is not
// agreement".
//
// The fix is to stop inventing a second consensus. The FREEZE record —
// like every handoff record — is committed by the EXISTING root BFT
// consensus before any endorsement. Root consensus commits at most one
// freeze per (attempt, predecessor) (quorum intersection at the root
// level). So an honest signer endorses a FrozenID ONLY if it carries a
// FrozenOrdered proof (the verifier's authenticated view of that root
// commit). A Byzantine handoff leader cannot obtain such a proof for two
// different FrozenIDs, so it cannot split honest weight. Honest signers
// also hold durable local state: once they endorsed the root-ordered
// FrozenID F for attempt j they will not endorse a different value for j,
// and will not sign an abort of a committed F — a restart reloads that
// state.
//
//   P1  a Byzantine handoff leader cannot split honest weight: only the
//       root-ordered FrozenID gathers honest endorsements; the other gets
//       at most Byzantine weight (< threshold).
//   P2  two root-ordered FrozenIDs for one (attempt, predecessor) is a
//       root-consensus violation (two root quorums for the same slot) —
//       the model flags it, it is not something the handoff has to resolve.
//   P3  durable state survives a restart: an honest signer will not switch
//       its endorsement to a different FrozenID even when handed a
//       valid-looking FrozenOrdered proof for it.
//   P4  a committed attempt's abort cannot reach a quorum — honest signers
//       that endorsed -> committed F refuse it; only Byzantine weight is
//       available.
//   P5  the combined schedule (delayed delivery + restart + commit-vs-abort
//       + Byzantine equivocation) preserves P1 and P4.
//
// Normative source: docs/design/d4-epoch-handoff-state-machine.md §4,
// governance.tex §"root handoff".

// honestSigner is one honest old-assignment member with durable local
// state.
type honestSigner struct {
	id            string
	weight        uint64
	endorsedFroze []byte // the FrozenID it has a standing endorsement for (nil = none)
	committed     bool   // it has seen its endorsed FrozenID committed
}

// endorse records an endorsement of frozenID iff:
//   - the FrozenOrdered proof authenticates THIS exact frozenID against the
//     root chain (a Byzantine leader has no such proof for a second value);
//   - the signer has not already endorsed a DIFFERENT FrozenID (durable
//     state — unconditional, survives restart).
func (s *honestSigner) endorse(frozenID []byte, fo FrozenOrdered, oldThreshold uint64) bool {
	if !fo.authenticates(frozenID, oldThreshold) {
		return false
	}
	if s.endorsedFroze != nil && !bytesEqual(s.endorsedFroze, frozenID) {
		return false
	}
	s.endorsedFroze = append([]byte(nil), frozenID...)
	return true
}

// restart reloads durable state — endorsedFroze / committed are retained,
// so a restarted signer still refuses to double-endorse.
func (s *honestSigner) restart() {}

// endorseAbort: an honest signer that saw its endorsed FrozenID committed
// will not sign an abort of that attempt.
func (s *honestSigner) endorseAbort(committedFrozen []byte) bool {
	return !(s.committed && bytesEqual(s.endorsedFroze, committedFrozen))
}

// rootOrdersAtMostOne reports whether two FrozenOrdered proofs for the same
// (attempt, predecessor) slot could BOTH be genuine. They cannot: each
// needs a root quorum, and two root quorums for one commit slot violate
// quorum intersection. The model flags this rather than "resolving" it.
func rootOrdersAtMostOne(a, b FrozenOrdered, oldThreshold uint64) (bothClaimQuorum, isViolation bool) {
	aOK := len(a.FrozenID) == 32 && a.RootCommit.QuorumWeight >= oldThreshold
	bOK := len(b.FrozenID) == 32 && b.RootCommit.QuorumWeight >= oldThreshold
	if aOK && bOK && !bytesEqual(a.FrozenID, b.FrozenID) {
		return true, true
	}
	return aOK && bOK, false
}

// ProgressRun is one progress/abort scenario outcome.
type ProgressRun struct {
	Name               string   `json:"name"`
	Note               string   `json:"note"`
	Threshold          uint64   `json:"threshold"`
	FaultyBound        uint64   `json:"faulty_weight_bound"`
	ByzantineSigners   []string `json:"byzantine_signers"`
	OnlineHonest       []string `json:"online_honest_signers"`
	EndorsedFrozenIDs  []string `json:"frozen_ids_that_reached_a_quorum"`
	AbortReachedQuorum bool     `json:"abort_reached_a_quorum"`
	QuorumFormed       bool     `json:"a_quorum_formed"`
	SplitAvoided       bool     `json:"honest_weight_not_split"`
	Holds              bool     `json:"property_holds"`
}

func d4HonestSigners(byz map[string]struct{}) []*honestSigner {
	ws := d3Assignment()
	var out []*honestSigner
	for _, m := range ws {
		if _, b := byz[m.NodeID]; b {
			continue
		}
		out = append(out, &honestSigner{id: m.NodeID, weight: m.Weight})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].id < out[j].id })
	return out
}

func honestWeightOn(signers []*honestSigner, frozenID []byte) uint64 {
	var w uint64
	for _, s := range signers {
		if bytesEqual(s.endorsedFroze, frozenID) {
			w += s.weight
		}
	}
	return w
}

// d4FrozenOrdered fabricates the verifier's AUTHENTICATED view of the root
// commit that ordered a freeze — the verified external precondition. In the
// model a genuine one has QuorumWeight >= threshold.
func d4FrozenOrdered(frozenID []byte, quorumWeight uint64) FrozenOrdered {
	return FrozenOrdered{
		FrozenID: frozenID,
		RootCommit: RootCommit{
			CommitID: sha256Slice([]byte("d4-freeze-commit:" + string(frozenID))), Round: 40,
			ParentID: rep(0x00, 32), CommittedRootHash: rep(0x5A, 32), QuorumWeight: quorumWeight,
		},
	}
}

// D4ProgressRuns builds the progress/abort scenario set.
func D4ProgressRuns() []ProgressRun {
	ws := d3Assignment()
	w, _ := ws.TotalWeight()
	threshold := RootQuorumThreshold(w) // 17
	fBound := FaultyWeightBound(w)      // 7

	X := sha256Slice([]byte("frozen-X"))
	Y := sha256Slice([]byte("frozen-Y"))
	foX := d4FrozenOrdered(X, threshold+4) // genuinely root-ordered
	noProof := FrozenOrdered{}             // Y was NOT ordered by root consensus

	var out []ProgressRun

	// P1: a Byzantine handoff leader sends X to a and Y to c/d. Only X is
	// root-ordered. a endorses X (has proof); c/d reject Y (no proof) and
	// later endorse X (proof arrives by gossip). Byzantine b/e (weight 7)
	// endorse Y. X: 10+5+2 = 17 >= 17. Y: 7 < 17. No honest weight on Y.
	{
		byz := map[string]struct{}{"root-b": {}, "root-e": {}}
		hs := d4HonestSigners(byz)
		byID := map[string]*honestSigner{}
		for _, s := range hs {
			byID[s.id] = s
		}
		byID["root-a"].endorse(X, foX, threshold)                   // leader sent a -> X (root-ordered)
		cRejectsY := !byID["root-c"].endorse(Y, noProof, threshold) // leader sent c -> Y (no proof)
		dRejectsY := !byID["root-d"].endorse(Y, noProof, threshold) // leader sent d -> Y (no proof)
		byID["root-c"].endorse(X, foX, threshold)                   // X's proof reaches c
		byID["root-d"].endorse(X, foX, threshold)                   // and d
		xw := honestWeightOn(hs, X)
		yw := honestWeightOn(hs, Y) + 7 // Byzantine b/e also "endorse" Y
		var reached []string
		if xw >= threshold {
			reached = append(reached, "X")
		}
		if yw >= threshold {
			reached = append(reached, "Y")
		}
		out = append(out, ProgressRun{
			Name: "byzantine_leader_cannot_split_honest_weight", Threshold: threshold, FaultyBound: fBound,
			ByzantineSigners: []string{"root-b", "root-e"}, OnlineHonest: []string{"root-a", "root-c", "root-d"},
			EndorsedFrozenIDs: reached, QuorumFormed: len(reached) == 1, SplitAvoided: honestWeightOn(hs, Y) == 0,
			Holds: cRejectsY && dRejectsY && len(reached) == 1 && reached[0] == "X" && honestWeightOn(hs, Y) == 0,
			Note:  "A Byzantine handoff leader sends X to a and Y to c/d in the same attempt. Only the FREEZE for X was committed by the existing root BFT consensus, so only X carries a FrozenOrdered proof. Honest signers endorse only a root-ordered FrozenID: a keeps X, c/d reject Y and adopt X. X reaches 17; Y gets only Byzantine weight 7. Honest weight is never split.",
		})
	}

	// P2: two root-ordered FrozenIDs for one (attempt, predecessor) is a
	// root-consensus violation, not a handoff problem.
	{
		foY := d4FrozenOrdered(Y, threshold+4)
		_, isViolation := rootOrdersAtMostOne(foX, foY, threshold)
		out = append(out, ProgressRun{
			Name: "two_root_ordered_frozen_ids_is_a_root_violation", Threshold: threshold, FaultyBound: fBound,
			Holds: isViolation,
			Note:  "Two FrozenOrdered proofs with distinct FrozenIDs, both quorate, for one (attempt, predecessor) slot. Each needs a root quorum; two root quorums for one commit slot violate quorum intersection. The model FLAGS this as a root-consensus violation — the handoff state machine does not have to resolve it.",
		})
	}

	// P3: durable state survives a restart. a endorses X, restarts, then is
	// handed a valid-looking FrozenOrdered proof for Y -> still refused.
	{
		s := &honestSigner{id: "root-a", weight: 10}
		e1 := s.endorse(X, foX, threshold)
		s.restart()
		foY := d4FrozenOrdered(Y, threshold+4)
		switched := s.endorse(Y, foY, threshold)      // must be false
		reEndorseSame := s.endorse(X, foX, threshold) // re-endorsing the same value is fine
		out = append(out, ProgressRun{
			Name: "durable_state_survives_restart", Threshold: threshold, FaultyBound: fBound,
			Holds: e1 && !switched && reEndorseSame,
			Note:  "root-a endorses X, restarts (durable endorsedFroze retained), then is handed a valid-looking FrozenOrdered proof for Y. The unconditional durable-state check refuses the switch; re-endorsing the same X is still allowed.",
		})
	}

	// P4: a committed attempt's abort cannot reach a quorum.
	{
		byz := map[string]struct{}{"root-b": {}, "root-e": {}}
		hs := d4HonestSigners(byz)
		for _, s := range hs {
			s.endorse(X, foX, threshold)
			s.committed = true
		}
		abortWeight := uint64(7) // Byzantine b/e vote the abort
		for _, s := range hs {
			if s.endorseAbort(X) {
				abortWeight += s.weight
			}
		}
		out = append(out, ProgressRun{
			Name: "commit_then_abort_cannot_reach_quorum", Threshold: threshold, FaultyBound: fBound,
			ByzantineSigners: []string{"root-b", "root-e"}, OnlineHonest: []string{"root-a", "root-c", "root-d"},
			AbortReachedQuorum: abortWeight >= threshold, QuorumFormed: true, SplitAvoided: true,
			Holds: abortWeight < threshold,
			Note:  fmt.Sprintf("X endorsed and committed. Honest signers refuse to sign an abort of a committed attempt; only Byzantine weight 7 < %d is available. A committed handoff and its abort cannot both be certified.", threshold),
		})
	}

	// P5: combined schedule — delayed delivery, restart, Byzantine
	// equivocation, then a late abort.
	{
		byz := map[string]struct{}{"root-b": {}, "root-e": {}}
		hs := d4HonestSigners(byz)
		byID := map[string]*honestSigner{}
		for _, s := range hs {
			byID[s.id] = s
		}
		byID["root-d"].endorse(X, foX, threshold) // out-of-order: d first
		byID["root-a"].endorse(X, foX, threshold)
		byID["root-a"].restart()
		foY := d4FrozenOrdered(Y, threshold+4)
		switchBlocked := !byID["root-a"].endorse(Y, foY, threshold) // restart-durable refusal
		byID["root-c"].endorse(X, foX, threshold)                   // delayed c lands
		xw := honestWeightOn(hs, X)
		for _, s := range hs {
			s.committed = true
		}
		abortWeight := uint64(7)
		for _, s := range hs {
			if s.endorseAbort(X) {
				abortWeight += s.weight
			}
		}
		var reached []string
		if xw >= threshold {
			reached = append(reached, "X")
		}
		out = append(out, ProgressRun{
			Name: "combined_delay_restart_equivocation_abort", Threshold: threshold, FaultyBound: fBound,
			ByzantineSigners: []string{"root-b", "root-e"}, OnlineHonest: []string{"root-a", "root-c", "root-d"},
			EndorsedFrozenIDs: reached, QuorumFormed: xw >= threshold, AbortReachedQuorum: abortWeight >= threshold, SplitAvoided: honestWeightOn(hs, Y) == 0,
			Holds: switchBlocked && xw >= threshold && honestWeightOn(hs, Y) == 0 && abortWeight < threshold,
			Note:  "Endorsements delivered out of order (d, a, then delayed c); root-a restarts and its durable state blocks a switch to Y; Byzantine b/e equivocate; X reaches 17 with nothing on Y; a subsequent abort of the committed attempt gets only weight 7.",
		})
	}

	return out
}
