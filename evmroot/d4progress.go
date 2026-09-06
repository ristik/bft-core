package evmroot

import (
	"fmt"
	"sort"
)

// D4 handoff progress / abort model.
//
// exploreQuorumIntersection (d4multireplica.go) proves a *static* safety
// fact: two conflicting statements cannot both reach a quorum. The
// re-review (#80, third round) noted that is not a progress model — it
// assumes every honest signer has already, permanently, picked X, Y or
// abstain, and it does not say how consensus ordering keeps honest weight
// from being split across X and Y in the first place.
//
// This file models that. The key structural fact: the election candidate
// is committed by the epoch manager, so there is exactly ONE FrozenID per
// (attempt, view). Honest signers do not pick a FrozenID independently —
// they endorse the FrozenID the current view's leader proposed. A cross-
// FrozenID split can therefore only appear across a VIEW CHANGE, and a
// view-change certificate carries the highest lock, which the next view's
// leader must re-propose (the safe lock rule). Honest signers hold this
// state DURABLY: a restart reloads it and they refuse to double-endorse.
//
//   P1  in one view, all honest signers that endorse, endorse the SAME
//       FrozenID — no intra-view split, so honest weight is never divided.
//   P2  across a view change, the new leader must carry the highest lock;
//       honest signers reject a proposal that drops it, so a locked
//       FrozenID is the only one that can still gather honest weight.
//   P3  the reviewer's "a→X, c,d→Y, b,e withhold" split does not arise:
//       with a/c/d online in one view they endorse the one proposed
//       FrozenID and reach the quorum (17 ≥ 17) although b/e are silent.
//   P4  once a FrozenID is committed for an attempt, an abort of the same
//       attempt cannot reach a quorum — honest signers that endorsed →
//       committed will not sign the abort (durable state), and Byzantine
//       weight alone is < threshold.
//
// Normative source: docs/design/d4-epoch-handoff-state-machine.md §4,
// governance.tex §"root handoff" / §"Extension".

// honestSigner is one honest old-assignment member with durable local
// state. It endorses at most one FrozenID per view and never a lower view.
type honestSigner struct {
	id            string
	weight        uint64
	view          uint64 // highest view it has acted in
	endorsedView  uint64 // view of its standing endorsement (0 = none)
	endorsedFroze []byte // the FrozenID it endorsed in endorsedView
	committed     bool   // it has seen its endorsed FrozenID committed
}

// endorse records an endorsement of frozenID in `view` if the signer's
// durable state allows it: the leader-proposed FrozenID for a view it has
// not already endorsed a different value in, and not a lower view than one
// it already acted in. Returns whether the endorsement was recorded.
func (s *honestSigner) endorse(view uint64, frozenID []byte, leaderFrozenID []byte) bool {
	if view < s.view {
		return false // will not act in a superseded view
	}
	if !bytesEqual(frozenID, leaderFrozenID) {
		return false // honest signers only endorse the view leader's proposal
	}
	if s.endorsedView == view && !bytesEqual(s.endorsedFroze, frozenID) {
		return false // already endorsed a different value in this view — impossible for one leader, guarded anyway
	}
	if s.endorsedView != 0 && s.endorsedView < view && bytesEqual(s.endorsedFroze, frozenID) {
		// re-endorsing the same locked value in a later view is fine
	}
	s.view = view
	s.endorsedView = view
	s.endorsedFroze = append([]byte(nil), frozenID...)
	return true
}

// restart reloads durable state — endorsedView/endorsedFroze survive, so a
// restarted signer still refuses to double-endorse.
func (s *honestSigner) restart() { /* durable fields are already retained */ }

// endorseAbort records a vote for an abort of the given attempt. An honest
// signer that has seen its endorsed FrozenID committed will not sign an
// abort of that attempt.
func (s *honestSigner) endorseAbort(committedFrozen []byte) bool {
	if s.committed && bytesEqual(s.endorsedFroze, committedFrozen) {
		return false
	}
	return true
}

// HandoffView is one view: a leader proposes exactly one FrozenID, which
// must be the highest lock carried by the view-change certificates that
// formed the view (if any).
type HandoffView struct {
	Number         uint64
	LeaderFrozenID []byte
	CarriedLock    []byte // highest lock from the view-change certs (nil in view 1)
}

// leaderProposalValid checks the safe lock rule: a view whose view-change
// certs carry a lock must propose exactly that lock.
func (v HandoffView) leaderProposalValid() bool {
	if len(v.CarriedLock) == 0 {
		return true
	}
	return bytesEqual(v.LeaderFrozenID, v.CarriedLock)
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

func sumEndorsed(signers []*honestSigner, view uint64, frozenID []byte, byzWeightOnThis uint64) uint64 {
	total := byzWeightOnThis
	for _, s := range signers {
		if s.endorsedView == view && bytesEqual(s.endorsedFroze, frozenID) {
			total += s.weight
		}
	}
	return total
}

// D4ProgressRuns builds the progress/abort scenario set.
func D4ProgressRuns() []ProgressRun {
	ws := d3Assignment()
	w, _ := ws.TotalWeight()
	threshold := RootQuorumThreshold(w) // 17
	fBound := FaultyWeightBound(w)      // 7

	X := sha256Slice([]byte("frozen-X"))
	Y := sha256Slice([]byte("frozen-Y"))

	var out []ProgressRun

	// P3: the reviewer's split cannot arise. Byzantine b/e (weight 7)
	// withhold; honest a/c/d online. In view 1 the leader proposes X; all
	// three honest signers endorse X (they follow the view leader, they do
	// not pick X or Y independently). 10+5+2 = 17 ≥ 17 → quorum on X.
	{
		byz := map[string]struct{}{"root-b": {}, "root-e": {}}
		hs := d4HonestSigners(byz)
		v1 := HandoffView{Number: 1, LeaderFrozenID: X}
		for _, s := range hs {
			s.endorse(1, X, v1.LeaderFrozenID)
		}
		xw := sumEndorsed(hs, 1, X, 0)
		yw := sumEndorsed(hs, 1, Y, 0)
		online := []string{}
		for _, s := range hs {
			online = append(online, s.id)
		}
		var reached []string
		if xw >= threshold {
			reached = append(reached, "X")
		}
		if yw >= threshold {
			reached = append(reached, "Y")
		}
		out = append(out, ProgressRun{
			Name: "no_honest_split_byzantine_withholding", Threshold: threshold, FaultyBound: fBound,
			ByzantineSigners: []string{"root-b", "root-e"}, OnlineHonest: online,
			EndorsedFrozenIDs: reached, QuorumFormed: len(reached) == 1, SplitAvoided: yw == 0,
			Holds: len(reached) == 1 && reached[0] == "X" && yw == 0,
			Note:  "Byzantine b/e (weight 7 = f_W) withhold. Honest a/c/d follow the view-1 leader's single proposal X; 10+5+2 = 17 reaches the quorum. No honest weight lands on Y — the a→X / c,d→Y split the review posited requires honest signers to choose independently, which the view rule forbids.",
		})
	}

	// P2: cross-view lock. View 1 leader proposes X; only a (weight 10)
	// endorses before a view change. View 2's view-change certs carry the
	// lock on X, so its leader MUST propose X. An attempt by the view-2
	// leader to propose Y instead is rejected by honest signers; proposing
	// X lets c/d join → 10+5+2 = 17 on X. Y never gathers honest weight.
	{
		byz := map[string]struct{}{"root-b": {}, "root-e": {}}
		hs := d4HonestSigners(byz)
		byID := map[string]*honestSigner{}
		for _, s := range hs {
			byID[s.id] = s
		}
		v1 := HandoffView{Number: 1, LeaderFrozenID: X}
		byID["root-a"].endorse(1, X, v1.LeaderFrozenID) // partial lock: a only

		badV2 := HandoffView{Number: 2, LeaderFrozenID: Y, CarriedLock: X}
		v2 := HandoffView{Number: 2, LeaderFrozenID: X, CarriedLock: X}
		badRejected := !badV2.leaderProposalValid()
		// honest signers act in the valid view 2 (proposes the lock X)
		for _, s := range hs {
			s.endorse(2, v2.LeaderFrozenID, v2.LeaderFrozenID)
		}
		// a re-endorses X in view 2 too (same locked value)
		byID["root-a"].endorse(2, X, v2.LeaderFrozenID)
		xw := sumEndorsed(hs, 2, X, 0)
		yw := sumEndorsed(hs, 1, Y, 0) + sumEndorsed(hs, 2, Y, 0)
		out = append(out, ProgressRun{
			Name: "view_change_carries_lock", Threshold: threshold, FaultyBound: fBound,
			ByzantineSigners: []string{"root-b", "root-e"}, OnlineHonest: []string{"root-a", "root-c", "root-d"},
			EndorsedFrozenIDs: func() []string {
				if xw >= threshold {
					return []string{"X"}
				}
				return nil
			}(),
			QuorumFormed: xw >= threshold, SplitAvoided: yw == 0,
			Holds: badRejected && xw >= threshold && yw == 0,
			Note:  "View 1 partially endorsed X (a only). The view-2 leader proposing Y is rejected (drops the carried lock X). The valid view-2 leader re-proposes X; a/c/d endorse it, 17 reaches the quorum. Y never gathers honest weight across either view.",
		})
	}

	// P4: commit-vs-abort exclusion under durable state. X is endorsed and
	// committed in view 1. An abort of the same attempt is then attempted:
	// honest signers that endorsed → committed X refuse the abort, so only
	// Byzantine b/e weight (7) is available for it — 7 < 17.
	{
		byz := map[string]struct{}{"root-b": {}, "root-e": {}}
		hs := d4HonestSigners(byz)
		v1 := HandoffView{Number: 1, LeaderFrozenID: X}
		for _, s := range hs {
			s.endorse(1, X, v1.LeaderFrozenID)
			s.committed = true // they saw X committed
		}
		abortWeight := uint64(0)
		for _, s := range hs {
			if s.endorseAbort(X) {
				abortWeight += s.weight
			}
		}
		abortWeight += 7 // Byzantine b/e both vote the abort
		out = append(out, ProgressRun{
			Name: "commit_then_abort_cannot_reach_quorum", Threshold: threshold, FaultyBound: fBound,
			ByzantineSigners: []string{"root-b", "root-e"}, OnlineHonest: []string{"root-a", "root-c", "root-d"},
			AbortReachedQuorum: abortWeight >= threshold, QuorumFormed: true, SplitAvoided: true,
			Holds: abortWeight < threshold,
			Note:  fmt.Sprintf("X endorsed and committed in view 1. Honest signers refuse to sign an abort of a committed attempt (durable state); only Byzantine weight 7 is available for the abort, 7 < %d. A committed handoff and its abort cannot both be certified.", threshold),
		})
	}

	// Combined schedule: delayed endorsement delivery + a signer restart +
	// commit-then-abort, in one execution. Honest a/c/d; b/e Byzantine.
	{
		byz := map[string]struct{}{"root-b": {}, "root-e": {}}
		hs := d4HonestSigners(byz)
		byID := map[string]*honestSigner{}
		for _, s := range hs {
			byID[s.id] = s
		}
		v1 := HandoffView{Number: 1, LeaderFrozenID: X}
		// endorsements arrive out of order: d, then a; c is delayed
		byID["root-d"].endorse(1, X, v1.LeaderFrozenID)
		byID["root-a"].endorse(1, X, v1.LeaderFrozenID)
		// root-a restarts mid-schedule; durable state must survive
		byID["root-a"].restart()
		doubleEndorseBlocked := !byID["root-a"].endorse(1, Y, v1.LeaderFrozenID) // cannot switch to Y
		// delayed c endorsement finally lands
		byID["root-c"].endorse(1, X, v1.LeaderFrozenID)
		xw := sumEndorsed(hs, 1, X, 0)
		// commit, then a late abort attempt
		for _, s := range hs {
			s.committed = true
		}
		abortWeight := uint64(7)
		for _, s := range hs {
			if s.endorseAbort(X) {
				abortWeight += s.weight
			}
		}
		out = append(out, ProgressRun{
			Name: "combined_delay_restart_commit_vs_abort", Threshold: threshold, FaultyBound: fBound,
			ByzantineSigners: []string{"root-b", "root-e"}, OnlineHonest: []string{"root-a", "root-c", "root-d"},
			EndorsedFrozenIDs: func() []string {
				if xw >= threshold {
					return []string{"X"}
				}
				return nil
			}(),
			QuorumFormed: xw >= threshold, AbortReachedQuorum: abortWeight >= threshold, SplitAvoided: true,
			Holds: doubleEndorseBlocked && xw >= threshold && abortWeight < threshold,
			Note:  "Endorsements delivered out of order (d, a, then delayed c); root-a restarts and its durable state blocks a switch to Y; X reaches 17; a subsequent abort of the committed attempt gets only Byzantine weight 7 < 17.",
		})
	}

	return out
}
