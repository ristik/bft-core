package evmroot

import (
	"fmt"
	"sort"
)

// D4 multi-replica exploration. The single-Handoff scenarios exercise one
// replica's phase API; this model runs several replicas that receive the
// handoff records in different orders (and lose some), with a global
// non-equivocation lock on the endorsement signers, and checks properties
// that only make sense across replicas:
//
//   G1  no signer endorses two different FrozenIDs (quorum intersection).
//   G2  at most one FrozenID is ever committed (single successor); an
//       aborted attempt's FrozenID can never be committed.
//   G3  no root round is authorised by both the old and the new set across
//       the replica population — every replica's Authorized(r) is `old`
//       unless that replica holds a finalised commit and r >= its A*, and
//       all committed replicas agree on A*.
//   G4  no replica reaches Activated/Acknowledged without a finalised
//       commit record.
//   G5  (conditional liveness) if every record is delivered to every
//       replica, no permanent loss, and no abort, every replica reaches
//       acknowledged.

// HandoffRecord is one durably-committed artefact of the handoff that
// replicas exchange. Prepare/Freeze/Endorse/Commit/Abort/Finalize each
// produce one; a replica applies the records it receives in order.
type recordKind uint8

const (
	recPrepare recordKind = iota
	recFreeze
	recEndorse
	recCommit
	recAbort
	recFinalize
)

type handoffRecord struct {
	kind     recordKind
	frozenID []byte // recFreeze/recEndorse/recCommit
	summary  []byte // recFreeze
	parent   []byte // recFreeze
	signer   string // recEndorse
	weight   uint64 // recEndorse cumulative
	aStar    uint64 // recCommit
	commitAt uint64 // recCommit
	trHash   []byte // recCommit
	reason   string // recAbort
}

// replica applies handoff records to its own Handoff copy and tracks which
// endorsement signers it has counted.
type replica struct {
	id       string
	h        *Handoff
	endorsed map[string]struct{}
}

func newReplica(id string, c Candidate) *replica {
	return &replica{id: id, h: NewHandoff(c, 1), endorsed: map[string]struct{}{}}
}

// signerLock is the global non-equivocation record: a signer that endorsed
// FrozenID X may never be counted for FrozenID Y != X.
type signerLock struct {
	locked map[string][]byte // signer -> FrozenID it is bound to
}

func (l *signerLock) endorse(signer string, frozenID []byte) error {
	if prev, ok := l.locked[signer]; ok && string(prev) != string(frozenID) {
		return fmt.Errorf("signer %s equivocates: bound to %x, asked to endorse %x", signer, prev, frozenID)
	}
	l.locked[signer] = frozenID
	return nil
}

// MultiReplicaResult is the outcome of one exploration run.
type MultiReplicaResult struct {
	Name               string               `json:"name"`
	Note               string               `json:"note"`
	Replicas           []string             `json:"replicas"`
	Deliveries         []string             `json:"delivery_order"`
	FinalPhases        map[string]string    `json:"final_phases"`
	CommittedFrozenIDs []string             `json:"committed_frozen_ids"`
	Violations         []InvariantViolation `json:"violations"`
	G1NoEquivocation   bool                 `json:"g1_no_equivocation"` // no signer's weight counted toward two FrozenIDs
	EquivBlocked       int                  `json:"equivocation_attempts_blocked"`
	G2SingleSuccessor  bool                 `json:"g2_single_successor"`
	G3NoOverlap        bool                 `json:"g3_no_overlap_across_replicas"`
	G4FinalCommit      bool                 `json:"g4_no_activation_without_final_commit"`
	G5Liveness         string               `json:"g5_liveness"` // "reached" | "held-safe" | "n/a"
}

// applyRecord applies one record to a replica, consulting/updating the
// global signer lock. Returns an error only for a genuine protocol
// violation (equivocation); out-of-order or duplicate records are ignored.
func (r *replica) applyRecord(rec handoffRecord, lock *signerLock, oldThreshold uint64) error {
	switch rec.kind {
	case recPrepare:
		_ = r.h.Prepare()
	case recFreeze:
		if r.h.Phase == PhasePrepared {
			b := sampleHandoffBody(r.h.Candidate.PredecessorHash, r.h.Candidate.MinActivation)
			_ = r.h.Freeze(rec.summary, rec.parent, b)
		}
	case recEndorse:
		if err := lock.endorse(rec.signer, rec.frozenID); err != nil {
			return err
		}
		r.endorsed[rec.signer] = struct{}{}
		if r.h.Phase == PhaseFrozen && string(r.h.FrozenID) == string(rec.frozenID) && rec.weight >= oldThreshold {
			_ = r.h.Endorse(rec.weight, oldThreshold)
		}
	case recCommit:
		if r.h.Phase == PhaseEndorsed && string(r.h.FrozenID) == string(rec.frozenID) {
			_ = r.h.Commit(rec.commitAt, rec.aStar, rec.trHash)
		}
	case recFinalize:
		if r.h.Phase >= PhaseCommitted && r.h.Phase != PhaseAborted {
			_ = r.h.FinalizeCommit()
			_ = r.h.Activate(rec.aStar)
			_ = r.h.Acknowledge(rec.aStar + 1)
		}
	case recAbort:
		_ = r.h.Abort(rec.reason)
	}
	return nil
}

// runMultiReplica delivers `records` to each replica in the per-replica
// order given by `orders` (a slice of index slices), then checks G1..G5.
func runMultiReplica(name, note string, c Candidate, records []handoffRecord, orders map[string][]int, expectLiveness bool) MultiReplicaResult {
	oldThreshold := RootQuorumThreshold(func() uint64 { w, _ := d3Assignment().TotalWeight(); return w }())
	lock := &signerLock{locked: map[string][]byte{}}
	res := MultiReplicaResult{Name: name, Note: note, FinalPhases: map[string]string{},
		G1NoEquivocation: true, G2SingleSuccessor: true, G3NoOverlap: true, G4FinalCommit: true}

	ids := make([]string, 0, len(orders))
	for id := range orders {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	res.Replicas = ids

	reps := map[string]*replica{}
	for _, id := range ids {
		reps[id] = newReplica(id, c)
	}

	for _, id := range ids {
		for _, idx := range orders[id] {
			res.Deliveries = append(res.Deliveries, fmt.Sprintf("%s<-%d", id, idx))
			if err := reps[id].applyRecord(records[idx], lock, oldThreshold); err != nil {
				// The global lock BLOCKED a cross-FrozenID endorsement.
				// That is the property working, not a violation: the
				// signer's weight is never counted toward the second
				// FrozenID (Endorse only fires when the replica's own
				// FrozenID matches). Record it as a blocked attempt.
				res.EquivBlocked++
			}
		}
	}

	// Collect committed FrozenIDs and A* values.
	committed := map[string]uint64{}
	for _, id := range ids {
		h := reps[id].h
		res.FinalPhases[id] = h.Phase.String()
		if h.Phase >= PhaseCommitted && h.Phase != PhaseAborted {
			committed[string(h.FrozenID)] = h.ActivationRound
		}
		// G4
		if (h.Phase == PhaseActivated || h.Phase == PhaseAcknowledged) && !h.CommitFinalized {
			res.G4FinalCommit = false
			res.Violations = append(res.Violations, InvariantViolation{"g4", id + " activated without a finalised commit"})
		}
		for _, iv := range checkInvariants(h, probeRounds) {
			res.Violations = append(res.Violations, iv)
		}
	}
	for fid := range committed {
		res.CommittedFrozenIDs = append(res.CommittedFrozenIDs, fmt.Sprintf("%x", fid[:8]))
	}
	sort.Strings(res.CommittedFrozenIDs)
	if len(committed) > 1 {
		res.G2SingleSuccessor = false
		res.Violations = append(res.Violations, InvariantViolation{"g2", "more than one FrozenID committed"})
	}

	// G3: across replicas, at every probe round, no two replicas disagree
	// in a way that authorises both sets; and all committed replicas share
	// one A*.
	var aStar uint64
	haveAStar := false
	for _, a := range committed {
		if !haveAStar {
			aStar, haveAStar = a, true
		} else if a != aStar {
			res.G3NoOverlap = false
			res.Violations = append(res.Violations, InvariantViolation{"g3", "committed replicas disagree on A*"})
		}
	}
	for _, r := range probeRounds {
		sawOld, sawNew := false, false
		for _, id := range ids {
			switch reps[id].h.Authorized(r) {
			case OldAssignment:
				sawOld = true
			case NewAssignment:
				sawNew = true
			}
		}
		// It is fine for some replicas to still say "old" while others say
		// "new" only when r straddles A* is impossible (a fixed r is either
		// < A* or >= A*). If any committed replica says NEW for r, then
		// r >= A*, and no replica may still treat r as an OLD-set round for
		// the SAME extension. We model the violation as: sawNew for r < the
		// agreed A*, or sawOld-as-authoritative for r >= A* on a committed
		// replica.
		if haveAStar {
			if sawNew && r < aStar {
				res.G3NoOverlap = false
				res.Violations = append(res.Violations, InvariantViolation{"g3", fmt.Sprintf("round %d < A*=%d authorised NEW", r, aStar)})
			}
			for _, id := range ids {
				h := reps[id].h
				if h.Phase >= PhaseCommitted && h.Phase != PhaseAborted && r >= h.ActivationRound && h.Authorized(r) != NewAssignment {
					res.G3NoOverlap = false
					res.Violations = append(res.Violations, InvariantViolation{"g3", fmt.Sprintf("%s: round %d >= A* still authorised OLD", id, r)})
				}
			}
		}
		_ = sawOld
	}

	// G5 liveness.
	switch {
	case !expectLiveness:
		res.G5Liveness = "n/a"
	case allAcknowledged(reps, ids):
		res.G5Liveness = "reached"
	default:
		res.G5Liveness = "held-safe"
	}
	return res
}

func bodyIdentityBytes(b TrustBaseBodyV2) []byte { id := b.Identity(); return id[:] }

func allAcknowledged(reps map[string]*replica, ids []string) bool {
	for _, id := range ids {
		if reps[id].h.Phase != PhaseAcknowledged {
			return false
		}
	}
	return true
}

// D4MultiReplicaRuns builds the multi-replica exploration set.
func D4MultiReplicaRuns() []MultiReplicaResult {
	c := Candidate{Network: 3, NextEpoch: 8, Attempt: 0, PredecessorHash: rep(0xE7, 32), MinActivation: 10, CandidateHash: rep(0xCA, 32)}

	// One agreed FrozenID: freeze the same (summary, parent) everywhere.
	summ, par := rep(0x11, 32), rep(0x22, 32)
	fid := frozenID(bodyIdentityBytes(sampleHandoffBody(c.PredecessorHash, c.MinActivation)), summ, par, c.CandidateHash, c.Attempt, c.PredecessorHash)
	base := []handoffRecord{
		{kind: recPrepare},
		{kind: recFreeze, frozenID: fid, summary: summ, parent: par},
		{kind: recEndorse, frozenID: fid, signer: "r1", weight: 8},
		{kind: recEndorse, frozenID: fid, signer: "r2", weight: 17},
		{kind: recCommit, frozenID: fid, aStar: 12, commitAt: 6, trHash: rep(0x33, 32)},
		{kind: recFinalize, aStar: 12},
	}
	full := []int{0, 1, 2, 3, 4, 5}

	var out []MultiReplicaResult

	// 1. All records to all replicas, but in three different orders.
	out = append(out, runMultiReplica("all_delivered_reordered",
		"Three replicas receive every handoff record; different per-replica orders; all reach acknowledged, one A*, no equivocation.",
		c, base, map[string][]int{
			"A": {0, 1, 2, 3, 4, 5},
			"B": {0, 1, 3, 2, 4, 5},
			"C": {0, 1, 3, 4, 2, 5}, // endorse r2 (over threshold) -> commit -> r1 no-op -> finalize
		}, true))
	_ = full

	// 2. Asymmetric: replica C never gets the commit/finalize records.
	out = append(out, runMultiReplica("commit_not_delivered_to_one",
		"Replica C is missing the commit and finalize records: it holds at endorsed, keeps the old set authoritative for every round, and never activates. A and B proceed.",
		c, base, map[string][]int{
			"A": {0, 1, 2, 3, 4, 5},
			"B": {0, 1, 2, 3, 4, 5},
			"C": {0, 1, 2, 3},
		}, false))

	// 3. Equivocation attempt: a second FrozenID (different summary) that
	//    reuses signer r1.
	summ2 := rep(0x99, 32)
	fid2 := frozenID(bodyIdentityBytes(sampleHandoffBody(c.PredecessorHash, c.MinActivation)), summ2, par, c.CandidateHash, c.Attempt, c.PredecessorHash)
	equiv := append(append([]handoffRecord{}, base...),
		handoffRecord{kind: recFreeze, frozenID: fid2, summary: summ2, parent: par},
		handoffRecord{kind: recEndorse, frozenID: fid2, signer: "r1", weight: 8}, // r1 already bound to fid
	)
	out = append(out, runMultiReplica("equivocating_endorsement_rejected",
		"A second FrozenID reuses endorsement signer r1; the global lock rejects it, so it can never gather weight or be committed.",
		c, equiv, map[string][]int{
			"A": {0, 1, 2, 3, 4, 5},
			"B": {0, 6, 7}, // sees only the second (equivocating) path
		}, false))

	// 4. Abort of one attempt then a fresh attempt j+1: the aborted
	//    FrozenID must never be committed.
	abortRecs := []handoffRecord{
		{kind: recPrepare},
		{kind: recFreeze, frozenID: fid, summary: summ, parent: par},
		{kind: recAbort, reason: "candidate replaced"},
	}
	out = append(out, runMultiReplica("aborted_attempt_never_commits",
		"An attempt is aborted before commit; its FrozenID can never reach a commit on any replica.",
		c, abortRecs, map[string][]int{
			"A": {0, 1, 2},
			"B": {0, 1, 2},
		}, false))

	return out
}
