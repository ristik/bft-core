package configuredprogress

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-go-base/types"
	bolt "go.etcd.io/bbolt"
)

// Superseded same-height history (bft-core#1019).
//
// The journal is pruned by the certified frontier only. While a height h = frontier+1 cannot be certified, every failed leader round journals
// another uncertified proposal for h, and every timeout journals another repeat certificate of block h-1. Without a rule for that history the
// candidate bound (and later the observation bound) is reached, every new proposal and certificate is refused with ErrCapacity, and nothing above
// h-1 can ever be certified to prune it: the shard is wedged for good. The two rules below free that history when, and only when, the journal is
// at a bound and the entries can no longer matter.
//
// 1. An uncertified candidate for partition round r is dead once a durable root certificate E has E.TR.Round > r and E.IR.RoundNumber < r.
//    The root certifies a request only for the round of its latest technical record (ShardInfo.validRequest: req.IRRound() == LastCR.Technical.Round),
//    and that round never decreases. E.TR.Round > r: no request for round r is accepted at or after E. E.IR.RoundNumber < r: E carries the shard's
//    latest certified input record at E's root round, and certified round numbers never decrease, so no input record of round r was certified
//    before E either. The candidate is therefore never certified, no certificate will ever name it, it is never an ancestor of a certified block,
//    and its body is not needed for execution, recovery, archive or serving. Its observations are unaffected: an uncertified candidate is the
//    target of no resolved observation.
//    Equivocation: the journal's local-proposal check refuses a second local proposal for one authorization. From the eviction on, every
//    durable certificate L (E is durable, or becomes durable in the same transaction, and progress only moves forward) has L.TR.Round > r, and
//    L.IR.RoundNumber != r because the root accepts no request for r after E. putJournalCandidate refuses every new local proposal for such a
//    round, so no different local proposal can ever take an evicted one's place. The node's vote record is kept by the independent signing
//    authority, not by this body.
//
// 2. A resolved repeat observation O of block B is superseded by a later retained (or incoming) observation N of the same complete input
//    record of the same block. It is deleted only if it is not B's own association (the certificate the candidate records as its result) and
//    no retained candidate was authorized by it. Every journal invariant that read O is then satisfied by N or by the association: B keeps its
//    newest resolved observation, the latest observation (durable progress) is never touched, unresolved, quiet and bootstrap observations are
//    never touched, and LoadJournal's authorization check of a retained candidate still finds its authorizing certificate. Recovery and peer
//    serving walk the observations in root order for the newest certified target (and, for a quiet tail, the nearest earlier target); deleting
//    an older duplicate of a certificate whose newer duplicate stays at a later position changes neither answer.

// deadCandidate reports whether an uncertified candidate of round r can never be certified, given an authenticated certificate pair.
func deadCandidate(round uint64, uc *types.UnicityCertificate, tr *certification.TechnicalRecord) bool {
	if uc == nil || uc.InputRecord == nil || tr == nil {
		return false
	}
	return round < tr.Round && uc.InputRecord.RoundNumber < round
}

// evictDeadCandidates deletes every uncertified candidate that the authenticated pair (uc, tr) proves dead (rule 1). The caller has authenticated
// the pair and commits it durably no later than this transaction.
func evictDeadCandidates(b *bolt.Bucket, uc *types.UnicityCertificate, tr *certification.TechnicalRecord) (int, error) {
	evicted := 0
	curs := b.Cursor()
	for k, raw := curs.Seek(journalCandidatePrefix); k != nil && bytes.HasPrefix(k, journalCandidatePrefix); {
		w, err := decodeCandidate(raw)
		if err != nil {
			return evicted, err
		}
		if w.Status != 0 || len(w.ResultingUC) != 0 || len(w.ResultingTR) != 0 || !deadCandidate(w.Round, uc, tr) || b.Get(archiveSelectionKey(w.Hash)) != nil {
			k, raw = curs.Next()
			continue
		}
		deleted := bytes.Clone(k) // k may alias page memory the delete rewrites
		if err := curs.Delete(); err != nil {
			return evicted, err
		}
		evicted++
		// Seek past the deleted key rather than relying on Next after Delete.
		k, raw = curs.Seek(deleted)
	}
	return evicted, nil
}

// evictSupersededObservations deletes every resolved repeat observation that a later observation of the same certified input record of the same
// block supersedes (rule 2). The incoming observation (newKey, newEpoch, newRootRound, newTarget, newIR) is not stored yet and counts as the
// latest of its target.
func evictSupersededObservations(b *bolt.Bucket, newKey []byte, newEpoch, newRootRound uint64, newTarget, newIR []byte) (int, error) {
	type position struct {
		epoch, root uint64
		ir          []byte
	}
	latest := make(map[string]position)
	note := func(target []byte, epoch, root uint64, ir []byte) {
		if p, ok := latest[string(target)]; !ok || rootPositionLater(epoch, root, p.epoch, p.root) {
			latest[string(target)] = position{epoch: epoch, root: root, ir: ir}
		}
	}
	if len(newTarget) == sha256.Size {
		note(newTarget, newEpoch, newRootRound, newIR)
	}
	type entry struct {
		key, target, uc, tr, ir []byte
		epoch, root, round      uint64
	}
	var resolved []entry
	curs := b.Cursor()
	for k, raw := curs.Seek(journalObservationPrefix); k != nil && bytes.HasPrefix(k, journalObservationPrefix); k, raw = curs.Next() {
		if bytes.Equal(k, newKey) {
			continue
		}
		o, err := decodeObservation(raw)
		if err != nil {
			return 0, err
		}
		if o.Unresolved || len(o.TargetHash) != sha256.Size {
			continue // unresolved, quiet and bootstrap observations are never evicted
		}
		var uc types.UnicityCertificate
		if err := types.Cbor.Unmarshal(o.UC, &uc); err != nil {
			return 0, err
		}
		ir, err := canonicalIR(&uc)
		if err != nil {
			return 0, err
		}
		e := entry{key: bytes.Clone(k), target: bytes.Clone(o.TargetHash), uc: bytes.Clone(o.UC), tr: bytes.Clone(o.TR), ir: ir, epoch: uc.GetRootEpoch(), root: uc.GetRootRoundNumber(), round: uc.GetRoundNumber()}
		resolved = append(resolved, e)
		note(e.target, e.epoch, e.root, e.ir)
	}
	if len(resolved) == 0 {
		return 0, nil
	}
	authorizations, err := retainedAuthorizationCoordinates(b)
	if err != nil {
		return 0, err
	}
	evicted := 0
	for _, e := range resolved {
		newest := latest[string(e.target)]
		if !rootPositionLater(newest.epoch, newest.root, e.epoch, e.root) || !bytes.Equal(newest.ir, e.ir) {
			continue // the newest observation of its block, or not a repeat of it
		}
		if _, needed := authorizations[[3]uint64{e.epoch, e.root, e.round}]; needed {
			// A retained candidate's authorization. Defensive: a live candidate is authorized by its block's newest repeat, and rule 1 runs on
			// every certificate, so this matters only for a candidate rule 1 has not freed yet (a follower's late copy of a closed round, or a
			// journal written before #1019). LoadJournal requires a local candidate's authorization to be present.
			continue
		}
		candidateRaw := b.Get(journalCandidateKey(e.target))
		if candidateRaw == nil {
			continue
		}
		candidate, err := decodeCandidate(candidateRaw)
		if err != nil {
			return evicted, err
		}
		if candidate.Status != 1 || bytes.Equal(e.uc, candidate.ResultingUC) && bytes.Equal(e.tr, candidate.ResultingTR) {
			continue // the block's own association
		}
		if err := b.Delete(e.key); err != nil {
			return evicted, err
		}
		evicted++
	}
	return evicted, nil
}

// retainedAuthorizationCoordinates is the (root epoch, root round, partition round) of every retained candidate's authorizing certificate.
func retainedAuthorizationCoordinates(b *bolt.Bucket) (map[[3]uint64]struct{}, error) {
	out := make(map[[3]uint64]struct{})
	curs := b.Cursor()
	for k, raw := curs.Seek(journalCandidatePrefix); k != nil && bytes.HasPrefix(k, journalCandidatePrefix); k, raw = curs.Next() {
		w, err := decodeCandidate(raw)
		if err != nil {
			return nil, err
		}
		var uc types.UnicityCertificate
		if err := types.Cbor.Unmarshal(w.AuthorizingUC, &uc); err != nil {
			return nil, err
		}
		out[[3]uint64{uc.GetRootEpoch(), uc.GetRootRoundNumber(), uc.GetRoundNumber()}] = struct{}{}
	}
	return out, nil
}

// EvictSuperseded frees, against the durable progress certificate, the history the two rules above prove superseded, in one transaction. It is
// what a catch-up calls before it decides the journal has no room (bft-core#1019): a node that accumulated a stall's history below the bounds,
// or under a binary that never evicted, otherwise waits for room only the frontier could make. A concurrent commit is not an error: that
// commit evicts against its own certificate, and the caller re-reads the journal.
func (s *Store) EvictSuperseded(ctx context.Context, c Context, limits JournalLimits) (candidates, observations int, err error) {
	if !s.journal {
		return 0, 0, fmt.Errorf("%w: journal not enabled", ErrSettings)
	}
	if err := limits.check(); err != nil {
		return 0, 0, err
	}
	state, _, err := s.Load(ctx, c)
	if err != nil {
		return 0, 0, err
	}
	if state.i.observed == nil {
		return 0, 0, nil
	}
	uc, tr := state.i.observed.observation.Certificate(), state.i.observed.observation.TechnicalRecord()
	err = s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketName)
		if !imageMatches(b, state.i) {
			return ErrStale
		}
		if err := readJournalMeta(b, state.i.descriptorDigest, limits); err != nil {
			return err
		}
		var e error
		if candidates, e = evictDeadCandidates(b, uc, tr); e != nil {
			return e
		}
		observations, e = evictSupersededObservations(b, nil, 0, 0, nil, nil)
		return e
	})
	if errors.Is(err, ErrStale) {
		return 0, 0, nil
	}
	if err != nil {
		return 0, 0, err
	}
	return candidates, observations, nil
}
