package configuredprogress

import (
	"bytes"
	"context"
	"fmt"

	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/rootinput"
	"github.com/unicitynetwork/bft-go-base/types"
	bolt "go.etcd.io/bbolt"
)

// InstallReplayedTip imports the one hot certified body after an empty-disk
// archive replay. The caller has checked every archived ancestor in the
// paired executor. This transaction starts a fresh journal at the verified
// current tip, with the replay target as its durable recovery anchor.
func (s *Store) InstallReplayedTip(ctx context.Context, c Context, limits JournalLimits, candidate JournalCandidate,
	resultUC *types.UnicityCertificate, resultTR *certification.TechnicalRecord,
	tipUC *types.UnicityCertificate, tipTR *certification.TechnicalRecord, anchor RestoreAnchor) error {
	return s.installReplayedTip(ctx, c, limits, candidate, resultUC, resultTR, tipUC, tipTR, anchor, RestoreCheckpoint{}, nil, nil)
}

// InstallSameEpochReplayedTip retains the original bootstrap observation and
// installs the certified tip, progress and recovery anchor in one transaction.
func (s *Store) InstallSameEpochReplayedTip(ctx context.Context, c Context, limits JournalLimits, candidate JournalCandidate,
	resultUC *types.UnicityCertificate, resultTR *certification.TechnicalRecord,
	tipUC *types.UnicityCertificate, tipTR *certification.TechnicalRecord, anchor RestoreAnchor,
	checkpoint RestoreCheckpoint, firstUC *types.UnicityCertificate, firstTR *certification.TechnicalRecord) error {
	if checkpoint.Pin == ([32]byte{}) || checkpoint.Target != anchor.Hash || checkpoint.VerifiedHeight != anchor.Height || !checkpoint.Finalizing || firstUC == nil || firstTR == nil {
		return ErrConflict
	}
	return s.installReplayedTip(ctx, c, limits, candidate, resultUC, resultTR, tipUC, tipTR, anchor, checkpoint, firstUC, firstTR)
}

func (s *Store) installReplayedTip(ctx context.Context, c Context, limits JournalLimits, candidate JournalCandidate,
	resultUC *types.UnicityCertificate, resultTR *certification.TechnicalRecord,
	tipUC *types.UnicityCertificate, tipTR *certification.TechnicalRecord, anchor RestoreAnchor,
	checkpoint RestoreCheckpoint, firstUC *types.UnicityCertificate, firstTR *certification.TechnicalRecord) error {
	s.vm.reset() // an install: whatever the memo holds was verified under the previous state (bft-core#728)
	if !s.journal || limits.check() != nil || candidate.LocallyBuilt || candidate.AuthorizingUC == nil || candidate.AuthorizingTR == nil ||
		resultUC == nil || resultTR == nil || tipUC == nil || tipTR == nil || resultUC.InputRecord == nil || tipUC.InputRecord == nil ||
		candidate.Number == 0 || candidate.Number != candidate.ParentNumber+1 || candidate.Round == 0 ||
		len(candidate.Hash) != 32 || len(candidate.StateRoot) != 32 || len(candidate.ParentHash) != 32 || len(candidate.ParentState) != 32 || len(candidate.Raw) == 0 || len(candidate.Raw) > MaxCandidateBytes ||
		candidate.Round != resultUC.InputRecord.RoundNumber || candidate.AuthorizingTR.Round != candidate.Round ||
		!bytes.Equal(candidate.Hash, resultUC.InputRecord.BlockHash) || !bytes.Equal(candidate.StateRoot, resultUC.InputRecord.Hash) ||
		!bytes.Equal(candidate.StateRoot, tipUC.InputRecord.Hash) || anchor.Height != candidate.Number || anchor.RootRound != resultUC.GetRootRoundNumber() ||
		!bytes.Equal(anchor.Hash[:], candidate.Hash) || !bytes.Equal(anchor.StateRoot[:], candidate.StateRoot) {
		return ErrConflict
	}
	if rootinput.CheckEpochCertificates(candidate.AuthorizingUC, resultUC) != nil ||
		candidate.AuthorizingUC.GetRootEpoch() == resultUC.GetRootEpoch() && candidate.AuthorizingUC.GetRootRoundNumber() >= resultUC.GetRootRoundNumber() ||
		resultUC.GetRootEpoch() > tipUC.GetRootEpoch() || resultUC.GetRootEpoch() == tipUC.GetRootEpoch() && resultUC.GetRootRoundNumber() > tipUC.GetRootRoundNumber() ||
		resultUC.GetRoundNumber() > tipUC.GetRoundNumber() {
		return ErrConflict
	}
	for _, pair := range []struct {
		uc *types.UnicityCertificate
		tr *certification.TechnicalRecord
	}{
		{candidate.AuthorizingUC, candidate.AuthorizingTR}, {resultUC, resultTR}} {
		if _, err := rootinput.AuthenticateHistoricalObservationV2(ctx, c.Observation, pair.uc, pair.tr); err != nil {
			return err
		}
	}
	tip, err := rootinput.AuthenticateObservationV2(ctx, c.Observation, tipUC, tipTR)
	if err != nil {
		return err
	}
	state, _, err := s.Load(ctx, c)
	if err != nil {
		return err
	}
	if state.i.control.Revision != 0 || state.i.observed != nil {
		return ErrConflict
	}
	tipPair, _, err := pairFromObservation(tip)
	if err != nil {
		return err
	}
	au, at, err := pairBytes(candidate.AuthorizingUC, candidate.AuthorizingTR)
	if err != nil {
		return err
	}
	ru, rt, err := pairBytes(resultUC, resultTR)
	if err != nil {
		return err
	}
	cr := journalCandidateWire{Version: journalVersion, Descriptor: state.i.descriptorDigest[:], Status: 1,
		Round: candidate.Round, Number: candidate.Number, ParentNumber: candidate.ParentNumber, Hash: bytes.Clone(candidate.Hash), StateRoot: bytes.Clone(candidate.StateRoot),
		ParentHash: bytes.Clone(candidate.ParentHash), ParentState: bytes.Clone(candidate.ParentState), Raw: bytes.Clone(candidate.Raw), BlockSize: candidate.BlockSize, StateSize: candidate.StateSize,
		AuthorizingUC: au, AuthorizingTR: at, ResultingUC: ru, ResultingTR: rt}
	candidateRaw, err := encodeCandidate(cr)
	if err != nil {
		return err
	}
	observations := make(map[string][]byte)
	type observationPair struct {
		uc    *types.UnicityCertificate
		u, tr []byte
	}
	pairs := []observationPair{{resultUC, ru, rt}, {tipUC, tipPair.UC, tipPair.TR}}
	cw := state.i.control
	cw.Revision, cw.First, cw.Observed = 1, &tipPair, &tipPair
	if firstUC != nil {
		if firstUC.GetRootEpoch() != c.Observation.RootEpoch ||
			resultUC.GetRootEpoch() != firstUC.GetRootEpoch() || tipUC.GetRootEpoch() != firstUC.GetRootEpoch() {
			return ErrConflict
		}
		first, err := rootinput.AuthenticateObservationV2(ctx, c.Observation, firstUC, firstTR)
		if err != nil {
			return err
		}
		result, err := rootinput.AuthenticateObservationV2(ctx, c.Observation, resultUC, resultTR)
		if err != nil {
			return err
		}
		if first.Class() != evmroot.OriginBootstrapV2 || result.Class() == evmroot.OriginBootstrapV2 {
			return ErrConflict
		}
		if rel, err := compareObservations(first, result); err != nil || rel != relationAdvance {
			return fmt.Errorf("%w: bootstrap to restored result: %v", ErrConflict, err)
		}
		rel, err := compareObservations(result, tip)
		if err != nil || rel == relationStale {
			return fmt.Errorf("%w: restored result to tip: %v", ErrConflict, err)
		}
		cw.First = &pairWire{UC: ru, TR: rt}
		if rel == relationDuplicate {
			// Keep the archived pair for the candidate and its observation
			// and progress. The checkpoint still binds the exact operator pin.
			pairs = pairs[:1]
			cw.Observed = cw.First
		}
		fu, ft, err := pairBytes(firstUC, firstTR)
		if err != nil {
			return err
		}
		pairs = append(pairs, observationPair{firstUC, fu, ft})
	}
	for _, pair := range pairs {
		w := journalObservationWire{Version: journalVersion, Descriptor: state.i.descriptorDigest[:], Round: pair.uc.GetRoundNumber(), RootRound: pair.uc.GetRootRoundNumber(),
			TargetHash: bytes.Clone(pair.uc.InputRecord.BlockHash), UC: pair.u, TR: pair.tr}
		if len(w.TargetHash) != 0 && !bytes.Equal(w.TargetHash, candidate.Hash) {
			return ErrConflict
		}
		raw, e := encodeObservation(w)
		if e != nil {
			return e
		}
		key := journalEpochObservationKey(pair.uc.GetRootEpoch(), w.RootRound, w.Round)
		if old, exists := observations[string(key)]; exists && !bytes.Equal(old, raw) {
			return ErrConflict
		}
		observations[string(key)] = raw
	}
	if len(observations) > limits.Observations || len(candidateRaw) > int(limits.Bytes) {
		return ErrBounds
	}
	if firstUC != nil {
		cw.Revision = uint64(len(observations))
	}
	controlPayload, err := marshal(cw)
	if err != nil {
		return err
	}
	controlRaw, err := encodeEnvelope(kindControl, controlPayload, MaxControlBytes)
	if err != nil {
		return err
	}
	aw := restoreAnchorWire{Version: journalVersion, Descriptor: state.i.descriptorDigest[:], Height: anchor.Height, Hash: anchor.Hash[:], StateRoot: anchor.StateRoot[:], RootRound: anchor.RootRound}
	anchorPayload, err := marshal(aw)
	if err != nil {
		return err
	}
	anchorRaw, err := encodeEnvelope(restoreAnchorKind, anchorPayload, 4096)
	if err != nil {
		return err
	}
	coverageRaw, err := encodeCoverageBase(state.i.descriptorDigest, CoverageBase{Height: anchor.Height, Hash: anchor.Hash})
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketName)
		if !imageMatches(b, state.i) || b.Get(restoreAnchorKey) != nil || b.Get(journalCoverageBaseKey) != nil {
			return ErrStale
		}
		storedCheckpoint, err := readRestoreCheckpoint(b)
		if err != nil {
			return err
		}
		if storedCheckpoint != checkpoint {
			return ErrConflict
		}
		if err := readJournalMeta(b, state.i.descriptorDigest, limits); err != nil {
			return err
		}
		count, observed, size, err := journalCount(b)
		if err != nil {
			return err
		}
		if count != 0 || observed != 0 || size != 0 {
			return ErrConflict
		}
		total := int64(len(journalCandidateKey(candidate.Hash)) + len(candidateRaw))
		for key, raw := range observations {
			total += int64(len(key) + len(raw))
		}
		if total > limits.Bytes {
			return fmt.Errorf("%w: restored hot tip exceeds journal capacity", ErrBounds)
		}
		if err := b.Put(controlKey, controlRaw); err != nil {
			return err
		}
		if err := b.Put(journalCandidateKey(candidate.Hash), candidateRaw); err != nil {
			return err
		}
		for key, raw := range observations {
			if err := b.Put([]byte(key), raw); err != nil {
				return err
			}
		}
		if err := b.Put(restoreAnchorKey, anchorRaw); err != nil {
			return err
		}
		if err := b.Put(journalCoverageBaseKey, coverageRaw); err != nil {
			return err
		}
		return s.at("before-replayed-tip-commit")
	})
}
