package configuredprogress

import (
	"bytes"
	"context"

	"github.com/unicitynetwork/bft-go-base/types"
)

// TerminalDischarge is the authenticated certified history for which this
// journal no longer has to retain bodies: the pruned prefix covered by the
// replica-acknowledged frontier and the prefix covered by the verified restore
// base (a full archive replay from genesis). It is read-only evidence taken
// from LoadJournal; it never admits anything.
type TerminalDischarge struct {
	positions []dischargedPosition
}

type dischargedPosition struct {
	epoch, root, round uint64
}

// DischargedThrough is the discharge of everything at or below one certified position: a root epoch and round and the partition round
// certified there. LoadTerminalDischarge derives its positions from the journal; this constructor is for callers that already hold an
// authenticated position (and for fakes of the journal reader).
func DischargedThrough(rootEpoch, rootRound, partitionRound uint64) TerminalDischarge {
	return TerminalDischarge{positions: []dischargedPosition{{rootEpoch, rootRound, partitionRound}}}
}

// Covers reports whether a terminal certificate sits at or below an
// authenticated discharged position, in both root position and partition round.
func (d TerminalDischarge) Covers(uc *types.UnicityCertificate) bool {
	if uc == nil || uc.InputRecord == nil {
		return false
	}
	for _, p := range d.positions {
		if observationCovered(uc.GetRootEpoch(), uc.GetRootRoundNumber(), uc.InputRecord.RoundNumber, p.epoch, p.root, p.round) {
			return true
		}
	}
	return false
}

// LoadTerminalDischarge reads the discharged history through LoadJournal, so a
// persisted frontier must already be enabled (authenticated) and a restore base
// is checked against its certified journal body, exactly as for every other
// reader. A restore base whose body a later frontier already pruned is covered
// by that frontier's position.
func (s *Store) LoadTerminalDischarge(ctx context.Context, c Context, limits JournalLimits) (TerminalDischarge, error) {
	image, err := s.LoadJournal(ctx, c, limits)
	if err != nil {
		return TerminalDischarge{}, err
	}
	var out TerminalDischarge
	if f := image.Frontier; f != nil && f.ResultingUC != nil && f.ResultingUC.InputRecord != nil {
		out.positions = append(out.positions, dischargedPosition{f.ResultingUC.GetRootEpoch(), f.ResultingUC.GetRootRoundNumber(), f.ResultingUC.InputRecord.RoundNumber})
	}
	if base := image.RestoreBase; base != nil {
		for _, entry := range image.Candidates {
			if entry.Certified && entry.ResultingUC != nil && entry.ResultingUC.InputRecord != nil && entry.Candidate.Number == base.Height &&
				bytes.Equal(entry.Candidate.Hash, base.Hash[:]) && entry.ResultingUC.GetRootRoundNumber() == base.RootRound {
				out.positions = append(out.positions, dischargedPosition{entry.ResultingUC.GetRootEpoch(), base.RootRound, entry.ResultingUC.InputRecord.RoundNumber})
				break
			}
		}
	}
	return out, nil
}
