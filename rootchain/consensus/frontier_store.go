package consensus

import (
	"errors"

	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
)

// frontierPersistentStore is installed only with the sampler. Both safety and
// block storage receive this same proxy, including recovery through GetDB.
type frontierPersistentStore struct {
	PersistentStore
	sampler *frontierSampler
	reader  frontierSafetyReader
}

func (s *frontierPersistentStore) fault(err error) error {
	if err != nil {
		s.sampler.latchFault()
	}
	return err
}
func (s *frontierPersistentStore) SetHighestVotedRound(round uint64) error {
	return s.fault(s.PersistentStore.SetHighestVotedRound(round))
}
func (s *frontierPersistentStore) SetHighestQcRound(qcRound, votedRound uint64) error {
	return s.fault(s.PersistentStore.SetHighestQcRound(qcRound, votedRound))
}
func (s *frontierPersistentStore) WriteBlock(block *storage.ExecutedBlock, root bool) error {
	return s.fault(s.PersistentStore.WriteBlock(block, root))
}
func (s *frontierPersistentStore) WriteVote(vote any) error {
	return s.fault(s.PersistentStore.WriteVote(vote))
}
func (s *frontierPersistentStore) WriteTC(tc *drctypes.TimeoutCert) error {
	return s.fault(s.PersistentStore.WriteTC(tc))
}
func (s *frontierPersistentStore) ReadSafetySnapshot() (storage.SafetySnapshot, error) {
	return s.reader.ReadSafetySnapshot()
}

func (s *frontierPersistentStore) InstallEpochAnchorSafety(a *drctypes.EpochAnchor) error {
	store, ok := s.PersistentStore.(interface {
		InstallEpochAnchorSafety(*drctypes.EpochAnchor) error
	})
	if !ok {
		return s.fault(errors.New("durable epoch anchor safety store unavailable"))
	}
	return s.fault(store.InstallEpochAnchorSafety(a))
}

func (s *frontierPersistentStore) ReadEpochAnchorSafety() (*drctypes.EpochAnchor, error) {
	store, ok := s.PersistentStore.(interface {
		ReadEpochAnchorSafety() (*drctypes.EpochAnchor, error)
	})
	if !ok {
		return nil, errors.New("durable epoch anchor safety store unavailable")
	}
	return store.ReadEpochAnchorSafety()
}
