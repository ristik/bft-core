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

// The proxy must not narrow what the code under it can discover. The handoff profile asserts for these
// optional capabilities on the store (the retained freeze companions and bundles, the atomic epoch-anchor
// root); a plain embedded interface would hide every one of them from a root that runs the frontier sampler,
// which is every root in default startup. Each method forwards to the real store; when the real store lacks
// the capability the result is exactly what the asserting caller does on a failed assertion.

func (s *frontierPersistentStore) StoreHandoffBody(id, body []byte) error {
	if store, ok := s.PersistentStore.(interface{ StoreHandoffBody([]byte, []byte) error }); ok {
		return store.StoreHandoffBody(id, body)
	}
	return nil // callers skip the retention when the store has no archive
}

func (s *frontierPersistentStore) HandoffBody(id []byte) ([]byte, error) {
	if store, ok := s.PersistentStore.(interface{ HandoffBody([]byte) ([]byte, error) }); ok {
		return store.HandoffBody(id)
	}
	return nil, storage.ErrAssignmentHistory
}

func (s *frontierPersistentStore) StoreHandoffCandidate(id, candidate []byte) error {
	if store, ok := s.PersistentStore.(interface{ StoreHandoffCandidate([]byte, []byte) error }); ok {
		return store.StoreHandoffCandidate(id, candidate)
	}
	return storage.ErrAssignmentHistory
}

func (s *frontierPersistentStore) HandoffCandidate(id []byte) ([]byte, error) {
	if store, ok := s.PersistentStore.(interface{ HandoffCandidate([]byte) ([]byte, error) }); ok {
		return store.HandoffCandidate(id)
	}
	return nil, nil // callers treat a store with no candidates as having none
}

func (s *frontierPersistentStore) StoreHandoffBundle(epoch uint64, data []byte) error {
	if store, ok := s.PersistentStore.(handoffBundleArchive); ok {
		return store.StoreHandoffBundle(epoch, data)
	}
	return nil
}

func (s *frontierPersistentStore) HandoffBundle(epoch uint64) ([]byte, error) {
	if store, ok := s.PersistentStore.(handoffBundleArchive); ok {
		return store.HandoffBundle(epoch)
	}
	return nil, nil
}

// InstallEpochAnchorRoot replaces the stored committed root, so its failure is a persistence fault.
func (s *frontierPersistentStore) InstallEpochAnchorRoot(block *storage.ExecutedBlock, a *drctypes.EpochAnchor) error {
	store, ok := s.PersistentStore.(interface {
		InstallEpochAnchorRoot(*storage.ExecutedBlock, *drctypes.EpochAnchor) error
	})
	if !ok {
		return errors.New("atomic epoch anchor storage unavailable")
	}
	return s.fault(store.InstallEpochAnchorRoot(block, a))
}
