package consensus

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/q3format"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
	"github.com/unicitynetwork/bft-core/utb"
)

// UTBHandoffState is what the successor entry is derived from: the committed handoff record of the executed block, and the successor body the
// Freeze retained on every root.
type UTBHandoffState interface {
	HandoffCommittedAt(round, epoch uint64, rootHash []byte) (evmroot.OrderedHandoffRecord, bool, error)
	HandoffBody(id []byte) ([]byte, error)
}

// UTBSuccessor derives the unsigned successor trust-base entry of a committing vote, a certificate or a replay from the locally executed state only:
// the committed record of the committed round's executed block (the actual ActivationRound), the retained successor body (V2 or Q3, both through the
// one builder) and the finalized entry of the voting epoch. It returns nil, nil when that state holds no outgoing handoff of the epoch (including a
// later epoch whose control state still shows an earlier epoch's record). Anything unavailable is an error: no entry is guessed.
type UTBSuccessor struct {
	State    UTBHandoffState
	Previous func(epoch uint64) (*types.RootTrustBaseV2, error)
}

var ErrUTBSuccessor = errors.New("successor trust-base entry cannot be derived")

// Entry matches SafetyModule's UTBSource and the storage binding's entry source.
func (s UTBSuccessor) Entry(committed *drctypes.RoundInfo, epoch uint64) ([]byte, error) {
	record, ok, err := s.State.HandoffCommittedAt(committed.RoundNumber, committed.Epoch, committed.CurrentRootHash)
	if err != nil {
		return nil, err
	}
	if !ok || record.Epoch != epoch {
		return nil, nil
	}
	raw, err := s.State.HandoffBody(record.NextBodyID)
	if err != nil || len(raw) == 0 {
		return nil, fmt.Errorf("%w: successor body of the committed record: %w", ErrUTBSuccessor, errors.Join(err, errors.New("not retained")))
	}
	var facts utb.SuccessorFacts
	if v2, err2 := storage.DecodeHandoffBody(raw); err2 == nil {
		if id := v2.Identity(); !bytes.Equal(id[:], record.NextBodyID) {
			return nil, fmt.Errorf("%w: the retained body is not the committed one", ErrUTBSuccessor)
		}
		facts = utb.FromBodyV2(v2, record.ActivationRound)
	} else if v3, err3 := q3format.DecodeBody(raw); err3 == nil {
		if id := v3.Identity(); !bytes.Equal(id[:], record.NextBodyID) {
			return nil, fmt.Errorf("%w: the retained body is not the committed one", ErrUTBSuccessor)
		}
		facts = utb.FromWeightSet(v3.Network, v3.Epoch, record.ActivationRound, v3.Members, v3.RootThreshold, v3.StateSummary, v3.ChangeRecordHash)
	} else {
		return nil, fmt.Errorf("%w: the retained body decodes as neither version: %w", ErrUTBSuccessor, errors.Join(err2, err3))
	}
	prev, err := s.Previous(epoch)
	if err != nil {
		return nil, fmt.Errorf("%w: finalized entry of epoch %d: %w", ErrUTBSuccessor, epoch, err)
	}
	entry, err := utb.BuildUnsigned(prev, facts)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUTBSuccessor, err)
	}
	return entry.SigBytes()
}

// utbBindingFor is the contextual check of a block store's certificates: in a UTB epoch a committing certificate carries exactly the entry the store's own
// executed state implies, derived like the endorsement a vote makes.
func utbBindingFor(cfgOf func(uint64) (votesig.Config, error), blocks *storage.BlockStore, previous func(uint64) (*types.RootTrustBaseV2, error)) storage.UTBBinding {
	return storage.NewUTBBinding(cfgOf, UTBSuccessor{State: blocks, Previous: previous}.Entry)
}
