package consensus

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/handoff"
	"github.com/unicitynetwork/bft-core/q3format"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
	"github.com/unicitynetwork/bft-core/utb"
	"github.com/unicitynetwork/bft-core/utbstore"
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

// utbRetentionFor appends the signed entry a committing certificate carries to the permanent store. The store verifies it strictly from its own
// predecessor, so an entry that does not extend the finalized chain is refused here and the certificate is not applied.
func utbRetentionFor(store *utbstore.Store) storage.UTBRetention {
	return func(qc *drctypes.QuorumCert) error {
		signed, err := utb.Signed(qc.UTB.Unsigned, qc.UTB.Signatures)
		if err != nil {
			return err
		}
		_, err = store.Append(signed)
		return err
	}
}

var (
	// ErrUTBStoreMissing: the old epoch is a UTB epoch but this root has no entry store, so it cannot retain the entry the install must leave behind.
	ErrUTBStoreMissing = errors.New("the old epoch is a UTB epoch and no trust-base entry store is configured")
	// ErrUTBMismatch: the old committee's endorsement is not of the entry the verified handoff implies.
	ErrUTBMismatch = errors.New("the old commit proof endorses another successor trust-base entry than the handoff implies")
)

// retainInstalledUTB is the installer's side of the endorsement: when the old epoch is a UTB epoch, the verified old commit proof must carry the old
// committee's endorsement of exactly the entry the installed epoch implies (derived from the verified body or history entry and the finalized entry of
// the old epoch), and that entry is made durable in the permanent store before the epoch is installed. The proof was already verified, strictly, by
// handoff.VerifyOldCommitProofSigning; the store verifies the entry again from its own predecessor.
func (x *ConsensusManager) retainInstalledUTB(oldEpoch uint64, oldSigning votesig.Config, proof handoff.OldCommitProof, facts utb.SuccessorFacts) error {
	if !oldSigning.UTB {
		return nil
	}
	if x.utbStore == nil {
		return ErrUTBStoreMissing
	}
	if proof.CommitQC == nil || proof.CommitQC.UTB == nil {
		return fmt.Errorf("%w: the commit certificate carries no endorsement", ErrUTBMismatch)
	}
	prev, err := x.utbStore.Entry(oldEpoch)
	if err != nil {
		return fmt.Errorf("%w: finalized entry of epoch %d: %w", ErrUTBSuccessor, oldEpoch, err)
	}
	built, err := utb.BuildUnsigned(prev, facts)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrUTBSuccessor, err)
	}
	want, err := built.SigBytes()
	if err != nil {
		return err
	}
	if !bytes.Equal(want, proof.CommitQC.UTB.Unsigned) {
		return ErrUTBMismatch
	}
	return utbRetentionFor(x.utbStore)(proof.CommitQC)
}
