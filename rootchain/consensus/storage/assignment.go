package storage

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"errors"
	"fmt"
	"maps"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-go-base/types"
)

var (
	// ErrAssignmentHistory reports committed assignment history that is missing,
	// inconsistent or unverifiable. It refuses readiness: the genesis or a
	// retired configuration is never used instead.
	ErrAssignmentHistory = errors.New("EVM assignment history unavailable or inconsistent")
)

// DerivedConfigInstaller is the orchestration's internal writer. Verified
// derivation from committed history and genesis initialization are its only
// callers for the designated EVM shard.
type DerivedConfigInstaller interface {
	InstallDerivedShardConfig(conf *types.PartitionDescriptionRecord, provenance []byte) error
}

// candidateSource retains the verified H3 candidate preimages by body id.
type candidateSource interface {
	HandoffCandidate(bodyID []byte) ([]byte, error)
}

// successorTechnicalRecord derives the technical record that installing pdr
// gives the shard: the next monotone shard round, the successor epoch, the new
// set's leader and the rolled fee/stat commitments. It is what Commit binds in
// SuccessorTRHash, and exactly what the shard's next ordinary round would
// produce, so activation and ordinary progression cannot disagree.
func successorTechnicalRecord(si *ShardInfo, pdr *types.PartitionDescriptionRecord, hashAlg crypto.Hash) (certification.TechnicalRecord, error) {
	if si == nil || pdr == nil || si.TR.Epoch == ^uint64(0) || pdr.Epoch != si.TR.Epoch+1 {
		return certification.TechnicalRecord{}, ErrAssignmentHistory
	}
	clone := *si
	clone.Fees = maps.Clone(si.Fees)
	if err := clone.nextRound(nil, pdr, hashAlg); err != nil {
		return certification.TechnicalRecord{}, fmt.Errorf("deriving successor technical record: %w", err)
	}
	return clone.TR, nil
}

// candidateActivatedPDR decodes a verified preimage and applies the committed
// activation round.
func candidateActivatedPDR(preimage []byte, activation uint64) (evmassign.Candidate, *types.PartitionDescriptionRecord, error) {
	c, err := evmassign.DecodeCandidate(preimage)
	if err != nil {
		return c, nil, errors.Join(ErrAssignmentHistory, err)
	}
	succ, err := c.Successor()
	if err != nil {
		return c, nil, errors.Join(ErrAssignmentHistory, err)
	}
	pdr, err := evmassign.Activate(succ, activation)
	if err != nil {
		return c, nil, errors.Join(ErrAssignmentHistory, err)
	}
	return c, pdr, nil
}

// DeriveActivatedPDR verifies the committed record, successor body and
// candidate preimage against each other and returns the configuration that
// activates at the record's activation round, with its provenance digest.
// The chain is: record.NextBodyID (old root quorum) <- body identity <-
// body.ChangeRecordHash <- candidate digest <- preimage. The caller supplies
// the verified frozen parent so the possession proofs are checked in context.
func DeriveActivatedPDR(record evmroot.OrderedHandoffRecord, body evmroot.TrustBaseBodyV2, preimage, frozenParent []byte) (*types.PartitionDescriptionRecord, []byte, error) {
	id := body.Identity()
	digest := sha256.Sum256(preimage)
	if !bytes.Equal(id[:], record.NextBodyID) || body.Epoch != record.Epoch+1 ||
		!bytes.Equal(body.ChangeRecordHash, evmroot.D4CandidateContextHash(record.Network, record.PredecessorBodyID, record.Attempt, digest[:], body.EarliestActivation)) {
		return nil, nil, ErrAssignmentHistory
	}
	c, pdr, err := candidateActivatedPDR(preimage, record.ActivationRound)
	if err != nil {
		return nil, nil, err
	}
	if c.Network != record.Network || !bytes.Equal(c.Predecessor, record.PredecessorBodyID) || c.Attempt != record.Attempt ||
		!bytes.Equal(c.Parent, frozenParent) {
		return nil, nil, ErrAssignmentHistory
	}
	succ, err := c.Successor()
	if err != nil {
		return nil, nil, errors.Join(ErrAssignmentHistory, err)
	}
	if err := evmassign.ValidateAssignment(succ); err != nil {
		return nil, nil, errors.Join(ErrAssignmentHistory, err)
	}
	var pop evmassign.PoPContext
	pop.Network, pop.Attempt = c.Network, c.Attempt
	copy(pop.Predecessor[:], c.Predecessor)
	copy(pop.Parent[:], c.Parent)
	if err := evmassign.VerifyPoPs(pop, succ, c.PoPs); err != nil {
		return nil, nil, errors.Join(ErrAssignmentHistory, err)
	}
	provenance := sha256.Sum256(append(bytes.Clone(record.ID()), digest[:]...))
	return pdr, provenance[:], nil
}

// activateEVMAssignment installs the committed successor assignment into the
// designated EVM shard at the first new-root execution boundary. A shard whose
// installed configuration already equals the one in effect is untouched, which
// makes the activation idempotent: it runs once per (epoch, configuration, H).
// The successor technical record derived from the new configuration must equal
// the one H committed, or the whole checkpoint is refused.
func activateEVMAssignment(states map[types.PartitionShardID]*ShardInfo, shardConfs map[types.PartitionShardID]*types.PartitionDescriptionRecord,
	record evmroot.OrderedHandoffRecord, round uint64, hashAlg crypto.Hash) (map[types.PartitionShardID]*ShardInfo, error) {
	out := maps.Clone(states)
	for key, conf := range shardConfs {
		si := states[key]
		if si == nil || conf == nil || conf.PartitionTypeID != evmassign.EVMPartitionTypeID {
			continue
		}
		installed, err := conf.Hash(hashAlg)
		if err != nil {
			return nil, err
		}
		if bytes.Equal(installed, si.ShardConfHash) {
			continue
		}
		if conf.EpochStart != round || conf.Epoch != si.TR.Epoch+1 {
			return nil, fmt.Errorf("%w: configuration epoch %d starting at %d does not follow the installed epoch %d at boundary %d",
				ErrControlCheckpoint, conf.Epoch, conf.EpochStart, si.TR.Epoch, round)
		}
		tr, err := successorTechnicalRecord(si, conf, hashAlg)
		if err != nil {
			return nil, err
		}
		digest, err := tr.Hash()
		if err != nil || !bytes.Equal(digest, record.SuccessorTRHash) {
			return nil, fmt.Errorf("%w: committed successor technical record differs from the derived assignment", ErrControlCheckpoint)
		}
		advanced := *si
		advanced.Fees = maps.Clone(si.Fees)
		advanced.TR = tr
		next, err := advanced.nextEpoch(conf, hashAlg)
		if err != nil {
			return nil, err
		}
		out[key] = next
	}
	return out, nil
}

// expectedCommitSuccessorTR is the successor technical record H must commit for
// the frozen shard, or nil for a root-only handoff, whose record is unchanged
// behavior. It runs at Commit admission and never reads local schedules.
func expectedCommitSuccessorTR(candidates candidateSource, record evmroot.OrderedHandoffRecord, si *ShardInfo, hashAlg crypto.Hash) ([]byte, error) {
	if candidates == nil || si == nil {
		return nil, nil
	}
	preimage, err := candidates.HandoffCandidate(record.NextBodyID)
	if err != nil {
		return nil, errors.Join(ErrAssignmentHistory, err)
	}
	if len(preimage) == 0 {
		return nil, nil
	}
	_, pdr, err := candidateActivatedPDR(preimage, record.ActivationRound)
	if err != nil {
		return nil, err
	}
	tr, err := successorTechnicalRecord(si, pdr, hashAlg)
	if err != nil {
		return nil, err
	}
	return tr.Hash()
}

// AssignmentSuccessorTRHash is the successor technical record hash a leader
// commits in H for a retained candidate preimage.
func AssignmentSuccessorTRHash(si *ShardInfo, preimage []byte, activation uint64, hashAlg crypto.Hash) ([]byte, error) {
	_, pdr, err := candidateActivatedPDR(preimage, activation)
	if err != nil {
		return nil, err
	}
	tr, err := successorTechnicalRecord(si, pdr, hashAlg)
	if err != nil {
		return nil, err
	}
	return tr.Hash()
}
