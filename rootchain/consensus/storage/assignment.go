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
	// ErrActivationBoundary refuses an activation whose configuration does not start at the committed activation round.
	ErrActivationBoundary = errors.New("configuration start is not the committed activation round")
)

// DerivedConfigInstaller is the orchestration's internal writer. Verified
// derivation from committed history and genesis initialization are its only
// callers for the designated EVM shard.
type DerivedConfigInstaller interface {
	InstallDerivedShardConfig(conf *types.PartitionDescriptionRecord, provenance []byte) error
}

// DerivedBatchInstaller installs everything one handoff derives atomically.
type DerivedBatchInstaller interface {
	InstallDerivedShardConfigs(confs []*types.PartitionDescriptionRecord, provenance []byte) error
}

// InstallDerived installs a handoff's derived configurations: atomically when the orchestration can, else one by one.
func InstallDerived(orchestration Orchestration, confs []*types.PartitionDescriptionRecord, provenance []byte) error {
	if batch, ok := orchestration.(DerivedBatchInstaller); ok {
		return batch.InstallDerivedShardConfigs(confs, provenance)
	}
	installer, ok := orchestration.(DerivedConfigInstaller)
	if !ok {
		return fmt.Errorf("%w: orchestration cannot install a derived configuration", ErrAssignmentHistory)
	}
	for _, conf := range confs {
		if err := installer.InstallDerivedShardConfig(conf, provenance); err != nil {
			return err
		}
	}
	return nil
}

// derivedHistory is the orchestration's committed-history-derived record.
type derivedHistory interface {
	DerivedChain(partition types.PartitionID, shard types.ShardID, afterEpoch uint64) ([]evmassign.ChainStep, error)
	ShardConfigByEpoch(partition types.PartitionID, shard types.ShardID, epoch uint64) (*types.PartitionDescriptionRecord, error)
}

// CommittedChain reads the committed, unacknowledged assignment steps of the
// shard from the derived history: every derived configuration above the
// acknowledged shard epoch, on the acknowledged base. An empty chain means no
// assignment is pending.
func CommittedChain(orchestration Orchestration, partition types.PartitionID, shard types.ShardID, acknowledged uint64) (evmassign.Chain, error) {
	history, ok := orchestration.(derivedHistory)
	if !ok {
		return evmassign.Chain{}, fmt.Errorf("%w: orchestration keeps no derived history", ErrAssignmentHistory)
	}
	steps, err := history.DerivedChain(partition, shard, acknowledged)
	if err != nil {
		return evmassign.Chain{}, errors.Join(ErrAssignmentHistory, err)
	}
	if len(steps) == 0 {
		return evmassign.Chain{}, nil
	}
	base, err := history.ShardConfigByEpoch(partition, shard, acknowledged)
	if err != nil || base == nil {
		return evmassign.Chain{}, fmt.Errorf("%w: acknowledged configuration unavailable", ErrAssignmentHistory)
	}
	baseHash, err := evmassign.PDRHash(base)
	if err != nil {
		return evmassign.Chain{}, err
	}
	for i, step := range steps {
		if step.ShardEpoch != acknowledged+uint64(i)+1 || step.RootEpoch != steps[0].RootEpoch+uint64(i) {
			return evmassign.Chain{}, fmt.Errorf("%w: derived steps are not consecutive", ErrAssignmentHistory)
		}
	}
	return evmassign.Chain{BaseRootEpoch: steps[0].RootEpoch - 1, BaseShardEpoch: acknowledged,
		BaseActiveHash: baseHash[:], Steps: steps}, nil
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
	c, pdr, err := evmassign.ActivatedFromPreimage(preimage, activation)
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
func DeriveActivatedPDR(record evmroot.OrderedHandoffRecord, body evmroot.TrustBaseBodyV2, preimage, _ []byte) (*types.PartitionDescriptionRecord, []byte, error) {
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
	if c.Network != record.Network || !bytes.Equal(c.Predecessor, record.PredecessorBodyID) || c.Attempt != record.Attempt {
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
	if err := evmassign.VerifyPoPs(pop, succ, c.PoPs); err != nil {
		return nil, nil, errors.Join(ErrAssignmentHistory, err)
	}
	provenance, err := evmassign.Provenance{RecordID: record.ID(), CandidateDigest: digest[:], RootEpoch: record.Epoch + 1}.Bytes()
	if err != nil {
		return nil, nil, errors.Join(ErrAssignmentHistory, err)
	}
	return pdr, provenance, nil
}

// DeriveActivatedConfigs is DeriveActivatedPDR plus the aggregator validator replacements the same candidate commits: it
// returns the EVM configuration first, then one activated configuration per change (sorted as committed), all verified
// against the record, body and preimage, with the shared provenance. The state-dependent half (each change replaces exactly the
// installed configuration of an existing non-EVM shard) is checked by the callers that hold the installed configurations.
func DeriveActivatedConfigs(record evmroot.OrderedHandoffRecord, body evmroot.TrustBaseBodyV2, preimage, frozenParent []byte) ([]*types.PartitionDescriptionRecord, []byte, []evmassign.DecodedChange, error) {
	evm, provenance, err := DeriveActivatedPDR(record, body, preimage, frozenParent)
	if err != nil {
		return nil, nil, nil, err
	}
	c, err := evmassign.DecodeCandidate(preimage)
	if err != nil {
		return nil, nil, nil, errors.Join(ErrAssignmentHistory, err)
	}
	var pop evmassign.PoPContext
	pop.Network, pop.Attempt = c.Network, c.Attempt
	copy(pop.Predecessor[:], c.Predecessor)
	changes, err := evmassign.ValidateChanges(c.Changes, c.SourceRef, pop, evmroot.D4ControlPartition)
	if err != nil {
		return nil, nil, nil, errors.Join(ErrAssignmentHistory, err)
	}
	confs := []*types.PartitionDescriptionRecord{evm}
	for _, d := range changes {
		activated, err := evmassign.Activate(d.Successor, record.ActivationRound)
		if err != nil {
			return nil, nil, nil, errors.Join(ErrAssignmentHistory, err)
		}
		confs = append(confs, activated)
	}
	return confs, provenance, changes, nil
}

// activateEVMAssignment installs the committed successor assignment into the
// designated EVM shard at the first new-root execution boundary. epochStart is the COMMITTED activation round of the handoff
// (record.ActivationRound, the root epoch's start): every configuration it installs must start exactly there. It is deliberately not
// the round of the block that executes the boundary: that block is the first one a successor-committee leader manages to propose,
// and rounds that time out before it (a restarting committee, a faulty leader) move it past the epoch start. A shard whose
// installed configuration already equals the one in effect is untouched, which
// makes the activation idempotent: it runs once per (epoch, configuration, H).
// The successor technical record derived from the new configuration must equal
// the one H committed, or the whole checkpoint is refused.
//
// The same boundary activates every aggregator validator replacement the committed candidate names (derived, a key of
// derivedShards): their technical record advances at once and the new trust base is installed immediately, so the retired
// key's first post-boundary request is refused. Such a shard has no committed successor technical record: every root derives it
// from the same configuration and shard state, exactly as an ordinary round would.
func activateEVMAssignment(states map[types.PartitionShardID]*ShardInfo, shardConfs map[types.PartitionShardID]*types.PartitionDescriptionRecord,
	record evmroot.OrderedHandoffRecord, epochStart uint64, hashAlg crypto.Hash, derivedShards map[types.PartitionShardID]struct{}) (map[types.PartitionShardID]*ShardInfo, error) {
	out := maps.Clone(states)
	for key, conf := range shardConfs {
		si := states[key]
		if si == nil || conf == nil {
			continue
		}
		if _, derived := derivedShards[key]; derived && conf.PartitionTypeID != evmassign.EVMPartitionTypeID {
			installed, err := conf.Hash(hashAlg)
			if err != nil {
				return nil, err
			}
			if bytes.Equal(installed, si.ShardConfHash) {
				continue
			}
			if conf.EpochStart != epochStart || conf.Epoch != si.TR.Epoch+1 {
				return nil, fmt.Errorf("%w: %w: shard %s configuration epoch %d starting at %d does not follow the installed epoch %d at the committed activation %d",
					ErrControlCheckpoint, ErrActivationBoundary, key, conf.Epoch, conf.EpochStart, si.TR.Epoch, epochStart)
			}
			tr, err := successorTechnicalRecord(si, conf, hashAlg)
			if err != nil {
				return nil, err
			}
			advanced := *si
			advanced.Fees = maps.Clone(si.Fees)
			advanced.TR = tr
			next, err := advanced.nextEpoch(conf, hashAlg)
			if err != nil {
				return nil, err
			}
			out[key] = next
			continue
		}
		if conf.PartitionTypeID != evmassign.EVMPartitionTypeID {
			continue
		}
		installed, err := conf.Hash(hashAlg)
		if err != nil {
			return nil, err
		}
		if bytes.Equal(installed, si.ShardConfHash) {
			continue
		}
		if conf.EpochStart != epochStart || conf.Epoch != si.TR.Epoch+1 {
			return nil, fmt.Errorf("%w: %w: configuration epoch %d starting at %d does not follow the installed epoch %d at the committed activation %d",
				ErrControlCheckpoint, ErrActivationBoundary, conf.Epoch, conf.EpochStart, si.TR.Epoch, epochStart)
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

// derivedChangeShards names the aggregator shards the committed candidate of H replaces validators of.
func derivedChangeShards(candidates candidateSource, record evmroot.OrderedHandoffRecord) (map[types.PartitionShardID]struct{}, error) {
	if candidates == nil {
		return nil, nil
	}
	preimage, err := candidates.HandoffCandidate(record.NextBodyID)
	if err != nil {
		return nil, errors.Join(ErrAssignmentHistory, err)
	}
	if len(preimage) == 0 {
		return nil, nil
	}
	c, err := evmassign.DecodeCandidate(preimage)
	if err != nil {
		return nil, errors.Join(ErrAssignmentHistory, err)
	}
	out := make(map[types.PartitionShardID]struct{}, len(c.Changes))
	for _, ch := range c.Changes {
		if ch.Kind != evmassign.ChangeReplaceShardValidators {
			return nil, errors.Join(ErrAssignmentHistory, evmassign.ErrUnsupportedChange)
		}
		_, succ, err := evmassign.DecodeReplaceShardValidators(ch.Payload)
		if err != nil {
			return nil, errors.Join(ErrAssignmentHistory, err)
		}
		out[types.PartitionShardID{PartitionID: succ.PartitionID, ShardID: succ.ShardID.Key()}] = struct{}{}
	}
	return out, nil
}
