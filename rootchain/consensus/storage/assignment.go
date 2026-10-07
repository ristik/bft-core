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
	"github.com/unicitynetwork/bft-core/internal/quorumweight"
	"github.com/unicitynetwork/bft-core/internal/weightvalidation"
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
	return successorTechnicalRecordWith(si, pdr, hashAlg, (*ShardInfo).resetTrustBase)
}

// successorTechnicalRecordWith is successorTechnicalRecord with the successor's trust base derivation supplied.
func successorTechnicalRecordWith(si *ShardInfo, pdr *types.PartitionDescriptionRecord, hashAlg crypto.Hash,
	reset func(*ShardInfo, *types.PartitionDescriptionRecord, crypto.Hash, []byte) error) (certification.TechnicalRecord, error) {
	if si == nil || pdr == nil || si.TR.Epoch == ^uint64(0) || pdr.Epoch != si.TR.Epoch+1 {
		return certification.TechnicalRecord{}, ErrAssignmentHistory
	}
	clone := *si
	clone.Fees = maps.Clone(si.Fees)
	if err := clone.nextRoundWith(nil, pdr, hashAlg, reset); err != nil {
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
	return deriveActivatedPDR(record, id[:], body.Epoch, body.EarliestActivation, body.ChangeRecordHash, preimage, weightvalidation.ModeUnit)
}

// deriveActivatedPDR is DeriveActivatedPDR over the facts of a body of either version: its identity, epoch, earliest activation and
// change-record hash. mode selects the validator weight rules of the successor assignment; only a verified V3 activation passes
// ModeWeighted.
func deriveActivatedPDR(record evmroot.OrderedHandoffRecord, bodyID []byte, bodyEpoch, earliest uint64, changeRecordHash, preimage []byte,
	mode weightvalidation.Mode) (*types.PartitionDescriptionRecord, []byte, error) {
	digest := sha256.Sum256(preimage)
	if !bytes.Equal(bodyID, record.NextBodyID) || bodyEpoch != record.Epoch+1 ||
		!bytes.Equal(changeRecordHash, evmroot.D4CandidateContextHash(record.Network, record.PredecessorBodyID, record.Attempt, digest[:], earliest)) {
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
	if err := validateAssignment(succ, mode); err != nil {
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

// validateAssignment is evmassign.ValidateAssignment under the validator weight rules of mode: the unit rules unchanged, or, for
// a verified Q3 activation, the bounded weights of the weighted rules.
func validateAssignment(succ *types.PartitionDescriptionRecord, mode weightvalidation.Mode) error {
	if mode == weightvalidation.ModeUnit {
		return evmassign.ValidateAssignment(succ)
	}
	if err := weightvalidation.PDR(succ, weightvalidation.RoleEVM, mode); err != nil {
		return fmt.Errorf("%w: %v", evmassign.ErrAssignment, err)
	}
	if succ.EpochStart != 0 {
		return fmt.Errorf("%w: activation round is set before commit", evmassign.ErrEpoch)
	}
	return nil
}

// ErrRecordNotCommitted refuses a handoff record that is not a verified committed record (a freeze, an abort, a malformed record,
// or one the committed history does not vouch for) as the source of an activation. It is also ErrAssignmentHistory.
var ErrRecordNotCommitted error = &requestSentinel{"handoff record is not a verified committed record", ErrAssignmentHistory}

// CommittedHandoffs is the committed consensus history that vouches for a handoff record: the commit proof and the predecessor
// linkage against an established anchor. The record's contents agreeing with its body and candidate is not that.
type CommittedHandoffs interface {
	VerifyCommitted(record evmroot.OrderedHandoffRecord) error
}

// ActivationFromHandoff authenticates a committed handoff (record, successor body and candidate preimage verified against each
// other by DeriveActivatedPDR) and returns the assignment it activates at record.ActivationRound, with the root identity that
// authorises it and the successor technical record digest it committed. Coupling is rechecked where the configuration
// requires it. Production policy is unit; a weighted policy is not reachable from here before Q3.
func ActivationFromHandoff(committed CommittedHandoffs, record evmroot.OrderedHandoffRecord, body evmroot.TrustBaseBodyV2, preimage, frozenParent []byte, hashAlg crypto.Hash, version uint64) (*RequestActivation, error) {
	// only a verified committed record mints an activation: checked before anything is derived from its contents
	if committed == nil {
		return nil, fmt.Errorf("%w: no committed history", ErrRecordNotCommitted)
	}
	if !record.Valid() {
		return nil, fmt.Errorf("%w: kind %q", ErrRecordNotCommitted, record.Kind)
	}
	if err := committed.VerifyCommitted(record); err != nil {
		return nil, errors.Join(ErrRecordNotCommitted, err)
	}
	pdr, _, err := DeriveActivatedPDR(record, body, preimage, frozenParent)
	if err != nil {
		return nil, err
	}
	c, err := evmassign.DecodeCandidate(preimage)
	if err != nil {
		return nil, errors.Join(ErrAssignmentHistory, err)
	}
	if evmassign.CouplingRequired(pdr) {
		if err := evmassign.ValidateCoupling(c.RootMembers, pdr, c.Bindings); err != nil {
			return nil, errors.Join(ErrAssignmentHistory, err)
		}
	}
	return newRequestActivation(pdr, hashAlg, quorumweight.PolicyUnit, nil, record.Epoch+1, record.NextBodyID, record.ActivationRound, record.SuccessorTRHash, version)
}

// VerifiedActivation is the verified Q3 history's entry for an activated epoch (q3format.Entry, which only the history mints, from
// the old committee's authenticated commit). The storage package states it as an interface because q3format's own tests build on
// this package; like CommittedHandoffs it is provenance by the verifier the caller holds, and an entry that is not an activation
// (a legacy or zero one) answers Handoff false and is refused.
type VerifiedActivation interface {
	Handoff() (evmroot.VerifiedHandoff, evmroot.EpochGenesis, bool)
	Epoch() uint64
	Start() uint64
	EarliestActivation() uint64
	BodyID() [32]byte
	ActivationCommitID() [32]byte
	Projection() *types.RootTrustBaseV1
}

// ActivationFromVerifiedV3 is ActivationFromHandoff for a Q3 activation, and the only way a weighted request policy is reached.
// The committed record is the verified history's own (the entry's activation record id, body and boundary must be the record's,
// so a freeze, an abort or a record the history did not mint cannot be presented), the successor assignment is validated under
// the weighted rules, the candidate's root members must be the entry's committee with its exact weights, and the EVM request
// context is the mirrored weighted one built from that coupling. A legacy entry has no weighted branch: it is refused.
func ActivationFromVerifiedV3(entry VerifiedActivation, record evmroot.OrderedHandoffRecord, preimage []byte, hashAlg crypto.Hash, version uint64) (*RequestActivation, error) {
	commit := entry.ActivationCommitID()      // zero for a legacy or zero entry: no record has that id
	if !bytes.Equal(record.ID(), commit[:]) { // the id commits to the record's kind, epoch, boundary, body and candidate context
		return nil, fmt.Errorf("%w: the record is not the one that activated epoch %d", ErrRecordNotCommitted, entry.Epoch())
	}
	body, projection := entry.BodyID(), entry.Projection()
	pdr, _, err := deriveActivatedPDR(record, body[:], entry.Epoch(), entry.EarliestActivation(), projection.ChangeRecordHash, preimage, weightvalidation.ModeWeighted)
	if err != nil {
		return nil, err
	}
	c, err := evmassign.DecodeCandidate(preimage)
	if err != nil {
		return nil, errors.Join(ErrAssignmentHistory, err)
	}
	if len(c.RootMembers) != len(projection.RootNodes) {
		return nil, fmt.Errorf("%w: the candidate's root committee is not the activated one", ErrAssignmentHistory)
	}
	for i, m := range c.RootMembers {
		n := projection.RootNodes[i]
		if m.NodeID != n.NodeID || m.Weight != n.Stake || !bytes.Equal(m.Key, n.SigKey) {
			return nil, fmt.Errorf("%w: the candidate's root member %q is not the activated committee's", ErrAssignmentHistory, m.NodeID)
		}
	}
	if err := evmassign.ValidateCoupling(c.RootMembers, pdr, c.Bindings); err != nil {
		return nil, errors.Join(ErrAssignmentHistory, err)
	}
	coupling := &quorumweight.Coupling{RootEpoch: entry.Epoch(), RootBodyID: bytes.Clone(body[:]), Root: c.RootMembers, Bindings: c.Bindings}
	return newRequestActivation(pdr, hashAlg, quorumweight.PolicyEVMWeighted, coupling, entry.Epoch(), body[:], record.ActivationRound, record.SuccessorTRHash, version)
}

// DeriveActivatedConfigs is DeriveActivatedPDR plus the aggregator validator replacements the same candidate commits: it
// returns the EVM configuration first, then one activated configuration per change (sorted as committed), all verified
// against the record, body and preimage, with the shared provenance. The state-dependent half (each change replaces exactly the
// installed configuration of an existing non-EVM shard) is checked by the callers that hold the installed configurations.
func DeriveActivatedConfigs(record evmroot.OrderedHandoffRecord, body evmroot.TrustBaseBodyV2, preimage, frozenParent []byte) ([]*types.PartitionDescriptionRecord, []byte, []evmassign.DecodedChange, error) {
	id := body.Identity()
	return deriveActivatedConfigs(record, retainedBody{id: id[:], epoch: body.Epoch, earliest: body.EarliestActivation, changeRecordHash: body.ChangeRecordHash, mode: weightvalidation.ModeUnit}, preimage)
}

// retainedBody is what the derivation needs of a retained successor body of either version: its identity, epoch, earliest activation and
// change-record hash, and the validator weight rules of its assignment.
type retainedBody struct {
	id               []byte
	epoch, earliest  uint64
	changeRecordHash []byte
	mode             weightvalidation.Mode
}

const retainedV3Domain = "UNICITY_TRUSTBASE_V3"

// decodeRetainedBody reads the body retained under the committed body identity. A V2 body is decoded and validated in full, as before.
// A V3 body is a domain-tagged array whose identity is the SHA-256 of exactly these bytes: the facts the derivation reads are
// authenticated by that identity, which deriveActivatedPDR compares with the committed record's NextBodyID, and the body was
// validated in full when the verified history minted its activation. Its assignment weights are the weighted rules'.
func decodeRetainedBody(raw []byte) (retainedBody, error) {
	var outer []any
	if err := types.Cbor.Unmarshal(raw, &outer); err == nil && len(outer) == 2 {
		if domain, _ := outer[0].(string); domain == retainedV3Domain {
			fields, ok := outer[1].([]any)
			if !ok || len(fields) != 10 {
				return retainedBody{}, ErrHandoffRecord
			}
			epoch, eOK := fields[2].(uint64)
			earliest, aOK := fields[3].(uint64)
			crh, cOK := optionalD3Bytes(fields[7])
			if version, _ := fields[0].(uint64); version != 3 || !eOK || !aOK || !cOK {
				return retainedBody{}, ErrHandoffRecord
			}
			id := sha256.Sum256(raw)
			return retainedBody{id: id[:], epoch: epoch, earliest: earliest, changeRecordHash: crh, mode: weightvalidation.ModeWeighted}, nil
		}
	}
	body, err := DecodeHandoffBody(raw)
	if err != nil {
		return retainedBody{}, err
	}
	id := body.Identity()
	return retainedBody{id: id[:], epoch: body.Epoch, earliest: body.EarliestActivation, changeRecordHash: body.ChangeRecordHash, mode: weightvalidation.ModeUnit}, nil
}

func deriveActivatedConfigs(record evmroot.OrderedHandoffRecord, body retainedBody, preimage []byte) ([]*types.PartitionDescriptionRecord, []byte, []evmassign.DecodedChange, error) {
	evm, provenance, err := deriveActivatedPDR(record, body.id, body.epoch, body.earliest, body.changeRecordHash, preimage, body.mode)
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
