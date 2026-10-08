package storage

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"sort"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/internal/quorumweight"
	"github.com/unicitynetwork/bft-core/internal/weightvalidation"

	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"
)

const evmPartitionTypeID = 8

// EVMPartitionTypeID is the partition type of the designated EVM shard.
const EVMPartitionTypeID = evmPartitionTypeID

type (
	ExecutedBlock struct {
		_          struct{}            `cbor:",toarray"`
		BlockData  *rctypes.BlockData  // proposed block
		HashAlgo   crypto.Hash         // hash algorithm for the block
		RootHash   hex.Bytes           // resulting root hash
		Qc         *rctypes.QuorumCert // block's quorum certificate (from next view)
		CommitQc   *rctypes.QuorumCert // block's commit certificate
		ShardState ShardStates
	}

	IRChangeReqVerifier interface {
		VerifyIRChangeReq(round uint64, irChReq *rctypes.IRChangeReq) (*types.InputRecord, error)
	}
)

// ErrShardConfMismatch is the refusal of a checkpoint whose shard configuration hash does not match the local
// orchestration's configuration of that shard.
var ErrShardConfMismatch = errors.New("calculated shard conf hash doesn't match the value in block data")

func NewRootBlock(block *abdrc.CommittedBlock, hash crypto.Hash, orchestration Orchestration, networkProfile ...uint64) (*ExecutedBlock, error) {
	profile, err := profileVersion(networkProfile)
	if err != nil {
		return nil, err
	}
	if block == nil || block.Block == nil || block.CommitQc == nil || block.CommitQc.LedgerCommitInfo == nil {
		return nil, errors.New("missing committed root certificate")
	}
	if (profile == ProfileHandoff) != (block.Control != nil) {
		return nil, ErrNetworkProfile
	}
	if (profile == ProfileHandoff && block.Block.GetVersion() != 2) || (profile == ProfileLegacy && block.Block.GetVersion() != 1) {
		return nil, ErrNetworkProfile
	}
	if block.Control != nil && (block.Control.Network != uint64(orchestration.NetworkID()) || block.Control.Epoch != block.Block.Epoch || len(block.Control.PredecessorBodyID) != 32) {
		return nil, ErrNetworkProfile
	}
	if block.Control != nil {
		if err := validateControl(block.Control); err != nil {
			return nil, err
		}
	}
	configRound := block.GetRound()
	if block.Control != nil && block.Control.Phase == "committed" {
		if block.Control.OrderedRound == 0 || block.Control.OrderedRound > configRound {
			return nil, errors.New("invalid control order round")
		}
		configRound = block.Control.OrderedRound
	}
	shardConfs, err := orchestration.ShardConfigs(configRound)
	if err != nil {
		return nil, fmt.Errorf("loading shard configurations for round %d: %w", block.GetRound(), err)
	}

	shardState := ShardStates{
		States:  make(map[types.PartitionShardID]*ShardInfo, len(shardConfs)),
		Changed: ShardSet{},
		Control: block.Control,
	}
	for _, d := range block.ShardInfo {
		if profile == ProfileHandoff && d.Partition == evmroot.D4ControlPartition {
			return nil, ErrControlCheckpoint
		}
		shardKey := types.PartitionShardID{PartitionID: d.Partition, ShardID: d.Shard.Key()}
		shardConf, ok := shardConfs[shardKey]
		if !ok {
			return nil, fmt.Errorf("block contains shard %s - %s which is not listed in the local orchestration", d.Partition, d.Shard)
		}
		shardConfHash, err := shardConf.Hash(crypto.SHA256)
		if err != nil {
			return nil, fmt.Errorf("calculating PDR hash: %w", err)
		}
		if !bytes.Equal(d.ShardConfHash, shardConfHash) {
			return nil, fmt.Errorf("%w for %s - %s", ErrShardConfMismatch, d.Partition, d.Shard)
		}

		si := &ShardInfo{
			PartitionID:   d.Partition,
			ShardID:       d.Shard,
			T2Timeout:     d.T2Timeout,
			ShardConfHash: d.ShardConfHash,
			RootHash:      d.RootHash,
			PrevEpochStat: d.PrevEpochStat,
			Stat:          d.Stat,
			PrevEpochFees: d.PrevEpochFees,
			Fees:          d.Fees,
			IR:            d.IR,
			TR:            d.IRTR,
		}
		if d.UC != nil {
			si.LastCR = &certification.CertificationResponse{
				Partition: d.Partition,
				Shard:     d.Shard,
				Technical: *d.TR,
				UC:        *d.UC,
			}
		}
		if profile == ProfileHandoff {
			feeHash, err := si.feeHash(crypto.SHA256)
			if err != nil || !bytes.Equal(feeHash, si.TR.FeeHash) {
				return nil, fmt.Errorf("%w: fee accumulator differs from technical record", ErrControlCheckpoint)
			}
			statHash, err := si.statHash(crypto.SHA256)
			if err != nil || !bytes.Equal(statHash, si.TR.StatHash) {
				return nil, fmt.Errorf("%w: statistics differ from technical record", ErrControlCheckpoint)
			}
		}
		if err := si.resetTrustBase(shardConf, crypto.SHA256, shardConfHash); err != nil {
			return nil, fmt.Errorf("initializing shard trustbase: %w", err)
		}
		shardState.States[shardKey] = si
	}

	ut, _, err := shardState.UnicityTree(hash)
	if err != nil {
		return nil, err
	}
	if profile == ProfileHandoff && !bytes.Equal(ut.RootHash(), block.CommitQc.LedgerCommitInfo.Hash) {
		return nil, ErrControlCheckpoint
	}
	return &ExecutedBlock{
		BlockData:  block.Block,
		HashAlgo:   hash,
		RootHash:   ut.RootHash(),
		Qc:         block.Qc,
		CommitQc:   block.CommitQc,
		ShardState: shardState,
	}, nil
}

func (x *ExecutedBlock) Extend(newBlock *rctypes.BlockData, verifier IRChangeReqVerifier, orchestration Orchestration, hash crypto.Hash, log *slog.Logger) (*ExecutedBlock, error) {
	return x.extendWithAuthority(newBlock, verifier, orchestration, hash, log, nil, nil, nil)
}

func (x *ExecutedBlock) extendWithAuthority(newBlock *rctypes.BlockData, verifier IRChangeReqVerifier, orchestration Orchestration, hash crypto.Hash, log *slog.Logger, authority handoffAuthority, candidates candidateSource, services *PosServices) (*ExecutedBlock, error) {
	bootstrapChild := isEpochAnchorRoot(x)
	if bootstrapChild && (newBlock.Anchor == nil || !bytes.Equal(newBlock.Anchor.GenesisID, x.BlockData.Anchor.GenesisID) ||
		newBlock.Anchor.Slot != x.GetRound() || newBlock.Epoch != x.BlockData.Epoch) {
		return nil, ErrNetworkProfile
	}
	if x.ShardState.Control != nil && newBlock.Epoch != x.BlockData.Epoch {
		return nil, ErrNetworkProfile
	}
	if !bootstrapChild && x.ShardState.Control != nil && x.ShardState.Control.Phase == "committed" {
		if newBlock.Payload == nil || !newBlock.Payload.IsEmpty() || newBlock.Payload.Version != 2 {
			return nil, ErrHandoffSuffix
		}
		unchanged := ShardStates{States: make(map[types.PartitionShardID]*ShardInfo, len(x.ShardState.States)), Changed: ShardSet{}}
		control := *x.ShardState.Control
		control.PredecessorBodyID = bytes.Clone(control.PredecessorBodyID)
		control.RecordBytes = bytes.Clone(control.RecordBytes)
		control.PreviousDigest = bytes.Clone(control.PreviousDigest)
		control.FrozenParent = bytes.Clone(control.FrozenParent)
		unchanged.Control = &control
		for key, previous := range x.ShardState.States {
			copy := *previous
			copy.Fees = maps.Clone(previous.Fees)
			unchanged.States[key] = &copy
		}
		return &ExecutedBlock{BlockData: newBlock, HashAlgo: hash, RootHash: bytes.Clone(x.RootHash), ShardState: unchanged}, nil
	}
	// clone parent state
	shardConfs, err := orchestration.ShardConfigs(newBlock.Round)
	if err != nil {
		return nil, fmt.Errorf("loading shard configurations for round %d: %w", newBlock.Round, err)
	}

	parentState := x.ShardState
	if bootstrapChild {
		record, err := decodeOrderedRecord(parentState.Control.RecordBytes)
		if err != nil || record.Kind != "commit" || len(record.NextBodyID) != 32 || parentState.Control.Epoch+1 != newBlock.Epoch {
			return nil, ErrControlCheckpoint
		}
		// The designated EVM shard installs the committed successor assignment
		// here, once, from the configuration derived from committed history.
		derivedShards, err := derivedChangeShards(candidates, record)
		if err != nil {
			return nil, err
		}
		// The epoch starts at the committed activation round, which is the round after the epoch anchor (the genesis start): every
		// root derives the same value from the committed record, whatever rounds timed out before this first block was proposed.
		if x.GetRound()+1 != record.ActivationRound || newBlock.Round < record.ActivationRound {
			return nil, errors.Join(ErrControlCheckpoint, ErrActivationBoundary)
		}
		states, err := activateEVMAssignment(parentState.States, shardConfs, record, record.ActivationRound, hash, derivedShards)
		if err != nil {
			return nil, err
		}
		parentState.States = states
		parentState.Control = &evmroot.ControlState{Network: parentState.Control.Network,
			Epoch: newBlock.Epoch, PredecessorBodyID: bytes.Clone(record.NextBodyID), Phase: "idle", Pos: parentState.Control.Pos}
	}
	nextShardState, err := parentState.nextBlock(shardConfs, hash)
	if err != nil {
		return nil, fmt.Errorf("creating shard info for the block: %w", err)
	}
	if bootstrapChild {
		// The first ordinary successor block recertifies every imported shard
		// under the new committee once that block is committed.
		for shard := range nextShardState.States {
			nextShardState.Changed[shard] = struct{}{}
		}
	}
	pos, err := loadPos(nextShardState.Control)
	if err != nil {
		return nil, err
	}
	if err := pos.block(newBlock.Epoch, newBlock.Round); err != nil {
		return nil, err
	}
	// Apply the ordered control record before shard requests. A freeze takes
	// effect in its own block, for leaders and for every voter replaying it.
	if nextShardState.Control != nil {
		if len(newBlock.Payload.HandoffRecords) > 2 {
			return nil, ErrHandoffRecord
		}
		if len(newBlock.Payload.HandoffRecords) > 0 {
			var companion []byte
			if len(newBlock.Payload.HandoffRecords) == 2 {
				companion = newBlock.Payload.HandoffRecords[1]
			}
			control, err := applyHandoffRecord(nextShardState.Control, newBlock.Payload.HandoffRecords[0], uint64(orchestration.NetworkID()), newBlock.Epoch, newBlock.Round, authority, companion)
			if err != nil {
				return nil, err
			}
			if control.Phase == "prepared" {
				// The root, not the operator, binds the frozen parent: the EVM IR certified in this branch when the Prepare is
				// executed. The EVM is frozen from this block on, so it is the parent the endorsements and the Freeze must name.
				key, found, err := frozenEVMShard(nextShardState, shardConfs)
				if err != nil {
					return nil, err
				}
				if !found || nextShardState.States[key] == nil || nextShardState.States[key].IR == nil || len(nextShardState.States[key].IR.BlockHash) != 32 {
					return nil, errors.Join(ErrHandoffRecord, ErrPrepareNoEVMParent)
				}
				control.FrozenParent = bytes.Clone(nextShardState.States[key].IR.BlockHash)
			}
			if control.Phase == "endorsed" || control.Phase == "committed" {
				frozen, err := frozenShard(nextShardState, shardConfs, control.FrozenParent)
				if err != nil {
					return nil, err
				}
				if len(companion) != 0 && control.Phase == "endorsed" {
					if err := verifyFreezeAssignment(companion, nextShardState.States[frozen], shardConfs[frozen], orchestration, authority.CurrentRoot(), nextShardState.States, shardConfs); err != nil {
						return nil, err
					}
				}
				if control.Phase == "committed" && nextShardState.Control.Phase == "endorsed" {
					committed, err := decodeOrderedRecord(newBlock.Payload.HandoffRecords[0])
					if err != nil {
						return nil, err
					}
					want, err := expectedCommitSuccessorTR(candidates, committed, nextShardState.States[frozen], hash)
					if err != nil {
						return nil, err
					}
					if want != nil && !bytes.Equal(want, committed.SuccessorTRHash) {
						return nil, errors.Join(ErrHandoffRecord, ErrAssignmentHistory)
					}
					// H is ordered here: the successor's offset is fixed now and an assignment handoff waits for its EVM acknowledgement
					if err := pos.commit(committed, want != nil); err != nil {
						return nil, err
					}
				}
			}
			nextShardState.Control = control
		}
		pos.store(nextShardState.Control)
	} else if len(newBlock.Payload.HandoffRecords) > 0 {
		return nil, ErrNetworkProfile
	}

	for _, irChReq := range newBlock.Payload.Requests {
		if x.ShardState.Control != nil && irChReq.Partition == evmroot.D4ControlPartition {
			return nil, ErrHandoffRecord
		}
		shardKey := types.PartitionShardID{PartitionID: irChReq.Partition, ShardID: irChReq.Shard.Key()}
		if frozen, active, err := frozenShardOf(nextShardState, shardConfs, nextShardState.Control, newBlock.Round); err != nil {
			return nil, err
		} else if active && shardKey == frozen {
			return nil, ErrHandoffFrozen
		}
		si, ok := nextShardState.States[shardKey]
		if !ok {
			log.Info(fmt.Sprintf("no validators in shard config (shard has been removed?) %s", shardKey))
			continue
		}
		// a committed assignment handoff waits for this shard's certified acknowledgement: its IR epoch catches up with the installed one
		awaiting := pos.pendingAck() && si.TR.Epoch != si.IR.Epoch

		if vv := viewDispatch(verifier); vv != nil {
			// View-aware branch: the request is judged under the view resolved from the state this block executes on and the
			// committed history, so the committed anchor lagging behind the activation cannot select another assignment.
			parentID, err := x.BlockData.Hash(hash)
			if err != nil {
				return nil, fmt.Errorf("hashing parent block: %w", err)
			}
			view, err := resolveExecutionView(vv, si, parentID, newBlock.Round, hash)
			if err != nil {
				return nil, fmt.Errorf("resolving request context: %w", err)
			}
			if ignore, why := ineligibleAtExecution(view, irChReq); ignore {
				log.Info(fmt.Sprintf("ignoring a request of shard %s outside its request context: %v", shardKey, why))
				continue
			}
			res, err := vv.VerifyIRChangeReqView(view, irChReq)
			if err != nil {
				return nil, fmt.Errorf("verifying change request: %w", err)
			}
			if !bytes.Equal(res.ViewKey, view.ViewKey()) {
				return nil, fmt.Errorf("%w: verifier judged another view than the one resolved", quorumweight.ErrRequestContext)
			}
			si.IR = res.IR
		} else {
			// The verifier judges the request against the last COMMITTED shard state, which in and just after the activation block is
			// still the pre-activation anchor (old trust base). Every signer must also belong to the configuration ACTIVE for this
			// block, the state executed here; a retired key's request is ignored, identically on every root, like a request for a
			// removed shard. It depends on block content only, so proposal and validation cannot disagree.
			if member, memberErr := requestSignersAreActive(si, irChReq); !member {
				log.Info(fmt.Sprintf("ignoring a request of shard %s signed outside its active configuration: %v", shardKey, memberErr))
				continue
			}
			if si.IR, err = verifier.VerifyIRChangeReq(newBlock.Round, irChReq); err != nil {
				return nil, fmt.Errorf("verifying change request: %w", err)
			}
		}

		if awaiting && si.IR.Epoch == si.TR.Epoch {
			evm, found, err := frozenEVMShard(nextShardState, shardConfs)
			if err != nil {
				return nil, err
			}
			if pos.acknowledges(awaiting, si.IR.Epoch, si.TR.Epoch, shardKey, evm, found) {
				// the acknowledgement is certified in this block: project it at this block's progress and committed time
				if err := pos.ack(candidates, newBlock.Round, newBlock.Timestamp, si.IR.Epoch); err != nil {
					return nil, err
				}
			}
		}

		// timeout IR change request do not have BCR
		var req *certification.BlockCertificationRequest
		if len(irChReq.Requests) > 0 {
			req = irChReq.Requests[0]
		}
		if err = si.nextRound(req, shardConfs[shardKey], hash); err != nil {
			return nil, fmt.Errorf("updating shard info for the next round: %w", err)
		}

		nextShardState.Changed[shardKey] = struct{}{}
	}
	// the P85 controls follow the certifications, in payload order
	if err := pos.controls(newBlock, services); err != nil {
		return nil, err
	}
	if nextShardState.Control != nil {
		pos.store(nextShardState.Control) // an acknowledgement or a control changes the state the control digest commits
	}
	nextShardState.Records = pos.records
	ut, _, err := nextShardState.UnicityTree(hash)
	if err != nil {
		return nil, fmt.Errorf("creating UnicityTree: %w", err)
	}
	return &ExecutedBlock{
		BlockData:  newBlock,
		HashAlgo:   hash,
		RootHash:   ut.RootHash(),
		ShardState: nextShardState,
	}, nil
}

// freezeAssignmentRules are the validator weight rules the successor assignment of a Freeze companion is judged under: the unit rules for
// the legacy and V2 companions, the bounded weights for a V3 one (the authority already admitted it under them: a weighted rotation out of
// a unit epoch carries stakes the unit rules refuse).
func freezeAssignmentRules(version uint64) evmassign.Rules {
	if version == freezeV3Version {
		return weightvalidation.EVMRules(weightvalidation.ModeWeighted)
	}
	return evmassign.UnitRules
}

// verifyFreezeAssignment runs the EVM-state-dependent half of freeze
// admission, after the authority has checked the candidate's static bindings.
// The installed assignment is the authenticated configuration of the frozen
// shard at this block, never a value the candidate supplies.
func verifyFreezeAssignment(companion []byte, si *ShardInfo, installed *types.PartitionDescriptionRecord, orchestration Orchestration, currentRoot []evmassign.RootMember,
	states map[types.PartitionShardID]*ShardInfo, shardConfs map[types.PartitionShardID]*types.PartitionDescriptionRecord) error {
	fc, err := ParseFreezeCompanion(companion)
	if err != nil || si == nil || installed == nil {
		return ErrHandoffRecord
	}
	// An installed assignment whose acknowledgement is not certified is exactly
	// the state where TR already names the successor epoch but IR does not.
	if currentRoot == nil {
		return ErrHandoffRecord // the old committee is required: coupling is judged against it
	}
	pending := si.TR.Epoch != si.IR.Epoch
	if len(fc.Preimage) == 0 {
		// The legacy root-only companion carries no EVM binding: on a chain that requires coupling it must not change
		// the committee (it could otherwise add a root entity without its delegated EVM key).
		if evmassign.CouplingRequired(installed) {
			body, bodyErr := decodeD3Body(fc.Body)
			if bodyErr != nil {
				return errors.Join(ErrHandoffRecord, bodyErr)
			}
			next := make([]evmassign.RootMember, 0, len(body.Members))
			for _, m := range body.Members {
				next = append(next, evmassign.RootMember{NodeID: m.NodeID, Key: m.ConsensusKey, Weight: m.Weight})
			}
			sort.Slice(next, func(i, j int) bool { return next[i].NodeID < next[j].NodeID })
			if !evmassign.SameCommittee(next, currentRoot) {
				return errors.Join(ErrHandoffRecord, evmassign.ErrCoupling)
			}
		}
		if pending {
			return ErrAssignmentAckPending
		}
		return nil
	}
	candidate, err := evmassign.DecodeCandidate(fc.Preimage)
	if err != nil {
		return errors.Join(ErrHandoffRecord, err)
	}
	succ, err := candidate.Successor()
	if err != nil {
		return errors.Join(ErrHandoffRecord, err)
	}
	if candidate.Supersedes == nil && pending {
		return ErrAssignmentAckPending
	}
	if err := evmassign.VerifyInstalledWith(freezeAssignmentRules(fc.Version), candidate, succ, installed, currentRoot); err != nil {
		return errors.Join(ErrHandoffRecord, err)
	}
	if err := verifyShardChanges(candidate, states, shardConfs); err != nil {
		return errors.Join(ErrHandoffRecord, err)
	}
	if candidate.Supersedes != nil {
		if err := verifySupersession(candidate.Supersedes, si, orchestration); err != nil {
			return err
		}
	}
	// The kind rules run over the committed history the supersession evidence was just checked against.
	lctx, err := LifecycleFor(orchestration, si.PartitionID, si.ShardID, si.IR.Epoch, installed)
	if err != nil {
		return errors.Join(ErrHandoffRecord, err)
	}
	if err := evmassign.VerifyLifecycle(candidate, lctx); err != nil {
		return errors.Join(ErrHandoffRecord, err)
	}
	return nil
}

// requestSignersAreActive reports whether every block certification request of the IR change request is signed by a member of the
// shard's executing configuration: the node is in the active trust base AND the signature verifies under the ACTIVE key of that node
// (a rotation may keep a node id and change only its key, so membership by id alone would let the retired key through). A timeout
// request carries none.
func requestSignersAreActive(si *ShardInfo, irChReq *rctypes.IRChangeReq) (bool, error) {
	for _, req := range irChReq.Requests {
		if req == nil {
			return false, errors.New("nil block certification request")
		}
		bs, err := req.Bytes()
		if err != nil {
			return false, err
		}
		if err := si.Verify(req.NodeID, func(v abcrypto.Verifier) error { return v.VerifyBytes(req.Signature, bs) }); err != nil {
			return false, err
		}
	}
	return true, nil
}

// verifyShardChanges is the state-dependent half of the aggregator validator replacements a candidate carries: each replaces
// exactly the installed configuration of an existing non-EVM shard whose last replacement is already acknowledged (its technical
// record names the epoch its input record certified). The static half (kinds, bounds, possession proofs) ran with the binding.
func verifyShardChanges(c evmassign.Candidate, states map[types.PartitionShardID]*ShardInfo, shardConfs map[types.PartitionShardID]*types.PartitionDescriptionRecord) error {
	if c.Supersedes != nil && len(c.Changes) != 0 {
		// Aggregator changes of the superseded H are already activated and never replayed; a supersession carries none.
		return fmt.Errorf("%w: a supersession carries no aggregator changes", evmassign.ErrChange)
	}
	for _, ch := range c.Changes {
		if ch.Kind != evmassign.ChangeReplaceShardValidators {
			return evmassign.ErrUnsupportedChange
		}
		r, succ, err := evmassign.DecodeReplaceShardValidators(ch.Payload)
		if err != nil {
			return err
		}
		key := types.PartitionShardID{PartitionID: succ.PartitionID, ShardID: succ.ShardID.Key()}
		si := states[key]
		if si == nil {
			return fmt.Errorf("%w: shard %s does not exist", evmassign.ErrChange, key)
		}
		if err := evmassign.VerifyChangeInstalled(evmassign.DecodedChange{Replace: r, Successor: succ}, shardConfs[key]); err != nil {
			return err
		}
		if si.TR.Epoch != si.IR.Epoch {
			return fmt.Errorf("%w: shard %s has an unacknowledged configuration", ErrAssignmentAckPending, key)
		}
	}
	return nil
}

// verifySupersession admits a replacement of the installed, unacknowledged
// assignment on the same frozen parent. The frozen shard's IR is still the
// acknowledged state P (a certified block after P would have acknowledged and
// ended the pending state), the installed assignment is the latest committed
// step, and the candidate's chain and acknowledged base equal the chain read
// from this node's committed history. No successor-set quorum is involved.
func verifySupersession(s *evmassign.Supersession, si *ShardInfo, orchestration Orchestration) error {
	if si.TR.Epoch == si.IR.Epoch {
		return errors.Join(ErrHandoffRecord, ErrSupersessionInvalid, ErrNothingToSupersede)
	}
	chain, err := CommittedChain(orchestration, si.PartitionID, si.ShardID, si.IR.Epoch)
	if err != nil || len(chain.Steps) == 0 {
		return errors.Join(ErrHandoffRecord, ErrSupersessionInvalid, err)
	}
	return verifySupersessionChain(s, si, chain)
}

func verifySupersessionChain(s *evmassign.Supersession, si *ShardInfo, chain evmassign.Chain) error {
	if si.TR.Epoch == si.IR.Epoch {
		return errors.Join(ErrHandoffRecord, ErrSupersessionInvalid, ErrNothingToSupersede)
	}
	if len(chain.Steps) == 0 {
		return errors.Join(ErrHandoffRecord, ErrSupersessionInvalid)
	}
	// The chain is folded into one acknowledgement under handoff.MaxSupersessionSpan: a supersession that would lengthen it past
	// that could be admitted here and then never acknowledged.
	if err := CheckSupersessionChainLength(len(chain.Steps)); err != nil {
		return errors.Join(ErrHandoffRecord, ErrSupersessionInvalid, err)
	}
	last := chain.Steps[len(chain.Steps)-1]
	if last.ShardEpoch != si.TR.Epoch || !bytes.Equal(last.ConfHash, si.ShardConfHash) {
		return errors.Join(ErrHandoffRecord, ErrSupersessionInvalid)
	}
	if err := evmassign.VerifyChain(s, chain); err != nil {
		return errors.Join(ErrHandoffRecord, ErrSupersessionInvalid, err)
	}
	return nil
}

// The handoff binds one certified EVM parent. Its unique shard entry remains
// identifiable by that hash while the root refuses changes to it. Other
// partitions retain their normal certification path.
// frozenEVMShard is the designated EVM shard (the only shard of the designated partition type) a prepared handoff freezes
// from its Prepare record onward, before the frozen parent is bound at Freeze. It is selected by type, never by a parent hash.
func frozenEVMShard(state ShardStates, configs map[types.PartitionShardID]*types.PartitionDescriptionRecord) (types.PartitionShardID, bool, error) {
	var selected types.PartitionShardID
	found := false
	for key, conf := range configs {
		if conf == nil || conf.PartitionTypeID != evmPartitionTypeID {
			continue
		}
		if _, live := state.States[key]; !live {
			continue
		}
		if found {
			return selected, false, ErrHandoffRecord
		}
		selected, found = key, true
	}
	// A chain without a designated EVM shard has nothing to freeze before the parent is bound.
	return selected, found, nil
}

// frozenShardOf is the shard whose certification the control state currently refuses: from Prepare the designated EVM shard,
// from Freeze the shard the bound frozen parent identifies (the same shard; the EVM IR cannot move in between). Abort returns the
// control to "aborted", which freezes nothing: one transition lifts the Prepare-time and the Freeze-time freeze alike. A Prepare-time
// freeze also lapses by itself, PrepareFreezeLapseRounds after the Prepare.
func frozenShardOf(state ShardStates, configs map[types.PartitionShardID]*types.PartitionDescriptionRecord, control *evmroot.ControlState, round uint64) (types.PartitionShardID, bool, error) {
	var zero types.PartitionShardID
	if control == nil {
		return zero, false, nil
	}
	switch control.Phase {
	case "prepared":
		if PrepareLapsed(control, round) {
			return zero, false, nil // no Freeze followed: the Prepare-time freeze has lapsed (see PrepareFreezeLapseRounds)
		}
		return frozenEVMShard(state, configs)
	case "endorsed", "committed":
		key, err := frozenShard(state, configs, control.FrozenParent)
		return key, err == nil, err
	}
	return zero, false, nil
}

func frozenShard(state ShardStates, configs map[types.PartitionShardID]*types.PartitionDescriptionRecord, parent []byte) (types.PartitionShardID, error) {
	var selected types.PartitionShardID
	found := false
	if len(parent) != 32 {
		return selected, ErrHandoffRecord
	}
	for key, shard := range state.States {
		if shard == nil || shard.IR == nil || !bytes.Equal(shard.IR.BlockHash, parent) {
			continue
		}
		// The parent hash identifies one certified EVM shard, not an
		// aggregator that happens to present the same hash.
		conf := configs[key]
		if conf == nil {
			return selected, ErrHandoffRecord
		}
		if conf.PartitionTypeID != evmPartitionTypeID {
			continue
		}
		if found {
			return selected, ErrHandoffRecord
		}
		selected, found = key, true
	}
	if !found {
		return selected, ErrHandoffRecord
	}
	return selected, nil
}

func (x *ExecutedBlock) GenerateCertificates(commitQc *rctypes.QuorumCert) ([]*certification.CertificationResponse, error) {
	crs, rootHash, err := x.ShardState.certificationResponses(x.HashAlgo)
	if err != nil {
		return nil, fmt.Errorf("failed to generate root hash: %w", err)
	}
	// sanity check, data must not have changed, hence the root hash must still be the same
	if !bytes.Equal(rootHash, x.RootHash) {
		return nil, fmt.Errorf("root hash does not match previously calculated root hash")
	}
	// sanity check, if root hashes do not match then fall back to recovery
	if !bytes.Equal(rootHash, commitQc.LedgerCommitInfo.Hash) {
		return nil, fmt.Errorf("root hash does not match hash in commit QC")
	}
	if len(crs) == 0 {
		return nil, nil
	}

	// The UC carries the signatures of the native seal. A legacy QC's signatures are those; a scheme 2 QC has two maps, and only its seal
	// signatures (the same voters' signatures over the unchanged native seal bytes) are the UC's: copying the vote signatures into a
	// seal would produce a certificate that does not verify, and none is produced from a scheme 2 QC that has no seal signatures.
	sealSignatures := commitQc.Signatures
	if commitQc.Scheme == votesig.SchemeDomainBound {
		if len(commitQc.SealSignatures) == 0 {
			return nil, fmt.Errorf("%w: scheme 2 commit QC has no seal signatures", votesig.ErrSignerSets)
		}
		sealSignatures = commitQc.SealSignatures
	}
	// create UnicitySeal for pending certificates
	uSeal := &types.UnicitySeal{
		Version:              1,
		NetworkID:            commitQc.LedgerCommitInfo.NetworkID,
		RootChainRoundNumber: commitQc.LedgerCommitInfo.RootChainRoundNumber,
		Epoch:                commitQc.LedgerCommitInfo.Epoch,
		Hash:                 commitQc.LedgerCommitInfo.Hash,
		Timestamp:            commitQc.LedgerCommitInfo.Timestamp,
		PreviousHash:         commitQc.LedgerCommitInfo.PreviousHash,
		Signatures:           sealSignatures,
	}
	for _, cr := range crs {
		cr.UC.UnicitySeal = uSeal
		x.ShardState.States[types.PartitionShardID{PartitionID: cr.Partition, ShardID: cr.Shard.Key()}].LastCR = cr
	}
	return crs, nil
}

func (x *ExecutedBlock) GetRound() uint64 {
	if x != nil {
		return x.BlockData.GetRound()
	}
	return 0
}

func (x *ExecutedBlock) GetParentRound() uint64 {
	if x != nil {
		return x.BlockData.GetParentRound()
	}
	return 0
}
