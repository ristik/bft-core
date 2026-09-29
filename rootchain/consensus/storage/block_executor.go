package storage

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"
	"log/slog"
	"maps"

	"github.com/unicitynetwork/bft-core/evmroot"

	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"
)

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
			return nil, fmt.Errorf("calculated shard conf hash doesn't match the value in block data for %s - %s", d.Partition, d.Shard)
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
		if err := si.resetTrustBase(shardConf); err != nil {
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
	return x.extendWithAuthority(newBlock, verifier, orchestration, hash, log, nil)
}

func (x *ExecutedBlock) extendWithAuthority(newBlock *rctypes.BlockData, verifier IRChangeReqVerifier, orchestration Orchestration, hash crypto.Hash, log *slog.Logger, authority handoffAuthority) (*ExecutedBlock, error) {
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
		parentState.Control = &evmroot.ControlState{Network: parentState.Control.Network,
			Epoch: newBlock.Epoch, PredecessorBodyID: bytes.Clone(record.NextBodyID), Phase: "idle"}
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
			if control.Phase == "endorsed" || control.Phase == "committed" {
				if _, err := frozenShard(nextShardState, control.FrozenParent); err != nil {
					return nil, err
				}
			}
			nextShardState.Control = control
		}
	} else if len(newBlock.Payload.HandoffRecords) > 0 {
		return nil, ErrNetworkProfile
	}

	for _, irChReq := range newBlock.Payload.Requests {
		if x.ShardState.Control != nil && irChReq.Partition == evmroot.D4ControlPartition {
			return nil, ErrHandoffRecord
		}
		shardKey := types.PartitionShardID{PartitionID: irChReq.Partition, ShardID: irChReq.Shard.Key()}
		if nextShardState.Control != nil && (nextShardState.Control.Phase == "endorsed" || nextShardState.Control.Phase == "committed") {
			frozen, err := frozenShard(nextShardState, nextShardState.Control.FrozenParent)
			if err != nil {
				return nil, err
			}
			if shardKey == frozen {
				return nil, ErrHandoffFrozen
			}
		}
		si, ok := nextShardState.States[shardKey]
		if !ok {
			log.Info(fmt.Sprintf("no validators in shard config (shard has been removed?) %s", shardKey))
			continue
		}

		if si.IR, err = verifier.VerifyIRChangeReq(newBlock.Round, irChReq); err != nil {
			return nil, fmt.Errorf("verifying change request: %w", err)
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

// The handoff binds one certified EVM parent. Its unique shard entry remains
// identifiable by that hash while the root refuses changes to it. Other
// partitions retain their normal certification path.
func frozenShard(state ShardStates, parent []byte) (types.PartitionShardID, error) {
	var selected types.PartitionShardID
	found := false
	if len(parent) != 32 {
		return selected, ErrHandoffRecord
	}
	for key, shard := range state.States {
		if shard == nil || shard.IR == nil || !bytes.Equal(shard.IR.BlockHash, parent) {
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

	// create UnicitySeal for pending certificates
	uSeal := &types.UnicitySeal{
		Version:              1,
		NetworkID:            commitQc.LedgerCommitInfo.NetworkID,
		RootChainRoundNumber: commitQc.LedgerCommitInfo.RootChainRoundNumber,
		Epoch:                commitQc.LedgerCommitInfo.Epoch,
		Hash:                 commitQc.LedgerCommitInfo.Hash,
		Timestamp:            commitQc.LedgerCommitInfo.Timestamp,
		PreviousHash:         commitQc.LedgerCommitInfo.PreviousHash,
		Signatures:           commitQc.Signatures,
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
