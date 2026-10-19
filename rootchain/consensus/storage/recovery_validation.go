package storage

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
)

/*
Validation of the committed head of a recovery state message.

StateMsg.Verify authenticates the QCs and each UC on their own, but nothing ties the shard infos of the message to the root the QCs commit to. A
recovering node therefore, before anything is written or installed:

 1. cross-checks the round, parent and state root relationships of the block, its QC and the commit QC (the genesis head only if it is the trusted local
    genesis), against the shard tree rebuilt from the supplied input records, technical records and configuration hashes - the root the commit QC
    authenticates - and rejects duplicate, missing and unexpected shards against the local configuration (validateRecoveredHead, validateShardSet);
 2. requires every shard info to hold the invariant of an executed one: the applied configuration is the one in effect, the technical record announces
    its epoch, and its fee and statistics commitments are those of the accumulators (ShardInfo.checkAppliedConfiguration, called by newRootBlock). The
    epoch transition is the profile 3 one: the applied configuration is named by its hash alone, so a skipped scheduled epoch is as valid as the next one;
 3. binds each retained last response (UC and technical record) to the shard and to the head state; a shard without one is accepted only when its whole
    state is the initial state derived from the configuration (validateLastResponse).

No information beyond the state message and the local orchestration is used.
*/

// validateShardSet requires the shard infos of a head to be exactly the shards with validators in the configuration in effect: no duplicate, none
// missing (a peer could otherwise strip a shard and have the node refuse its requests), none unexpected (the caller has already refused those).
func validateShardSet(block *abdrc.CommittedBlock, shardConfs map[types.PartitionShardID]*types.PartitionDescriptionRecord) error {
	seen := make(map[types.PartitionShardID]struct{}, len(block.ShardInfo))
	for i := range block.ShardInfo {
		d := &block.ShardInfo[i]
		key := types.PartitionShardID{PartitionID: d.Partition, ShardID: d.Shard.Key()}
		if _, dup := seen[key]; dup {
			return fmt.Errorf("shard %s - %s is listed more than once", d.Partition, d.Shard)
		}
		seen[key] = struct{}{}
	}
	for key, conf := range shardConfs {
		if conf == nil || len(conf.Validators) == 0 {
			continue // the shard is deleted
		}
		if _, ok := seen[key]; !ok {
			return fmt.Errorf("block lacks the active shard %s - %s", conf.PartitionID, conf.ShardID)
		}
	}
	return nil
}

// validateRecoveredFields requires the operational values of a shard info that the configuration or the certified state determine to be those, never
// the peer's: the T2 timeout is the configured one and the last certified root hash is the state hash of the input record.
func validateRecoveredFields(d *abdrc.ShardInfo, conf *types.PartitionDescriptionRecord) error {
	if d.T2Timeout != conf.T2Timeout {
		return fmt.Errorf("T2 timeout %s differs from the configured %s", d.T2Timeout, conf.T2Timeout)
	}
	if !bytes.Equal(d.RootHash, d.IR.Hash) {
		return errors.New("last certified root hash differs from the state hash of the input record")
	}
	return nil
}

// validateLastResponse binds the retained last certification response of a shard info to the shard and to the head state. The response is the one
// generated when the head (or the block which last changed the shard) was committed, hence it certifies exactly the state the info holds; an older
// genuine UC of the shard is not it. A shard without a response is refused. The UC was issued under
// a configuration of the shard in effect at the UC's own root round, which can be an earlier epoch than the applied one (and not the preceding one:
// epochs can be skipped), so it is looked up there.
func validateLastResponse(d *abdrc.ShardInfo, conf *types.PartitionDescriptionRecord, orchestration Orchestration, hashAlg crypto.Hash) error {
	// every shard of a committed head has a last response - a newly activated shard gets its first one when the block of the activation is
	// committed - so it cannot be left out: a peer could otherwise strip it from a certified shard and have the node refuse the shard's requests
	if d.UC == nil || d.TR == nil {
		return errors.New("last response (UC and technical record) is required")
	}
	if d.UC.UnicityTreeCertificate == nil || d.UC.UnicityTreeCertificate.Partition != d.Partition || !d.UC.ShardTreeCertificate.Shard.Equal(d.Shard) {
		return errors.New("last response UC is of another shard")
	}
	confHash, err := conf.Hash(hashAlg)
	if err != nil {
		return fmt.Errorf("calculating PDR hash: %w", err)
	}
	if !bytes.Equal(d.UC.ShardConfHash, confHash) {
		if d.UC.UnicitySeal == nil {
			return errors.New("last response UC has no seal")
		}
		older, err := orchestration.ShardConfigs(d.UC.UnicitySeal.RootChainRoundNumber)
		if err != nil {
			return fmt.Errorf("loading shard configurations for round %d: %w", d.UC.UnicitySeal.RootChainRoundNumber, err)
		}
		pdr, ok := older[types.PartitionShardID{PartitionID: d.Partition, ShardID: d.Shard.Key()}]
		if !ok {
			return errors.New("last response UC carries a shard configuration hash which is not one of the shard's")
		}
		h, err := pdr.Hash(hashAlg)
		if err != nil || !bytes.Equal(h, d.UC.ShardConfHash) {
			return errors.New("last response UC carries a shard configuration hash which is not one of the shard's")
		}
	}
	trHash, err := d.TR.Hash()
	if err != nil {
		return fmt.Errorf("hashing the technical record of the last response: %w", err)
	}
	if !bytes.Equal(trHash, d.UC.TRHash) {
		return errors.New("technical record of the last response does not match the UC")
	}
	if eq, err := types.EqualIR(d.UC.InputRecord, d.IR); err != nil || !eq {
		return errors.New("last response UC certifies another input record than the shard info holds")
	}
	if !technicalRecordsEqual(d.TR, &d.IRTR) {
		return errors.New("technical record of the last response differs from the one of the shard info")
	}
	return nil
}

func technicalRecordsEqual(a, b *certification.TechnicalRecord) bool {
	return a.Round == b.Round && a.Epoch == b.Epoch && a.Leader == b.Leader &&
		bytes.Equal(a.StatHash, b.StatHash) && bytes.Equal(a.FeeHash, b.FeeHash)
}

// validateRecoveredHead cross-checks the block, QC and commit QC of the head with each other and with the
// reconstructed state root, which is the root the commit QC authenticates.
func validateRecoveredHead(block *abdrc.CommittedBlock, rootHash []byte, hashAlg crypto.Hash, localGenesis *ExecutedBlock) error {
	if block == nil || block.Block == nil || block.Qc == nil || block.CommitQc == nil {
		return errors.New("committed block, its QC and its commit QC are required")
	}
	if block.Qc.VoteInfo == nil || block.CommitQc.VoteInfo == nil || block.CommitQc.LedgerCommitInfo == nil {
		return errors.New("QCs without vote info or ledger commit info")
	}
	round := block.Block.Round
	if round == rctypes.GenesisRootRound {
		return validateGenesisHead(block, rootHash, hashAlg, localGenesis)
	}
	qc, cqc, info := block.Qc.VoteInfo, block.CommitQc.VoteInfo, block.CommitQc.LedgerCommitInfo
	// the QC of the block
	if qc.RoundNumber != round {
		return fmt.Errorf("QC is of round %d but the block is of round %d", qc.RoundNumber, round)
	}
	if qc.ParentRoundNumber != block.Block.GetParentRound() {
		return fmt.Errorf("QC parent round %d differs from the parent round %d of the block", qc.ParentRoundNumber, block.Block.GetParentRound())
	}
	if qc.Epoch != block.Block.Epoch || qc.Timestamp != block.Block.Timestamp {
		return errors.New("QC epoch or timestamp differ from the block's")
	}
	// the commit QC is the QC of the consecutive round which commits the block
	if cqc.ParentRoundNumber != round || cqc.RoundNumber != round+1 {
		return fmt.Errorf("commit QC is of round %d (parent %d), expected round %d committing round %d", cqc.RoundNumber, cqc.ParentRoundNumber, round+1, round)
	}
	if info.RootChainRoundNumber != round || info.Epoch != block.Block.Epoch || info.Timestamp != block.Block.Timestamp {
		return errors.New("commit info is not of the committed block")
	}
	// the state: the shard tree rebuilt from the supplied records is the authenticated one
	if !bytes.Equal(info.Hash, rootHash) {
		return fmt.Errorf("shard state root %X differs from the root %X committed by the commit QC", rootHash, info.Hash)
	}
	if !bytes.Equal(qc.CurrentRootHash, rootHash) {
		return fmt.Errorf("shard state root %X differs from the root %X of the block's QC", rootHash, qc.CurrentRootHash)
	}
	return nil
}

// trustedGenesis is the genesis block the node trusts: the one in its own storage while it is still there,
// otherwise the one every node of the network derives (NewGenesisBlock).
func trustedGenesis(db PersistentStore, hashAlg crypto.Hash, orchestration Orchestration, profile uint64) (*ExecutedBlock, error) {
	if db != nil {
		blocks, err := db.LoadBlocks()
		if err != nil {
			return nil, fmt.Errorf("reading local blocks: %w", err)
		}
		for _, b := range blocks {
			if b != nil && b.BlockData != nil && b.GetRound() == rctypes.GenesisRootRound {
				return b, nil
			}
		}
	}
	return NewGenesisBlock(orchestration.NetworkID(), hashAlg, profile)
}

// validateGenesisHead: the genesis block is the same on every node and unsigned, so a genesis head is accepted
// only if it is the trusted local genesis: same block, same state root, same commit QC. Its commit QC is either the
// self-committing genesis QC, or (once the next round has been voted) the QC of round 2 which commits it, which
// the generic commit relationships describe.
func validateGenesisHead(block *abdrc.CommittedBlock, rootHash []byte, hashAlg crypto.Hash, local *ExecutedBlock) error {
	if local == nil || local.BlockData == nil || local.CommitQc == nil || local.CommitQc.VoteInfo == nil || local.CommitQc.LedgerCommitInfo == nil {
		return errors.New("no trusted local genesis")
	}
	if !bytes.Equal(rootHash, local.RootHash) || len(block.ShardInfo) != len(local.ShardState.States) {
		return errors.New("genesis state differs from the local genesis")
	}
	want, err := local.BlockData.Hash(hashAlg)
	if err != nil {
		return err
	}
	got, err := block.Block.Hash(hashAlg)
	if err != nil {
		return fmt.Errorf("hashing the genesis block: %w", err)
	}
	if !bytes.Equal(want, got) {
		return errors.New("genesis block differs from the local genesis")
	}
	// the QC of the genesis block is unsigned: it must be the local one in full
	if local.Qc == nil || local.Qc.VoteInfo == nil || local.Qc.LedgerCommitInfo == nil {
		return errors.New("no trusted local genesis QC")
	}
	wantVi, err := local.Qc.VoteInfo.Hash(hashAlg)
	if err != nil {
		return err
	}
	gotVi, err := block.Qc.VoteInfo.Hash(hashAlg)
	if err != nil {
		return err
	}
	if !bytes.Equal(wantVi, gotVi) || block.Qc.LedgerCommitInfo == nil ||
		!bytes.Equal(block.Qc.LedgerCommitInfo.PreviousHash, local.Qc.LedgerCommitInfo.PreviousHash) ||
		!bytes.Equal(block.Qc.LedgerCommitInfo.Hash, local.Qc.LedgerCommitInfo.Hash) ||
		block.Qc.LedgerCommitInfo.RootChainRoundNumber != local.Qc.LedgerCommitInfo.RootChainRoundNumber ||
		block.Qc.LedgerCommitInfo.Epoch != local.Qc.LedgerCommitInfo.Epoch || block.Qc.LedgerCommitInfo.Timestamp != local.Qc.LedgerCommitInfo.Timestamp {
		return errors.New("genesis QC differs from the local genesis")
	}
	cqc, info := block.CommitQc.VoteInfo, block.CommitQc.LedgerCommitInfo
	if cqc.RoundNumber == rctypes.GenesisRootRound {
		// the self-committing genesis QC is a constant of the network
		wantQc, err := local.CommitQc.VoteInfo.Hash(hashAlg)
		if err != nil {
			return err
		}
		gotQc, err := cqc.Hash(hashAlg)
		if err != nil {
			return err
		}
		if !bytes.Equal(wantQc, gotQc) || !bytes.Equal(info.PreviousHash, local.CommitQc.LedgerCommitInfo.PreviousHash) || !bytes.Equal(info.Hash, rootHash) {
			return errors.New("genesis commit QC differs from the local genesis")
		}
		return nil
	}
	if cqc.ParentRoundNumber != rctypes.GenesisRootRound || cqc.RoundNumber != rctypes.GenesisRootRound+1 {
		return fmt.Errorf("commit QC of round %d (parent %d) does not commit the genesis block", cqc.RoundNumber, cqc.ParentRoundNumber)
	}
	if info.RootChainRoundNumber != rctypes.GenesisRootRound || info.Epoch != block.Block.Epoch || info.Timestamp != block.Block.Timestamp || !bytes.Equal(info.Hash, rootHash) {
		return errors.New("commit info is not of the genesis block")
	}
	return nil
}
