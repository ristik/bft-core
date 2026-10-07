package abdrc

import (
	"errors"
	"fmt"

	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
)

var ErrRecoveryTimestamp = errors.New("recovered timestamp differs from authenticated history")

// verifyTimestamps runs after signature verification and before recovery writes.
// It does not consult a local clock. Uncertified leaves may be replayed, but an
// incoming QC must authenticate their time before they become a live parent.
func (sm *StateMsg) verifyTimestamps() error {
	head := sm.CommittedHead
	if head.Anchor == nil {
		seal := head.CommitQc.LedgerCommitInfo
		if seal.Epoch != head.Block.Epoch || seal.RootChainRoundNumber != head.Block.Round || seal.Timestamp != head.Block.Timestamp {
			return fmt.Errorf("%w: committed head time", ErrRecoveryTimestamp)
		}
	}
	var qcs []*rctypes.QuorumCert
	if head.Anchor == nil {
		qcs = append(qcs, head.Qc, head.CommitQc, head.Block.Qc)
	} // anchor-head certificate slots are not signature-verified
	for _, block := range sm.Pending {
		if block.Qc != nil {
			qcs = append(qcs, block.Qc)
		}
	}
	blocks := append([]*rctypes.BlockData{head.Block}, sm.Pending...)
	for _, block := range blocks {
		if head.Anchor != nil && block == head.Block {
			continue
		} // locally installed checkpoint floor
		for _, qc := range qcs {
			if qc == nil || qc.VoteInfo == nil || qc.GetRound() != block.Round {
				continue
			}
			if qc.VoteInfo.Timestamp != 0 {
				if err := rctypes.VerifyTimestampProof(block, qc); err != nil {
					return fmt.Errorf("%w: %w", ErrRecoveryTimestamp, err)
				}
				continue
			}
			// Historical scheme 2 QCs omit time. Only a separately verified native
			// commit seal can authenticate that block's timestamp; never invent a floor.
			proven := false
			for _, certificate := range qcs {
				if certificate == nil || certificate.LedgerCommitInfo == nil {
					continue
				}
				seal := certificate.LedgerCommitInfo
				if seal.Epoch == block.Epoch && seal.RootChainRoundNumber == block.Round && len(seal.Hash) != 0 && seal.Timestamp == block.Timestamp {
					proven = true
					break
				}
			}
			if !proven {
				return fmt.Errorf("%w: %w: round %d", ErrRecoveryTimestamp, rctypes.ErrTimestampProof, block.Round)
			}
		}
	}
	return nil
}
