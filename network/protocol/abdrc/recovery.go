package abdrc

import (
	"crypto"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/trusthistorystore"
)

var (
	ErrHistoricalTrustBase = errors.New("historical trust base unavailable or unverified")
	ErrHistoricalUC        = errors.New("historical certificate invalid")
	ErrRecoveryEpoch       = errors.New("pending consensus recovery crosses epoch")
)

// HistoricalTrustBases returns only lineage-verified epoch bodies.
type HistoricalTrustBases interface {
	ByEpoch(epoch uint64) (trusthistorystore.Record, error)
}

type StateRequestMsg struct {
	_ struct{} `cbor:",toarray"`
	// ID of the node which requested the state, ie response should
	// be sent to that node
	NodeId string
}

type CommittedBlock struct {
	_         struct{} `cbor:",toarray"`
	Block     *rctypes.BlockData
	ShardInfo []ShardInfo
	Qc        *rctypes.QuorumCert   // block's quorum certificate (from next view)
	CommitQc  *rctypes.QuorumCert   // commit certificate
	Control   *evmroot.ControlState // version 2 checkpoint control leaf
	Anchor    *rctypes.EpochAnchor  // verified, noncommittable successor root
}

func (r CommittedBlock) MarshalCBOR() ([]byte, error) {
	if r.Anchor != nil {
		return types.Cbor.Marshal([]any{uint64(3), r.Block, r.ShardInfo, r.Qc, r.CommitQc, r.Control, r.Anchor})
	}
	if r.Control == nil {
		return types.Cbor.Marshal([]any{r.Block, r.ShardInfo, r.Qc, r.CommitQc})
	}
	return types.Cbor.Marshal([]any{uint64(2), r.Block, r.ShardInfo, r.Qc, r.CommitQc, r.Control})
}

func (r *CommittedBlock) UnmarshalCBOR(data []byte) error {
	var v3 struct {
		_         struct{} `cbor:",toarray"`
		Version   uint64
		Block     *rctypes.BlockData
		ShardInfo []ShardInfo
		Qc        *rctypes.QuorumCert
		CommitQc  *rctypes.QuorumCert
		Control   *evmroot.ControlState
		Anchor    *rctypes.EpochAnchor
	}
	if err := types.Cbor.Unmarshal(data, &v3); err == nil {
		if v3.Version != 3 || v3.Control == nil || v3.Anchor == nil {
			return errors.New("invalid anchor checkpoint")
		}
		*r = CommittedBlock{Block: v3.Block, ShardInfo: v3.ShardInfo, Qc: v3.Qc, CommitQc: v3.CommitQc, Control: v3.Control, Anchor: v3.Anchor}
		return nil
	}
	var v2 struct {
		_         struct{} `cbor:",toarray"`
		Version   uint64
		Block     *rctypes.BlockData
		ShardInfo []ShardInfo
		Qc        *rctypes.QuorumCert
		CommitQc  *rctypes.QuorumCert
		Control   *evmroot.ControlState
	}
	if err := types.Cbor.Unmarshal(data, &v2); err == nil {
		if v2.Version != 2 || v2.Control == nil {
			return errors.New("invalid control checkpoint")
		}
		*r = CommittedBlock{Block: v2.Block, ShardInfo: v2.ShardInfo, Qc: v2.Qc, CommitQc: v2.CommitQc, Control: v2.Control}
		return nil
	}
	var v1 struct {
		_         struct{} `cbor:",toarray"`
		Block     *rctypes.BlockData
		ShardInfo []ShardInfo
		Qc        *rctypes.QuorumCert
		CommitQc  *rctypes.QuorumCert
	}
	if err := types.Cbor.Unmarshal(data, &v1); err != nil {
		return err
	}
	*r = CommittedBlock{Block: v1.Block, ShardInfo: v1.ShardInfo, Qc: v1.Qc, CommitQc: v1.CommitQc}
	return nil
}

type ShardInfo struct {
	_         struct{} `cbor:",toarray"`
	Partition types.PartitionID
	Shard     types.ShardID
	T2Timeout time.Duration
	RootHash  []byte // last certified root hash

	// statistical record of the previous epoch. As we only need
	// it for hashing we keep it in serialized representation
	PrevEpochStat []byte

	// statistical record of the current epoch
	Stat certification.StatisticalRecord

	// per validator total, invariant fees of the previous epoch
	// but as with statistical record of the previous epoch we need it
	// for hashing so we keep it in serialized representation
	PrevEpochFees []byte

	Fees map[string]uint64 // per validator summary fees of the current epoch

	// last CertificationResponse
	UC *types.UnicityCertificate
	TR *certification.TechnicalRecord

	// input data of the block
	IR            *types.InputRecord
	IRTR          certification.TechnicalRecord
	ShardConfHash []byte
}

type StateMsg struct {
	_             struct{} `cbor:",toarray"`
	CommittedHead *CommittedBlock
	Pending       []*rctypes.BlockData
}

// RecoveryAnchorVerifier checks an anchor against a locally installed,
// proof-verified genesis and reconstructs its native checkpoint tree.
type RecoveryAnchorVerifier interface {
	VerifyRecoveryAnchor(*CommittedBlock) error
}

/*
CanRecoverToRound returns non-nil error when the state message is not suitable for recovery into round "round".
*/
func (sm *StateMsg) CanRecoverToRound(round uint64) error {
	if sm.CommittedHead == nil {
		return fmt.Errorf("committed block is nil")
	}
	if round < sm.CommittedHead.Block.GetRound() {
		return fmt.Errorf("can't recover to round %d with committed block for round %d", round, sm.CommittedHead.Block.GetRound())
	}
	// commit head matches recover round
	if round == sm.CommittedHead.Block.GetRound() {
		return nil
	}
	if !slices.ContainsFunc(sm.Pending, func(b *rctypes.BlockData) bool { return b.GetRound() == round }) {
		return fmt.Errorf("state has no data block for round %d", round)
	}

	return nil
}

func (sm *StateMsg) Verify(hashAlgorithm crypto.Hash, tb types.RootTrustBase) error {
	return sm.verify(hashAlgorithm, tb, nil, nil)
}

// VerifyWithHistory verifies inherited LastCRs under their own signer epochs.
// Consensus certificates remain on the current, same-epoch recovery path.
func (sm *StateMsg) VerifyWithHistory(hashAlgorithm crypto.Hash, tb types.RootTrustBase, history HistoricalTrustBases) error {
	if history == nil {
		return ErrHistoricalTrustBase
	}
	return sm.verify(hashAlgorithm, tb, history, nil)
}

// VerifyWithAnchor is the profile-2 recovery path after local proof and
// snapshot installation. Ordinary recovery remains on VerifyWithHistory.
func (sm *StateMsg) VerifyWithAnchor(hashAlgorithm crypto.Hash, tb types.RootTrustBase, history HistoricalTrustBases, anchor RecoveryAnchorVerifier) error {
	if history == nil || anchor == nil {
		return ErrHistoricalTrustBase
	}
	return sm.verify(hashAlgorithm, tb, history, anchor)
}

func (sm *StateMsg) verify(hashAlgorithm crypto.Hash, tb types.RootTrustBase, history HistoricalTrustBases, anchor RecoveryAnchorVerifier) error {
	if sm.CommittedHead == nil {
		return fmt.Errorf("commit head is nil")
	}
	if err := sm.CommittedHead.IsValid(); err != nil {
		return fmt.Errorf("invalid commit head: %w", err)
	}
	anchorHead := sm.CommittedHead.Anchor != nil
	if anchorHead {
		if history == nil || anchor == nil {
			return ErrRecoveryEpoch
		}
		if err := anchor.VerifyRecoveryAnchor(sm.CommittedHead); err != nil {
			return fmt.Errorf("invalid recovery anchor: %w", err)
		}
	}
	if history != nil {
		epoch := tb.GetEpoch()
		if sm.CommittedHead.Block.Epoch != epoch ||
			(!anchorHead && (!recoveryQCEpoch(sm.CommittedHead.Block.Qc, epoch) ||
				!recoveryQCEpoch(sm.CommittedHead.Qc, epoch) ||
				!recoveryQCEpoch(sm.CommittedHead.CommitQc, epoch))) {
			return ErrRecoveryEpoch
		}
		for _, block := range sm.Pending {
			if block == nil || block.Epoch != epoch || (block.Anchor == nil && !recoveryQCEpoch(block.Qc, epoch)) ||
				(block.Anchor != nil && (!anchorHead || block.Anchor.Epoch != sm.CommittedHead.Anchor.Epoch ||
					block.Anchor.Slot != sm.CommittedHead.Anchor.Slot ||
					!slices.Equal(block.Anchor.GenesisID, sm.CommittedHead.Anchor.GenesisID) ||
					!slices.Equal(block.Anchor.StateRoot, sm.CommittedHead.Anchor.StateRoot))) {
				return ErrRecoveryEpoch
			}
		}
	}
	// Block from genesis round does not have a Qc
	if !anchorHead && sm.CommittedHead.GetRound() > rctypes.GenesisRootRound {
		if err := sm.CommittedHead.Block.Qc.Verify(tb); err != nil {
			return fmt.Errorf("block qc verification error: %w", err)
		}
	}
	if !anchorHead {
		if err := sm.CommittedHead.Qc.Verify(tb); err != nil {
			return fmt.Errorf("qc verification error: %w", err)
		}
		if err := sm.CommittedHead.CommitQc.Verify(tb); err != nil {
			return fmt.Errorf("commit qc verification error: %w", err)
		}
	}
	// verify node blocks
	for _, n := range sm.Pending {
		if err := n.IsValid(); err != nil {
			return fmt.Errorf("invalid block node: %w", err)
		}
		if n.Qc != nil {
			if err := n.Qc.Verify(tb); err != nil {
				return fmt.Errorf("block node qc verification error: %w", err)
			}
		}
	}
	for _, c := range sm.CommittedHead.ShardInfo {
		ucTrust := tb
		if history != nil {
			// IsValid above permits absent LastCRs; there is no UC to verify in that case.
			if c.UC == nil {
				continue
			}
			historical, err := history.ByEpoch(c.UC.GetRootEpoch())
			if err != nil {
				return fmt.Errorf("%w for epoch %d: %w", ErrHistoricalTrustBase, c.UC.GetRootEpoch(), err)
			}
			if historical.Epoch != c.UC.GetRootEpoch() {
				return fmt.Errorf("%w for epoch %d: returned epoch %d", ErrHistoricalTrustBase, c.UC.GetRootEpoch(), historical.Epoch)
			}
			if historical.V1 != nil && historical.V2 == nil {
				ucTrust = historical.V1
			} else if historical.V2 != nil && historical.V1 == nil {
				ucTrust, err = v2UCTrustBase(historical)
				if err != nil {
					return fmt.Errorf("%w for epoch %d: %w", ErrHistoricalTrustBase, historical.Epoch, err)
				}
			} else {
				return fmt.Errorf("%w for epoch %d: invalid body variant", ErrHistoricalTrustBase, historical.Epoch)
			}
		}
		if err := verifyRecoveryUC(c, ucTrust, hashAlgorithm, history != nil); err != nil {
			if history != nil {
				return fmt.Errorf("%w for %s-%s: %w", ErrHistoricalUC, c.Partition, c.Shard, err)
			}
			return fmt.Errorf("certificate for %s is invalid: %w", c.UC.UnicityTreeCertificate.Partition, err)
		}
	}
	return nil
}

func verifyRecoveryUC(c ShardInfo, trust types.RootTrustBase, hashAlgorithm crypto.Hash, historical bool) error {
	partition, shard, conf := c.UC.GetPartitionID(), c.UC.GetShardID(), []byte(nil)
	if historical {
		partition, shard, conf = c.Partition, c.Shard, c.ShardConfHash
	}
	return c.UC.Verify(trust, hashAlgorithm, partition, shard, conf)
}

// v2UCTrustBase adapts an authenticated WP1 body to the legacy UC signature
// verifier. The synthetic value is used only to verify historical seal bytes;
// it is never installed as a current consensus or consumer trust base.
func v2UCTrustBase(record trusthistorystore.Record) (*types.RootTrustBaseV1, error) {
	body := record.V2
	if body == nil || body.Epoch != record.Epoch {
		return nil, errors.New("invalid v2 body")
	}
	if err := body.Validate(); err != nil {
		return nil, fmt.Errorf("invalid v2 body: %w", err)
	}
	if body.Identity() != record.BodyID {
		return nil, errors.New("v2 body identity mismatch")
	}
	nodes := make([]*types.NodeInfo, 0, len(body.Members))
	for _, member := range body.Members {
		nodes = append(nodes, &types.NodeInfo{NodeID: member.NodeID, SigKey: member.ConsensusKey, Stake: member.Weight})
	}
	return types.NewTrustBase(types.NetworkID(body.NetworkID), nodes,
		types.WithEpoch(body.Epoch), types.WithEpochStart(record.Start), types.WithQuorumThreshold(body.RootThreshold))
}

// recoveryQCEpoch reports whether a QC of recovery state belongs to the receiver's epoch. The epoch of what the QC votes for is always
// required. The epoch of what it commits is required whenever it commits something; a QC that commits nothing carries the empty seal
// (isEmptyCommitInfo) and has no committed block that could cross an epoch. QuorumCert.Verify binds the vote info, and so its epoch, to the
// signed commit info, so skipping the commit epoch for the empty seal accepts nothing that names an old-epoch block.
func recoveryQCEpoch(qc *rctypes.QuorumCert, epoch uint64) bool {
	return qc == nil || (qc.VoteInfo != nil && qc.LedgerCommitInfo != nil &&
		qc.VoteInfo.Epoch == epoch && (isEmptyCommitInfo(qc.LedgerCommitInfo) || qc.LedgerCommitInfo.Epoch == epoch))
}

// isEmptyCommitInfo is the commit info of a QC that commits nothing, exactly as SafetyModule.constructCommitInfo builds it: a seal that
// names no committed block (epoch 0, root round 0, no hash) and no network or time. Every other field of the seal that identifies a
// commit is zero; matching only the epoch would let a seal that names a round or a root hash skip the epoch check.
func isEmptyCommitInfo(seal *types.UnicitySeal) bool {
	return seal != nil && seal.Epoch == 0 && seal.RootChainRoundNumber == 0 && len(seal.Hash) == 0 &&
		seal.NetworkID == 0 && seal.Timestamp == 0
}

func (r *CommittedBlock) GetRound() uint64 {
	if r != nil {
		return r.Block.GetRound()
	}
	return 0
}

func (r *CommittedBlock) IsValid() error {
	if r == nil || r.Block == nil {
		return errors.New("block data is nil")
	}
	if (r.Block.GetVersion() == 2) != (r.Control != nil) {
		return errors.New("missing or unexpected control checkpoint")
	}
	if r.Anchor != nil {
		if err := r.Anchor.IsValid(); err != nil {
			return err
		}
		if r.Block.Version != 2 || r.Block.Payload == nil || !r.Block.Payload.IsEmpty() ||
			r.Block.Payload.Version != 2 || r.Block.Anchor == nil || r.Block.Qc != nil ||
			r.Block.Round != r.Anchor.Slot || r.Block.Epoch != r.Anchor.Epoch ||
			!slices.Equal(r.Block.Anchor.GenesisID, r.Anchor.GenesisID) || !slices.Equal(r.Block.Anchor.StateRoot, r.Anchor.StateRoot) ||
			r.Block.Anchor.Slot != r.Anchor.Slot || r.Block.Anchor.Epoch != r.Anchor.Epoch ||
			r.Qc != nil || r.CommitQc != nil || r.Control == nil || r.Control.Epoch+1 != r.Anchor.Epoch {
			return ErrRecoveryEpoch
		}
	}
	if r.Control != nil {
		if (r.Anchor == nil && r.Control.Epoch != r.Block.Epoch) || r.Control.Network == 0 || len(r.Control.PredecessorBodyID) != 32 {
			return errors.New("invalid control checkpoint")
		}
	}
	for _, si := range r.ShardInfo {
		if r.Control != nil && si.Partition == evmroot.D4ControlPartition {
			return errors.New("control partition cannot be shard info")
		}
		if err := si.IsValid(); err != nil {
			return fmt.Errorf("invalid ShardInfo[%s - %s]: %w", si.Partition, si.Shard, err)
		}
	}
	if r.Block == nil {
		return fmt.Errorf("block data is nil")
	}
	if r.Anchor == nil {
		if err := r.Block.IsValid(); err != nil {
			return fmt.Errorf("invalid block data: %w", err)
		}
	}
	if r.Anchor != nil {
		return nil
	}

	if r.Qc == nil {
		return errors.New("commit head is missing qc certificate")
	}
	if r.CommitQc == nil {
		return errors.New("commit head is missing commit qc certificate")
	}
	return nil
}

func (si *ShardInfo) IsValid() error {
	if si.Partition == 0 {
		return errors.New("missing partition id")
	}
	if len(si.PrevEpochStat) == 0 {
		return errors.New("missing PrevEpochStat")
	}
	if len(si.PrevEpochFees) == 0 {
		return errors.New("missing PrevEpochFees")
	}
	if len(si.Fees) == 0 {
		return errors.New("missing Fees")
	}

	if err := si.IR.IsValid(); err != nil {
		return fmt.Errorf("invalid input record: %w", err)
	}
	if len(si.ShardConfHash) == 0 {
		return errors.New("shard conf hash not set")
	}

	if si.UC != nil {
		if err := si.UC.IsValid(si.Partition, si.Shard, si.ShardConfHash); err != nil {
			return fmt.Errorf("invalid UC: %w", err)
		}
		if err := si.TR.IsValid(); err != nil {
			return fmt.Errorf("invalid TR of CertificationResponse: %w", err)
		}
	}

	return nil
}
