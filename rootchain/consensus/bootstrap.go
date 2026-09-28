package consensus

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/handoff"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	basetypes "github.com/unicitynetwork/bft-go-base/types"
)

type epochAnchorSafetyStore interface {
	InstallEpochAnchorSafety(*rctypes.EpochAnchor) error
	ReadEpochAnchorSafety() (*rctypes.EpochAnchor, error)
}

// InstallEpochGenesis is the local/test injection path until H4 provides
// transport. Call it before Run with a proof under the lineage-verified old
// trust base, the full native recovery checkpoint, and the successor body.
func (x *ConsensusManager) InstallEpochGenesis(proof handoff.OldCommitProof, head *abdrc.CommittedBlock, body evmroot.TrustBaseBodyV2) (*rctypes.EpochAnchor, error) {
	if x.params.NetworkProfileVersion != storage.ProfileHandoff || x.pacemaker.GetCurrentRound() != 0 {
		return nil, errors.New("epoch genesis requires stopped profile-2 consensus")
	}
	old, err := x.trustBaseStore.GetByEpoch(proof.Record.Epoch)
	if err != nil {
		return nil, fmt.Errorf("old root trust lineage: %w", err)
	}
	oldID, err := old.Hash(crypto.SHA256)
	if err != nil || !bytes.Equal(oldID, proof.Record.PredecessorBodyID) {
		return nil, errors.New("handoff predecessor differs from verified old trust base")
	}
	verified, err := handoff.VerifyOldCommitProof(proof, old)
	if err != nil {
		return nil, fmt.Errorf("old handoff commit proof: %w", err)
	}
	v := evmroot.VerifiedHandoff{RecordID: bytes.Clone(verified.RecordID[:]), Root: bytes.Clone(verified.StateRoot[:]),
		ControlDigest: bytes.Clone(verified.ControlDigest[:]), OrderRound: verified.OrderRound,
		CommitSealRound: verified.CommitSealRound, Epoch: verified.SignerEpoch, Record: proof.Record}
	g, err := evmroot.DeriveEpochGenesis(v, body)
	if err != nil {
		return nil, fmt.Errorf("derive epoch genesis: %w", err)
	}
	for _, member := range body.Members {
		if _, err := peer.Decode(member.NodeID); err != nil {
			return nil, fmt.Errorf("invalid successor node ID %q: %w", member.NodeID, err)
		}
	}
	nodes := make([]*basetypes.NodeInfo, len(body.Members))
	for i, member := range body.Members {
		nodes[i] = &basetypes.NodeInfo{NodeID: member.NodeID, SigKey: bytes.Clone(member.ConsensusKey), Stake: member.Weight}
	}
	projected, err := basetypes.NewTrustBase(old.NetworkID, nodes, basetypes.WithEpoch(g.Epoch),
		basetypes.WithEpochStart(g.Start), basetypes.WithQuorumThreshold(body.RootThreshold), basetypes.WithPreviousTrustBaseHash(oldID))
	if err != nil {
		return nil, fmt.Errorf("project successor root committee: %w", err)
	}
	projected.StateHash = bytes.Clone(body.StateSummary)
	projected.ChangeRecordHash = bytes.Clone(body.ChangeRecordHash)
	safetyStore, ok := x.blockStore.GetDB().(epochAnchorSafetyStore)
	if !ok {
		return nil, errors.New("durable epoch anchor safety store unavailable")
	}
	if existing, err := safetyStore.ReadEpochAnchorSafety(); err != nil {
		return nil, err
	} else if existing != nil && (existing.Epoch != g.Epoch || !bytes.Equal(existing.GenesisID, g.ID())) {
		return nil, rctypes.ErrEpochAnchor
	}
	a, err := x.blockStore.InstallEpochAnchor(head, v, g)
	if err != nil {
		return nil, err
	}
	newTrust, err := x.trustBaseStore.InstallV2Projection(projected)
	if err != nil {
		return nil, err
	}
	if err := safetyStore.InstallEpochAnchorSafety(a); err != nil {
		return nil, err
	}
	reqVerifier, err := NewIRChangeReqVerifier(x.params, x.blockStore)
	if err != nil {
		return nil, fmt.Errorf("successor request verifier: %w", err)
	}
	t2Timeouts, err := NewLucBasedT2TimeoutGenerator(x.params, x.blockStore)
	if err != nil {
		return nil, fmt.Errorf("successor T2 timeout generator: %w", err)
	}
	selector, err := newBootstrapLeader(x.leaderSelector, g.Start, newTrust.RootNodes)
	if err != nil {
		return nil, err
	}
	x.trustBase.Store(newTrust)
	x.leaderSelector = selector
	x.irReqVerifier = reqVerifier
	x.t2Timeouts = t2Timeouts
	x.epochAnchor = a
	return a, nil
}

func (x *ConsensusManager) matchesInstalledAnchor(a *rctypes.EpochAnchor) bool {
	return a != nil && x.epochAnchor != nil && a.Epoch == x.epochAnchor.Epoch && a.Slot == x.epochAnchor.Slot &&
		bytes.Equal(a.GenesisID, x.epochAnchor.GenesisID) && bytes.Equal(a.StateRoot, x.epochAnchor.StateRoot)
}

func (x *ConsensusManager) validateProposalParent(b *rctypes.BlockData) error {
	if b == nil {
		return errors.New("missing proposal block")
	}
	if x.epochAnchor == nil {
		if b.Anchor != nil {
			return rctypes.ErrEpochAnchor
		}
		return nil
	}
	if b.Epoch != x.epochAnchor.Epoch {
		return errors.New("proposal is outside installed epoch")
	}
	if b.Anchor != nil && !x.matchesInstalledAnchor(b.Anchor) {
		return rctypes.ErrEpochAnchor
	}
	if b.Qc != nil && (b.Qc.VoteInfo == nil || b.Qc.VoteInfo.Epoch != x.epochAnchor.Epoch) {
		return errors.New("old QC cannot parent successor proposal")
	}
	return nil
}

func (x *ConsensusManager) validateTimeoutParent(t *rctypes.Timeout) error {
	if t == nil {
		return errors.New("missing timeout")
	}
	if x.epochAnchor == nil {
		if t.Anchor != nil {
			return rctypes.ErrEpochAnchor
		}
		return nil
	}
	if t.Epoch != x.epochAnchor.Epoch {
		return errors.New("old timeout cannot advance successor pacemaker")
	}
	if t.Anchor != nil && !x.matchesInstalledAnchor(t.Anchor) {
		return rctypes.ErrEpochAnchor
	}
	if t.HighQc != nil && (t.HighQc.VoteInfo == nil || t.HighQc.VoteInfo.Epoch != x.epochAnchor.Epoch) {
		return errors.New("old timeout high QC cannot advance successor pacemaker")
	}
	return nil
}

func (x *ConsensusManager) validateTimeoutCert(tc *rctypes.TimeoutCert) error {
	if tc == nil {
		return nil
	}
	if err := x.validateTimeoutParent(tc.Timeout); err != nil {
		return err
	}
	for _, vote := range tc.Signatures {
		if vote == nil || (vote.Anchor != nil && !x.matchesInstalledAnchor(vote.Anchor)) {
			return rctypes.ErrEpochAnchor
		}
	}
	return nil
}
