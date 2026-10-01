package consensus

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"fmt"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/handoff"
	"github.com/unicitynetwork/bft-core/handoffdelivery"
	"github.com/unicitynetwork/bft-core/m2contract"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/trusthistorystore"
	basetypes "github.com/unicitynetwork/bft-go-base/types"
)

type epochAnchorSafetyStore interface {
	ReadEpochAnchorSafety() (*rctypes.EpochAnchor, error)
}

// InstalledRootEpoch is the epoch selected by the verified local root lineage.
func (x *ConsensusManager) InstalledRootEpoch() uint64 {
	return x.trustBase.Load().Epoch
}

// InstallEpochGenesis is the local/test injection path until H4 provides
// transport. Call it before Run with a proof under the lineage-verified old
// trust base, the full native recovery checkpoint, and the successor body.
func (x *ConsensusManager) InstallEpochGenesis(proof handoff.OldCommitProof, head *abdrc.CommittedBlock, body evmroot.TrustBaseBodyV2) (*rctypes.EpochAnchor, error) {
	return x.InstallEpochBundle(handoffdelivery.Bundle{Proof: proof, Body: body, Snapshot: head})
}

// InstallEpochBundle installs a verified handoff bundle, including the H3 EVM
// assignment candidate it carries: the candidate is retained, the successor
// configuration is derived from it and checked against the committed record, and
// only then is the anchor installed.
func (x *ConsensusManager) InstallEpochBundle(incoming handoffdelivery.Bundle) (*rctypes.EpochAnchor, error) {
	proof, head, body, candidate := incoming.Proof, incoming.Snapshot, incoming.Body, incoming.Candidate
	if x.params.NetworkProfileVersion != storage.ProfileHandoff || x.pacemaker.GetCurrentRound() != 0 {
		return nil, errors.New("epoch genesis requires stopped profile-2 consensus")
	}
	if !x.recoveryProfile2 || x.recoveryHistory == nil {
		return nil, fmt.Errorf("epoch genesis requires profile 2 recovery: %w", abdrc.ErrRecoveryEpoch)
	}
	old, err := x.trustBaseStore.GetByEpoch(proof.Record.Epoch)
	if err != nil {
		return nil, fmt.Errorf("old root trust lineage: %w", err)
	}
	prior, err := x.recoveryHistory.ByEpoch(proof.Record.Epoch)
	if err != nil {
		return nil, fmt.Errorf("old root trust lineage: %w", err)
	}
	var predecessor []byte
	if prior.V1 != nil {
		predecessor, err = old.Hash(crypto.SHA256)
	} else if prior.V2 != nil {
		predecessor = prior.BodyID[:]
	} else {
		return nil, errors.New("handoff predecessor has no verified trust body")
	}
	if err != nil || !bytes.Equal(predecessor, proof.Record.PredecessorBodyID) {
		return nil, errors.New("handoff predecessor differs from verified old trust base")
	}
	oldID, err := old.Hash(crypto.SHA256)
	if err != nil {
		return nil, err
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
	bodyID := body.Identity()
	interval := m2contract.TrustInterval{Body: body, Activation: evmroot.ActivatedTrustBase{
		BodyIdentity: bodyID[:], EpochStart: g.Start, ActivationCommitID: bytes.Clone(verified.RecordID[:])}}
	bundle := handoffdelivery.Bundle{Proof: proof, Body: body, Snapshot: head, Candidate: bytes.Clone(candidate)}
	if head == nil || len(head.ShardInfo) == 0 {
		return nil, errors.New("handoff snapshot has no shards")
	}
	first := head.ShardInfo[0]
	if _, err := handoffdelivery.Verify(bundle, old, first.Partition, first.Shard, first.ShardConfHash); err != nil {
		return nil, err
	}
	if archive, ok := x.blockStore.GetDB().(handoffBundleArchive); ok {
		if err := retainEquivalentHandoffBundle(archive, g.Epoch, bundle, old, g.ID()); err != nil {
			return nil, err
		}
	}
	safetyStore, ok := x.blockStore.GetDB().(epochAnchorSafetyStore)
	if !ok {
		return nil, errors.New("durable epoch anchor safety store unavailable")
	}
	if existing, err := safetyStore.ReadEpochAnchorSafety(); err != nil {
		return nil, err
	} else if existing != nil && existing.Epoch >= g.Epoch && (existing.Epoch != g.Epoch || !bytes.Equal(existing.GenesisID, g.ID())) {
		return nil, rctypes.ErrEpochAnchor
	}
	proofBytes, err := basetypes.Cbor.Marshal(proof)
	if err != nil {
		return nil, err
	}
	if err = x.recoveryHistory.AppendVerified(context.Background(), interval, proofBytes); err != nil {
		if !errors.Is(err, trusthistorystore.ErrAlreadyExists) {
			return nil, fmt.Errorf("persist verified successor lineage: %w", err)
		}
		stored, lookupErr := x.recoveryHistory.ByEpoch(g.Epoch)
		if lookupErr != nil || stored.V2 == nil || stored.BodyID != bodyID || stored.Start != g.Start {
			return nil, fmt.Errorf("successor lineage differs from installed body: %w", err)
		}
	}
	newTrust, err := x.trustBaseStore.InstallV2Projection(projected)
	if err != nil {
		return nil, err
	}
	if err := x.blockStore.RetainHandoffArtifacts(bodyID[:], body.Encode(), candidate); err != nil {
		return nil, fmt.Errorf("retain handoff candidate: %w", err)
	}
	a, err := x.blockStore.InstallEpochAnchor(head, v, g)
	if err != nil {
		return nil, err
	}
	installed, err := x.recoveryHistory.ByEpoch(g.Epoch)
	if err != nil {
		return nil, err
	}
	if err := x.blockStore.ConfigureHandoffV2Authority(newTrust, installed); err != nil {
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
	x.handoffMu.Lock()
	x.handoffPlans = nil
	x.handoffAborts = nil
	x.handoffMu.Unlock()
	x.leaderSelector = selector
	x.irReqVerifier = reqVerifier
	x.t2Timeouts = t2Timeouts
	x.epochAnchor = a
	return a, nil
}

type handoffBundleArchive interface {
	HandoffBundle(uint64) ([]byte, error)
	StoreHandoffBundle(uint64, []byte) error
}

// A later empty old-epoch suffix can produce another valid commit QC for H.
// Both bundles derive the same genesis; retain the first served bundle so a
// shard that fetched it and a root that installs a later suffix agree.
func retainEquivalentHandoffBundle(archive handoffBundleArchive, epoch uint64, incoming handoffdelivery.Bundle,
	old *basetypes.RootTrustBaseV1, genesisID []byte) error {
	existing, err := archive.HandoffBundle(epoch)
	if err != nil {
		return err
	}
	if len(existing) != 0 {
		stored, err := handoffdelivery.DecodeBundle(existing)
		if err != nil {
			return handoffdelivery.ErrBundle
		}
		if stored.Snapshot == nil || len(stored.Snapshot.ShardInfo) == 0 {
			return handoffdelivery.ErrBundle
		}
		first := stored.Snapshot.ShardInfo[0]
		verified, err := handoffdelivery.Verify(stored, old, first.Partition, first.Shard, first.ShardConfHash)
		if err != nil || stored.Body.Epoch != epoch || !bytes.Equal(verified.Genesis.ID(), genesisID) {
			return handoffdelivery.ErrBundle
		}
		return nil
	}
	encoded, err := handoffdelivery.EncodeBundle(incoming)
	if err != nil {
		return err
	}
	return archive.StoreHandoffBundle(epoch, encoded)
}

// InstalledEVMTransition derives the one acknowledgement payload from the
// signed old control state and this manager's durable installed anchor.
func (x *ConsensusManager) InstalledEVMTransition(proof handoff.OldCommitProof,
	body evmroot.TrustBaseBodyV2) ([]byte, error) {
	if x.params.NetworkProfileVersion != storage.ProfileHandoff || x.epochAnchor == nil {
		return nil, rctypes.ErrEpochAnchor
	}
	if err := x.blockStore.AnchoredFrozenParent(proof.Record.SuccessorTRHash, proof.Control.FrozenParent); err != nil {
		return nil, err
	}
	old, err := x.trustBaseStore.GetByEpoch(proof.Record.Epoch)
	if err != nil {
		return nil, fmt.Errorf("old root trust lineage: %w", err)
	}
	successorTR, err := x.blockStore.AnchoredTechnicalRecord(proof.Record.SuccessorTRHash)
	if err != nil {
		return nil, fmt.Errorf("verified successor shard assignment: %w", err)
	}
	step, err := x.blockStore.AnchoredAssignmentStep(proof.Record)
	if err != nil {
		return nil, err
	}
	transition, err := handoff.TransitionFromInstalledAnchor(proof, old, body, x.epochAnchor, successorTR, step)
	if err != nil {
		return nil, err
	}
	return transition.Encode()
}

// HandoffBundle serves a finalized bundle from durable archive, or assembles
// it from the current committed old tip while activation is still pending.
func (x *ConsensusManager) HandoffBundle(_ context.Context, epoch uint64) (*handoffdelivery.Bundle, error) {
	if x.params.NetworkProfileVersion != storage.ProfileHandoff || epoch < 2 {
		return nil, rctypes.ErrEpochAnchor
	}
	archive, ok := x.blockStore.GetDB().(handoffBundleArchive)
	if ok {
		raw, err := archive.HandoffBundle(epoch)
		if err != nil {
			return nil, err
		}
		if len(raw) != 0 {
			bundle, err := handoffdelivery.DecodeBundle(raw)
			if err != nil {
				return nil, err
			}
			if bundle.Body.Epoch != epoch || bundle.Proof.Record.Epoch+1 != epoch {
				return nil, handoffdelivery.ErrBundle
			}
			if bundle.Snapshot == nil || len(bundle.Snapshot.ShardInfo) == 0 {
				return nil, handoffdelivery.ErrBundle
			}
			old, err := x.trustBaseStore.GetByEpoch(bundle.Proof.Record.Epoch)
			if err != nil {
				return nil, handoffdelivery.ErrBundle
			}
			first := bundle.Snapshot.ShardInfo[0]
			if _, err := handoffdelivery.Verify(bundle, old, first.Partition, first.Shard, first.ShardConfHash); err != nil {
				return nil, err
			}
			return &bundle, nil
		}
	}
	head, path, record, err := x.blockStore.HandoffCheckpoint()
	if err != nil || record.Epoch+1 != epoch {
		return nil, handoffdelivery.ErrBundle
	}
	rawBody, err := x.blockStore.HandoffBody(record.NextBodyID)
	if err != nil {
		return nil, err
	}
	body, err := storage.DecodeHandoffBody(rawBody)
	if err != nil {
		return nil, err
	}
	candidate, err := x.blockStore.HandoffCandidate(record.NextBodyID)
	if err != nil {
		return nil, err
	}
	bundle := handoffdelivery.Bundle{Proof: handoff.OldCommitProof{Profile: evmroot.D4Profile,
		Record: record, Control: *head.Control, ControlPath: path, CommitQC: head.CommitQc}, Body: body, Snapshot: head,
		Candidate: candidate}
	old, err := x.trustBaseStore.GetByEpoch(record.Epoch)
	if err != nil || len(head.ShardInfo) == 0 {
		return nil, handoffdelivery.ErrBundle
	}
	first := head.ShardInfo[0]
	if _, err := handoffdelivery.Verify(bundle, old, first.Partition, first.Shard, first.ShardConfHash); err != nil {
		return nil, err
	}
	if ok {
		verified, err := handoffdelivery.Verify(bundle, old, first.Partition, first.Shard, first.ShardConfHash)
		if err != nil {
			return nil, err
		}
		if err := retainEquivalentHandoffBundle(archive, epoch, bundle, old, verified.Genesis.ID()); err != nil {
			return nil, err
		}
	}
	return &bundle, nil
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

// reconcileAssignmentHistory re-derives every committed EVM assignment the
// durable bundle archive holds and makes the orchestration's derived index match
// it. The install is idempotent, so a crash between committed storage and the
// derived write is repaired here; an existing conflicting entry is corruption
// and refuses startup. Epochs without a retained bundle derive nothing, and the
// block tree's own check refuses any stored block whose configuration is not the
// derived one.
func reconcileAssignmentHistory(db any, trust *trustbase.TrustBaseStore, orchestration Orchestration) error {
	archive, ok := db.(handoffBundleArchive)
	installer, installOK := orchestration.(storage.DerivedConfigInstaller)
	if !ok || !installOK {
		return nil
	}
	last, err := trust.LoadLast()
	if err != nil || last == nil {
		return nil
	}
	for epoch := uint64(2); epoch <= last.Epoch; epoch++ {
		raw, err := archive.HandoffBundle(epoch)
		if err != nil {
			return err
		}
		if len(raw) == 0 {
			continue
		}
		bundle, err := handoffdelivery.DecodeBundle(raw)
		if err != nil {
			return err
		}
		if len(bundle.Candidate) == 0 {
			continue
		}
		old, err := trust.GetByEpoch(bundle.Proof.Record.Epoch)
		if err != nil || bundle.Snapshot == nil || len(bundle.Snapshot.ShardInfo) == 0 {
			return fmt.Errorf("%w: epoch %d: old trust base unavailable", storage.ErrAssignmentHistory, epoch)
		}
		first := bundle.Snapshot.ShardInfo[0]
		if _, err := handoffdelivery.Verify(bundle, old, first.Partition, first.Shard, first.ShardConfHash); err != nil {
			return fmt.Errorf("%w: epoch %d: %w", storage.ErrAssignmentHistory, epoch, err)
		}
		pdr, provenance, err := storage.DeriveActivatedPDR(bundle.Proof.Record, bundle.Body, bundle.Candidate, bundle.Proof.Control.FrozenParent)
		if err != nil {
			return fmt.Errorf("epoch %d: %w", epoch, err)
		}
		if err := installer.InstallDerivedShardConfig(pdr, provenance); err != nil {
			return fmt.Errorf("epoch %d: %w", epoch, err)
		}
	}
	return nil
}
