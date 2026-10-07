package consensus

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-core/handoff"
	"github.com/unicitynetwork/bft-core/handoffdelivery"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/q3format"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
	basetypes "github.com/unicitynetwork/bft-go-base/types"
)

var (
	// ErrNotVerifiedEpoch is returned when an epoch is installed from an entry that is not a verified V3 activation: a legacy entry,
	// a zero entry, or one whose activation record the history did not mint.
	ErrNotVerifiedEpoch = errors.New("epoch is not a verified Q3 activation")
	// ErrNotStopped is returned when an epoch is installed into a manager that is not the stopped profile-2 consensus the install
	// requires.
	ErrNotStopped = errors.New("epoch genesis requires stopped profile-2 consensus")
	// ErrQ3Candidate is returned for a V3 install whose candidate is not the one the committed record binds: a root-only record
	// installed with an assignment, an assignment record installed without or with another one, or a candidate that does not derive
	// the weighted coupled assignment the verified entry activates.
	ErrQ3Candidate = errors.New("the Q3 install's candidate is not the committed one")
	// ErrNoCheckpoint is returned for a V3 install whose handoff snapshot is absent or holds no shards: there is no committed
	// checkpoint to verify or to anchor the epoch on.
	ErrNoCheckpoint = errors.New("handoff snapshot is not a checkpoint")
)

// InstallVerifiedEpoch installs the first epoch of a Q3 activation. Every fact it installs (the epoch, its weights and threshold,
// the activation boundary, the anchor identity and the signing configuration) is taken from the verified history's entry, never
// from the proof, the snapshot or the caller: the proof and the native snapshot are only re-authenticated against that entry. The
// old epoch's commit is verified once more under its own epoch's scheme and keys, because the installer must not depend on
// what any other component checked.
//
// It is the V3 counterpart of InstallEpochBundle for a root-only handoff, with the same stopped-consensus precondition. It does
// not append to the V1/V2 recovery history (that store holds no V3 body); the durable record is the Q3 history the caller retains,
// and the trust-base store accepts the projection only for a configuration the bound history holds (InstallVerified).
func (x *ConsensusManager) InstallVerifiedEpoch(entry q3format.Entry, proof handoff.OldCommitProof, head *abdrc.CommittedBlock, candidate []byte) (*rctypes.EpochAnchor, error) {
	if x.params.NetworkProfileVersion != storage.ProfileHandoff {
		return nil, fmt.Errorf("%w: not the handoff profile", ErrNotStopped)
	}
	if x.pacemaker.GetCurrentRound() != 0 {
		return nil, fmt.Errorf("%w: consensus is running", ErrNotStopped)
	}
	v, g, ok := entry.Handoff()
	if !ok {
		return nil, ErrNotVerifiedEpoch
	}
	cfg, _ := entry.Config() // an entry with a handoff is an activation: it has its tuple
	switch {
	case len(candidate) == 0 && !entry.RootOnly(): // the committed candidate is an assignment: omitting its preimage must not turn it into a root-only install
		return nil, fmt.Errorf("%w: the committed candidate is not the root-only operator candidate", ErrQ3Candidate)
	case len(candidate) != 0 && entry.RootOnly():
		return nil, fmt.Errorf("%w: the committed candidate is the root-only operator candidate", ErrQ3Candidate)
	case len(candidate) != 0:
		// the whole chain record <- body <- change-record hash <- candidate digest <- preimage, the entry's own committee and the
		// mirrored coupling, under the weighted rules: nothing about the candidate is taken from the caller
		// (the version only labels the activation built to check)
		if _, err := storage.ActivationFromVerifiedV3(entry, v.Record, candidate, x.params.HashAlgorithm, 1); err != nil {
			return nil, errors.Join(ErrQ3Candidate, err)
		}
	}
	if head == nil || len(head.ShardInfo) == 0 {
		return nil, fmt.Errorf("%w: no shards", ErrNoCheckpoint)
	}
	old, err := x.trustBaseStore.GetByEpoch(v.Epoch)
	if err != nil {
		return nil, fmt.Errorf("old root trust lineage: %w", err)
	}
	oldID, err := old.Hash(crypto.SHA256)
	if err != nil {
		return nil, err
	}
	oldSigning, err := x.trustBaseStore.SigningConfig(v.Epoch)
	if err != nil {
		return nil, fmt.Errorf("old root trust lineage: %w", err)
	}
	verified, err := handoff.VerifyOldCommitProofSigning(proof, old, oldSigning)
	if err != nil {
		return nil, fmt.Errorf("old handoff commit proof: %w", err)
	}
	if !bytes.Equal(verified.RecordID[:], v.RecordID) { // the record commits to its body, boundary and control state, and the proof's QC to its root
		return nil, fmt.Errorf("%w: the proof is not the one that activated the epoch", ErrNotVerifiedEpoch)
	}
	first := head.ShardInfo[0]
	if _, err := handoffdelivery.VerifySnapshot(proof, verified, head, first.Partition, first.Shard, first.ShardConfHash); err != nil {
		return nil, err
	}
	projected := entry.Projection()
	projected.PreviousEntryHash = oldID
	signing := votesig.Config{Scheme: cfg.SigningScheme, Network: cfg.Network, Genesis: cfg.Genesis}
	safetyStore, ok := x.blockStore.GetDB().(epochAnchorSafetyStore)
	if !ok {
		return nil, errors.New("durable epoch anchor safety store unavailable")
	}
	if existing, err := safetyStore.ReadEpochAnchorSafety(); err != nil {
		return nil, err
	} else if existing != nil && existing.Epoch >= g.Epoch && (existing.Epoch != g.Epoch || !bytes.Equal(existing.GenesisID, g.ID())) {
		return nil, rctypes.ErrEpochAnchor
	}
	newTrust, err := x.trustBaseStore.InstallVerified(projected, signing)
	if err != nil {
		return nil, err
	}
	if len(candidate) != 0 { // retained before the anchor, which derives the activated configuration from the retained pair
		bodyID := entry.BodyID()
		if err := x.blockStore.RetainHandoffArtifacts(bodyID[:], entry.BodyEncoding(), candidate); err != nil {
			return nil, fmt.Errorf("retain handoff candidate: %w", err)
		}
	}
	a, err := x.blockStore.InstallEpochAnchor(head, v, g)
	if err != nil {
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
	x.handoffIntent = nil
	x.handoffAborts = nil
	x.handoffMu.Unlock()
	x.leaderSelector = selector
	x.irReqVerifier = reqVerifier
	x.t2Timeouts = t2Timeouts
	x.epochAnchor = a
	return a, nil
}

// HoldsVerifiedEpoch reports whether the manager's durable state is exactly the verified entry's installation: the trust-base
// store holds the entry's projection (members, exact weights, threshold, start) and the durable epoch-anchor record is that epoch's
// anchor, or the epoch's has since been succeeded. The install journal calls it to check, never to install.
func (x *ConsensusManager) HoldsVerifiedEpoch(entry q3format.Entry) error {
	_, g, ok := entry.Handoff()
	if !ok {
		return ErrNotVerifiedEpoch
	}
	have, err := x.trustBaseStore.GetByEpoch(entry.Epoch())
	if err != nil {
		return err
	}
	if !sameCommittee(have, entry.Projection()) {
		return fmt.Errorf("%w: the stored trust base of epoch %d is not the verified one", ErrNotVerifiedEpoch, entry.Epoch())
	}
	safetyStore, ok := x.blockStore.GetDB().(epochAnchorSafetyStore)
	if !ok {
		return errors.New("durable epoch anchor safety store unavailable")
	}
	anchor, err := safetyStore.ReadEpochAnchorSafety()
	if err != nil {
		return err
	}
	if anchor == nil || (anchor.Epoch == g.Epoch && !bytes.Equal(anchor.GenesisID, g.ID())) {
		return fmt.Errorf("%w: the durable epoch anchor is not epoch %d's", ErrNotVerifiedEpoch, entry.Epoch())
	}
	return nil
}

// q3Activated reports whether the installed anchor is the anchor of an activated Q3 epoch of the verified history. An anchor that
// names an activated epoch but another genesis identity is not: it falls through to the V2 lineage check and fails there.
func q3Activated(a Q3Authority, anchor *rctypes.EpochAnchor) bool {
	if a == nil || anchor == nil {
		return false
	}
	entry, _ := a.Activated(anchor.Epoch) // not an activation: a zero entry, which has no handoff
	_, g, ok := entry.Handoff()
	return ok && bytes.Equal(g.ID(), anchor.GenesisID)
}

// sameCommittee compares two root trust bases by what authenticates with them: network, epoch, start, exact weights and keys in
// order, and the threshold.
func sameCommittee(a, b *basetypes.RootTrustBaseV1) bool {
	if a == nil || b == nil || a.NetworkID != b.NetworkID || a.Epoch != b.Epoch || a.EpochStart != b.EpochStart ||
		a.QuorumThreshold != b.QuorumThreshold || len(a.RootNodes) != len(b.RootNodes) {
		return false
	}
	for i, n := range a.RootNodes {
		m := b.RootNodes[i]
		if n == nil || m == nil || n.NodeID != m.NodeID || n.Stake != m.Stake || !bytes.Equal(n.SigKey, m.SigKey) {
			return false
		}
	}
	return true
}
