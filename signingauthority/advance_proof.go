package signingauthority

import (
	"bytes"
	"context"
	gocrypto "crypto"
	"fmt"
	"math"

	"github.com/unicitynetwork/bft-core/activationproof"
	"github.com/unicitynetwork/bft-core/internal/weightvalidation"
	"github.com/unicitynetwork/bft-go-base/types"
)

/*
The proof-verified advance (#1085; astra's review of the handoff design note, part B).

AdvanceEpoch installs a successor context an operator supplies and checks only its structure: the operator chooses the trust. An
authority started with a lineage pin (WithLineage) advances instead by AdvanceWithProof, one root activation bundle at a time, and
verifies everything itself, inside its own trust boundary, from that pin:

  - the bundle extends its own lineage: the Q3 history from the pinned genesis, which authenticates the predecessor identity, the
    monotonic epoch, the old committee's weighted quorum under that epoch's own signing scheme, the committed activation and its
    boundary, and the exact successor body and committee projection (activationproof.Lineage.Extend);
  - for the activation that follows its own root epoch: the old committee's commit once more under its own lineage's keys, the
    committed checkpoint against that commit AND against the configuration hash this authority holds (which authenticates the context
    it signs in now), the committed candidate against the activated body, and from it the configuration its shard runs from the
    activation (activationproof.ShardTransition): unchanged for a root-only change, the activated assignment for a coupled one;
  - the authority's own operator-provisioned root trust of its current epoch is the lineage's (the same committee, weights, threshold
    and boundary): the tip it advances from is authenticated, not assumed;
  - the activated configuration is valid under the bounded weights, is this network's, partition's and shard's, and names this node
    with THIS authority's key. One that does not retires the authority: it installs the history and signs nothing further.

Nothing a requester supplies is taken as a result: the bundle is evidence, and the only inputs are its bytes. A bundle for an epoch the
lineage already holds is an exact replay (a no-op) or a conflict; a bundle that skips an epoch is refused (send them in order). The first
successor certificate is not needed: the old committee's committed activation authorises the transition, and every request signed after
it still needs its own certificate under the installed context.

Verification runs outside the authority's lock, so signing continues meanwhile; the result is published under the lock, and only if
nothing changed since the snapshot it was verified against. The high-water record and the input-record acknowledgement state are kept
(publishScopeLocked, as for AdvanceEpoch), and the advance fences the client: the next session is the operator's to issue, as before.
*/

// AdvanceResult is what one proof advance did.
type AdvanceResult struct {
	// Epoch is the root epoch the bundle activates.
	Epoch uint64
	// Replay is a bundle for an epoch the lineage already held, exactly that entry: nothing changed.
	Replay bool
	// Advanced is a scope change: the authority now signs in Epoch (and has fenced its client).
	Advanced bool
	// Retired is the latched state of an authority the lineage removed, now or earlier.
	Retired bool
	// RootEpoch and ShardEpoch are the scope after the call; LineageEpoch the lineage's tip.
	RootEpoch, ShardEpoch, LineageEpoch uint64
}

// AdvanceWithProof verifies one activation bundle (q3active.Bundle encoding) against this authority's own lineage and, when it is the
// activation that follows the authority's root epoch, advances the signing scope to it. Bundles for earlier epochs extend the lineage
// only (the catch-up of an authority whose lineage is behind its scope), and the one for its own epoch also authenticates the root trust
// it was provisioned with.
func (a *Authority) AdvanceWithProof(ctx context.Context, bundle []byte) (AdvanceResult, error) {
	if err := ctx.Err(); err != nil {
		return AdvanceResult{}, err
	}
	if !a.advancing.TryLock() {
		return AdvanceResult{}, fmt.Errorf("%w: another activation proof is being verified", ErrAdvanceBusy)
	}
	defer a.advancing.Unlock()

	// the snapshot the proof is verified against
	a.mu.Lock()
	if a.signer == nil {
		a.mu.Unlock()
		return AdvanceResult{}, fmt.Errorf("%w: this authority has no key for %s", ErrKeyLost, a.enroll.NodeID)
	}
	if a.state != healthActive {
		a.mu.Unlock()
		return AdvanceResult{}, fmt.Errorf("%w: this authority has latched faulted", ErrStateUntrusted)
	}
	if a.lineage == nil {
		a.mu.Unlock()
		return AdvanceResult{}, fmt.Errorf("%w: this authority was enrolled without a lineage pin", ErrLineageUnverified)
	}
	enroll, lineage, trust, scope, retired := a.enroll.clone(), a.lineage, a.trust, a.scopeVersion, a.retired
	pub, err := publicKeyOf(a.signer)
	a.mu.Unlock()
	if err != nil {
		return AdvanceResult{}, err
	}
	if !enroll.complete() {
		return AdvanceResult{}, fmt.Errorf("%w: no shard configuration has been stated", ErrEnrollmentIncomplete)
	}
	current := *enroll.RootEpoch

	next, step, err := lineage.Extend(bundle)
	if err != nil {
		return AdvanceResult{}, fmt.Errorf("%w: %w", ErrLineageUnverified, err)
	}
	result := AdvanceResult{Epoch: step.Epoch, Replay: step.Replay, Retired: retired}
	var successor *scopeChange
	switch {
	case step.Replay:
		// exactly an entry the lineage holds: nothing to do
	case step.Epoch < current:
		// catch-up of a lineage behind the scope
	case step.Epoch == current:
		// the lineage reaches the authority's own epoch: the root trust it was provisioned with must be the lineage's
		if err := sameTrust(ctx, trust, next, current); err != nil {
			return AdvanceResult{}, err
		}
	case retired:
		// a retired authority follows the lineage and nothing else
	case step.Epoch == current+1:
		if err := sameTrust(ctx, trust, lineage, current); err != nil {
			return AdvanceResult{}, err
		}
		successor, err = verifySuccessor(lineage, next, step, enroll, pub)
		if err != nil {
			return AdvanceResult{}, err
		}
	default:
		// the lineage is ahead of the scope (an epoch this authority was never advanced to): no step from here is authenticated
		return AdvanceResult{}, fmt.Errorf("%w: epoch %d follows the lineage's tip %d, but this authority signs in epoch %d", ErrLineageUnverified, step.Epoch, lineage.Tip(), current)
	}
	if err := ctx.Err(); err != nil {
		return AdvanceResult{}, err
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if a.signer == nil {
		return AdvanceResult{}, fmt.Errorf("%w: this authority has no key for %s", ErrKeyLost, a.enroll.NodeID)
	}
	if a.state != healthActive {
		return AdvanceResult{}, fmt.Errorf("%w: this authority has latched faulted", ErrStateUntrusted)
	}
	if a.scopeVersion != scope || a.lineage != lineage || a.retired != retired {
		// the operator's recovery advance (the only other writer) landed meanwhile: verify again against what is now held
		return AdvanceResult{}, fmt.Errorf("%w: the authority's scope changed while the proof was verified", ErrConflict)
	}
	if successor != nil {
		if a.rec.checkInvariants() != nil || a.generation == math.MaxUint64 || a.scopeVersion == math.MaxUint64 {
			a.state = healthFaulted
			return AdvanceResult{}, ErrStateUntrusted
		}
	}
	a.lineage = next
	switch {
	case successor == nil:
	case successor.retire:
		// installed and fenced: the history is the lineage's, and nothing is signed or issued again within this lifetime
		a.retired = true
		a.scopeVersion++
		a.generation++
		a.sessionIssued = false
		result.Retired = true
	default:
		a.publishScopeLocked(a.enroll, successor.shardEpoch, successor.confHash, successor.trust)
		result.Advanced = true
	}
	result.RootEpoch, result.ShardEpoch, result.LineageEpoch = pinnedRootEpoch(a.enroll.RootEpoch), a.enroll.ShardEpoch, a.lineage.Tip()
	return result, nil
}

// lineageEpochLocked is the lineage's tip, zero without a pin.
func (a *Authority) lineageEpochLocked() uint64 {
	if a.lineage == nil {
		return 0
	}
	return a.lineage.Tip()
}

// scopeChange is the verified successor scope of one proof advance.
type scopeChange struct {
	retire     bool
	shardEpoch uint64
	confHash   []byte
	trust      *types.RootTrustBaseV1
}

// verifySuccessor derives the authority's scope from the activation that follows its epoch, from nothing but the verified step and its
// own enrollment and key.
func verifySuccessor(prev, next *activationproof.Lineage, step activationproof.Step, enroll Enrollment, pub []byte) (*scopeChange, error) {
	t, err := activationproof.ShardTransition(prev, step, enroll.PartitionID, enroll.ShardID, enroll.ShardConfHash)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrLineageUnverified, err)
	}
	trust, err := next.Trust(step.Epoch)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrLineageUnverified, err)
	}
	if t.Conf == nil {
		// root-only: the configuration (and so this node's place in it) is unchanged
		if !bytes.Equal(t.NextConfHash, enroll.ShardConfHash) {
			return nil, fmt.Errorf("%w: a root-only activation changes the configuration hash", ErrLineageUnverified)
		}
		return &scopeChange{shardEpoch: enroll.ShardEpoch, confHash: t.NextConfHash, trust: trust}, nil
	}
	conf := t.Conf
	if err := weightvalidation.PDR(conf, weightvalidation.RoleEVM, weightvalidation.ModeWeighted); err != nil {
		return nil, fmt.Errorf("%w: the activated configuration is not valid: %w", ErrLineageUnverified, err)
	}
	if conf.NetworkID != enroll.NetworkID || conf.PartitionID != enroll.PartitionID || !conf.ShardID.Equal(enroll.ShardID) || conf.Epoch < enroll.ShardEpoch {
		return nil, fmt.Errorf("%w: the activated configuration is for network %d partition %d shard %s epoch %d", ErrLineageUnverified,
			conf.NetworkID, conf.PartitionID, conf.ShardID, conf.Epoch)
	}
	hash, err := conf.Hash(gocrypto.SHA256)
	if err != nil || !bytes.Equal(hash, t.NextConfHash) {
		return nil, fmt.Errorf("%w: the activated configuration's hash", ErrLineageUnverified)
	}
	named := false
	for _, v := range conf.Validators {
		if v.NodeID == enroll.NodeID {
			named = bytes.Equal(v.SigKey, pub)
			break
		}
	}
	if !named {
		return &scopeChange{retire: true}, nil
	}
	return &scopeChange{shardEpoch: conf.Epoch, confHash: hash, trust: trust}, nil
}

// sameTrust authenticates the authority's provisioned root trust of an epoch against its lineage's: the same network, epoch, boundary,
// threshold and committee, member for member (key and weight). It is the check that the scope an authority advances FROM is the
// lineage's, so an operator-provisioned trust that is not cannot be carried forward.
func sameTrust(ctx context.Context, trust TrustBases, l *activationproof.Lineage, epoch uint64) error {
	have, err := trust.GetByEpoch(ctx, epoch)
	if err != nil || have == nil {
		return fmt.Errorf("%w: no root trust for epoch %d: %v", ErrStateUntrusted, epoch, err)
	}
	want, err := l.Trust(epoch)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrLineageUnverified, err)
	}
	if have.NetworkID != want.NetworkID || have.Epoch != want.Epoch || have.EpochStart != want.EpochStart || have.QuorumThreshold != want.QuorumThreshold ||
		len(have.RootNodes) != len(want.RootNodes) {
		return fmt.Errorf("%w: the provisioned root trust of epoch %d is not the lineage's", ErrContextMismatch, epoch)
	}
	members := make(map[string]*types.NodeInfo, len(want.RootNodes))
	for _, n := range want.RootNodes {
		members[n.NodeID] = n
	}
	for _, n := range have.RootNodes {
		w, ok := members[n.NodeID]
		if !ok || w.Stake != n.Stake || !bytes.Equal(w.SigKey, n.SigKey) {
			return fmt.Errorf("%w: the provisioned root trust of epoch %d is not the lineage's (member %s)", ErrContextMismatch, epoch, n.NodeID)
		}
	}
	return nil
}
