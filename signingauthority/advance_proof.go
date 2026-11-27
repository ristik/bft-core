package signingauthority

import (
	"bytes"
	"context"
	gocrypto "crypto"
	"errors"
	"fmt"
	"math"

	"github.com/unicitynetwork/bft-core/activationproof"
	"github.com/unicitynetwork/bft-core/internal/weightvalidation"
	"github.com/unicitynetwork/bft-core/vradmit"
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
  - the authority's own operator-provisioned root trust of its current epoch is the lineage's (the same network, committee, weights and
    threshold): the tip it advances from is authenticated, not assumed. When the lineage reaches that epoch, the authority holds the
    lineage's trust of it from then on, boundary included, and every later step compares that trust in full;
  - the activated configuration is valid under the bounded weights, is this network's, partition's and shard's, and names this node
    with THIS authority's key. One that does not fences the authority. Only the exact recovery of an unacknowledged primary
    exclusion can restore the original node and key to a signing scope.

Nothing a requester supplies is taken as a result: the bundle is evidence, and the only inputs are its bytes. A bundle for an epoch the
lineage already holds is an exact replay (a no-op) or a conflict; a bundle that skips an epoch is refused (send them in order). The first
successor certificate is not needed: the old committee's committed activation authorises the transition, and every request signed after
it still needs its own certificate under the installed context.

Verification runs outside the authority's lock, so signing continues meanwhile; the result is published under the lock, and only if
nothing changed since the snapshot it was verified against. A retired authority produces no signature of any kind: certification, the
handoff possession proof and the EVM election and delegation possessions are all refused (ErrRetired, under the lock).

What this does not do: the scope an authority starts in (its enrollment and the root trust of its first epoch) is still provisioned by
the operator, and an authority pinned at a late epoch can sign in that scope before its lineage has caught up to it. The lineage
authenticates that scope at the first proof advance FROM it (sameTrust, and the checkpoint against the held configuration), not
retrospectively before its first signature. The boundary (EpochStart) of that first epoch is the one field the operator cannot provision
in a UTB chain: the authority of a joining member runs before its first epoch activates (it attests possession for the handoff), and the
activation round A* is fixed only by the old committee's commit. So the operator's trust is authenticated on what it is authoritative for
(the committee a certificate of that epoch is verified with), and the boundary is taken from the lineage (bft-core#1114). It removes
operator trust from every advance, not from the bootstrap. The high-water record and the input-record acknowledgement state are kept
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
	// Generation is the client generation after the call. An advance or a retirement fences every session up to it: a server that
	// admits a session of a generation at or below it drops that credential, and keeps one issued later (by a replacement that raced the
	// verification and landed after the publication).
	Generation uint64
}

// AdvanceWithProof verifies one activation bundle (q3active.Bundle encoding) against this authority's own lineage and, when it is the
// activation that follows the authority's root epoch, advances the signing scope to it. Bundles for earlier epochs extend the lineage
// only (the catch-up of an authority whose lineage is behind its scope), and the one for its own epoch also authenticates the root trust
// it was provisioned with.
func (a *Authority) AdvanceWithProof(ctx context.Context, bundle []byte) (AdvanceResult, error) {
	if err := ctx.Err(); err != nil {
		return AdvanceResult{}, err
	}
	fence, err := a.fenceGate()
	if err != nil {
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
	enroll, lineage, trust, scope, retired, recovery := a.enroll.clone(), a.lineage, a.trust, a.scopeVersion, a.retired, a.recovery
	pending := !enroll.complete() && a.pendingJoinScope
	joinChainID, pos := a.joinChainID, a.pos
	pub, err := publicKeyOf(a.signer)
	a.mu.Unlock()
	if err != nil {
		return AdvanceResult{}, err
	}
	if !enroll.complete() && !pending {
		return AdvanceResult{}, fmt.Errorf("%w: no shard configuration has been stated", ErrEnrollmentIncomplete)
	}
	current := *enroll.RootEpoch
	if a.advanceHook != nil {
		a.advanceHook()
	}

	next, step, err := lineage.Extend(bundle)
	if err != nil {
		return AdvanceResult{}, fmt.Errorf("%w: %w", ErrLineageUnverified, err)
	}
	if fence != nil && step.Epoch >= current { // earlier steps are the lineage's catch-up: nothing to sign for
		// the schedule of the checkpoint this authority just verified (VerifySnapshot, against the entry's control digest): it holds every
		// entry with E <= the epoch, so it decides without an endpoint and whatever Boundaries the EVM skipped
		v, _, ok := step.Entry.Handoff()
		if !ok || step.Bundle.Snapshot == nil {
			return AdvanceResult{}, fmt.Errorf("%w: epoch %d has no verified checkpoint", ErrLineageUnverified, step.Epoch)
		}
		sched, err := vradmit.AuthenticatedSchedule(step.Bundle.Snapshot.Control, v.ControlDigest)
		if err != nil {
			return AdvanceResult{}, fmt.Errorf("%w: %w", ErrLineageUnverified, err)
		}
		if err := fence.CheckCheckpoint(step.Epoch, sched); err != nil {
			return AdvanceResult{}, fmt.Errorf("advancing to root epoch %d: %w", step.Epoch, err)
		}
	}
	result := AdvanceResult{Epoch: step.Epoch, Replay: step.Replay, Retired: retired}
	var successor *scopeChange
	var pendingSuccessor *scopeChange
	var adopted *types.RootTrustBaseV1 // the lineage's trust of the current epoch, held from now on
	switch {
	case step.Replay:
		// exactly an entry the lineage holds: nothing to do
	case step.Epoch < current:
		// catch-up of a lineage behind the scope
	case step.Epoch == current:
		// the lineage reaches the authority's own epoch: the root trust it was provisioned with must name the lineage's committee, and the
		// authority holds the lineage's trust of the epoch from now on (its boundary is the committed activation's, see above)
		if adopted, err = provisionedCommittee(ctx, trust, next, current); err != nil {
			return AdvanceResult{}, err
		}
	case retired:
		if recovery != nil {
			successor, err = recovery.verify(lineage, next, step, enroll, pub)
			if err != nil {
				return AdvanceResult{}, err
			}
		}
	case step.Epoch == current+1:
		if err := sameTrust(ctx, trust, lineage, current); err != nil {
			return AdvanceResult{}, err
		}
		if pending {
			pendingSuccessor, err = verifyPendingJoinSuccessor(lineage, next, step, enroll, pub, joinChainID, pos)
		} else {
			successor, err = verifySuccessor(lineage, next, step, enroll, pub)
		}
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
	if a.scopeVersion != scope || a.lineage != lineage || a.retired != retired || a.enroll.complete() != enroll.complete() || (pending && a.pos != pos) {
		// Enrollment, a PoS pin or an operator-trusted advance landed meanwhile. Verify again against what is now held.
		return AdvanceResult{}, fmt.Errorf("%w: the authority's scope changed while the proof was verified", ErrConflict)
	}
	if pendingSuccessor != nil && a.joinScopeProved && pendingSuccessor.shardEpoch != enroll.ShardEpoch {
		return AdvanceResult{}, fmt.Errorf("%w: the pending join authority already proved possession for shard epoch %d", ErrContextMismatch, enroll.ShardEpoch)
	}
	if successor != nil {
		if a.rec.checkInvariants() != nil || a.generation == math.MaxUint64 || a.scopeVersion == math.MaxUint64 {
			a.state = healthFaulted
			return AdvanceResult{}, ErrStateUntrusted
		}
	}
	a.lineage = next
	if !step.Replay {
		a.recovery = nil // eligibility lasts for the immediate successor of the exclusion
	}
	switch {
	case pendingSuccessor != nil:
		a.enroll.RootEpoch = PinRootEpoch(step.Epoch)
		a.enroll.ShardEpoch = pendingSuccessor.shardEpoch
		a.trust = currentTrust{base: pendingSuccessor.trust}
		result.Advanced = true
	case successor == nil:
		if adopted != nil {
			// the same committee, now with the authenticated boundary: the scope, its version and the session are unchanged
			a.trust = currentTrust{base: adopted}
		}
	case successor.retire:
		a.retired = true
		a.recovery = successor.recovery
		a.scopeVersion++
		a.generation++
		a.sessionIssued = false
		result.Retired = true
	default:
		a.publishScopeLocked(a.enroll, successor.shardEpoch, successor.confHash, successor.trust)
		a.retired, result.Retired = false, false
		result.Advanced = true
	}
	result.RootEpoch, result.ShardEpoch, result.LineageEpoch = pinnedRootEpoch(a.enroll.RootEpoch), a.enroll.ShardEpoch, a.lineage.Tip()
	result.Generation = a.generation
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
	recovery   *recoveryExclusion
	shardEpoch uint64
	confHash   []byte
	trust      *types.RootTrustBaseV1
}

// verifySuccessor derives the authority's scope from the activation that follows its epoch, from nothing but the verified step and its
// own enrollment and key.
func verifySuccessor(prev, next *activationproof.Lineage, step activationproof.Step, enroll Enrollment, pub []byte) (*scopeChange, error) {
	t, err := activationproof.ShardTransition(prev, step, enroll.PartitionID, enroll.ShardID, enroll.ShardConfHash)
	if err != nil && errors.Is(err, activationproof.ErrShard) {
		// A newly admitted member is enrolled at the SUCCESSOR configuration, which the predecessor's checkpoint does not carry. Its first
		// handoff is the one that admits it: the predecessor is verified against the configuration the authenticated checkpoint itself
		// certifies for the shard, and the activation must then yield exactly the configuration this authority is enrolled with (so its key
		// and configuration are bound to the certified successor before any session is issued).
		if pre := checkpointConfHash(step, enroll.PartitionID, enroll.ShardID); pre != nil && !bytes.Equal(pre, enroll.ShardConfHash) {
			if jt, jerr := activationproof.ShardTransition(prev, step, enroll.PartitionID, enroll.ShardID, pre); jerr == nil &&
				jt.Conf != nil && bytes.Equal(jt.NextConfHash, enroll.ShardConfHash) {
				t, err = jt, nil
			}
		}
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrLineageUnverified, err)
	}
	return scopeForTransition(next, step, enroll, pub, t)
}

func scopeForTransition(next *activationproof.Lineage, step activationproof.Step, enroll Enrollment, pub []byte, t activationproof.Transition) (*scopeChange, error) {
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
	for _, v := range conf.Validators {
		if v.NodeID == enroll.NodeID {
			if !bytes.Equal(v.SigKey, pub) {
				return &scopeChange{retire: true}, nil
			}
			return &scopeChange{shardEpoch: conf.Epoch, confHash: hash, trust: trust}, nil
		}
	}
	return &scopeChange{retire: true, recovery: excludedByPrimary(step, enroll, pub, conf.Epoch, hash)}, nil
}

// sameTrust authenticates the authority's held root trust of an epoch against its lineage's: the same network, epoch, boundary,
// threshold and committee, member for member (key and weight). It is the check that the scope an authority advances FROM is the
// lineage's, so a trust that is not cannot be carried forward.
func sameTrust(ctx context.Context, trust TrustBases, l *activationproof.Lineage, epoch uint64) error {
	have, want, err := committeeOf(ctx, trust, l, epoch)
	if err != nil {
		return err
	}
	if have.EpochStart != want.EpochStart {
		return fmt.Errorf("%w: the held root trust of epoch %d starts at round %d, the lineage's at %d", ErrContextMismatch, epoch, have.EpochStart, want.EpochStart)
	}
	return nil
}

// provisionedCommittee authenticates the operator-provisioned root trust of the authority's own epoch when its lineage reaches that
// epoch: the same network, epoch, threshold and committee, member for member (key and weight). Its boundary is not compared (a joining
// member's authority is provisioned before the activation round is fixed); the result is the lineage's trust of the epoch, the one the
// authority holds from then on.
func provisionedCommittee(ctx context.Context, trust TrustBases, l *activationproof.Lineage, epoch uint64) (*types.RootTrustBaseV1, error) {
	_, want, err := committeeOf(ctx, trust, l, epoch)
	return want, err
}

// committeeOf is the held and the lineage's root trust of an epoch, once their network, epoch, threshold and committee (a one-to-one
// match of members, key and weight) are the same.
func committeeOf(ctx context.Context, trust TrustBases, l *activationproof.Lineage, epoch uint64) (have, want *types.RootTrustBaseV1, err error) {
	have, err = trust.GetByEpoch(ctx, epoch)
	if err != nil || have == nil {
		return nil, nil, fmt.Errorf("%w: no root trust for epoch %d: %v", ErrStateUntrusted, epoch, err)
	}
	want, err = l.Trust(epoch)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrLineageUnverified, err)
	}
	if have.NetworkID != want.NetworkID || have.Epoch != want.Epoch || have.QuorumThreshold != want.QuorumThreshold || len(have.RootNodes) != len(want.RootNodes) {
		return nil, nil, fmt.Errorf("%w: the provisioned root trust of epoch %d is not the lineage's", ErrContextMismatch, epoch)
	}
	members := make(map[string]*types.NodeInfo, len(want.RootNodes))
	for _, n := range want.RootNodes {
		if n != nil {
			members[n.NodeID] = n
		}
	}
	for _, n := range have.RootNodes {
		if n == nil {
			return nil, nil, fmt.Errorf("%w: the provisioned root trust of epoch %d has an empty member", ErrContextMismatch, epoch)
		}
		w, ok := members[n.NodeID]
		if !ok || w.Stake != n.Stake || !bytes.Equal(w.SigKey, n.SigKey) {
			return nil, nil, fmt.Errorf("%w: the provisioned root trust of epoch %d is not the lineage's (member %s)", ErrContextMismatch, epoch, n.NodeID)
		}
		delete(members, n.NodeID) // one-to-one: a member listed twice does not stand in for one left out
	}
	return have, want, nil
}

// checkpointConfHash is the configuration hash the step's checkpoint certifies for the shard, or nil. The checkpoint is authenticated
// against the verified commit proof by ShardTransition before anything is derived from it.
func checkpointConfHash(step activationproof.Step, partition types.PartitionID, shard types.ShardID) []byte {
	if step.Bundle.Snapshot == nil {
		return nil
	}
	for _, si := range step.Bundle.Snapshot.ShardInfo {
		if si.Partition == partition && si.Shard.Equal(shard) {
			return si.ShardConfHash
		}
	}
	return nil
}
