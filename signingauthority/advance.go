package signingauthority

import (
	"bytes"
	"context"
	"crypto"
	"fmt"
	"math"

	"github.com/unicitynetwork/bft-go-base/types"
)

// AdvanceEpoch accepts operator-provisioned successor root trust and shard
// configuration. The authority verifies the scope and its own key, then
// publishes both together while retaining its one signing high-water record.
// Success fences the current client session.
func (a *Authority) AdvanceEpoch(ctx context.Context, conf *types.PartitionDescriptionRecord, successor *types.RootTrustBaseV1) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.signer == nil {
		return ErrKeyLost
	}
	if a.state != healthActive || a.rec.checkInvariants() != nil || a.generation == math.MaxUint64 || a.scopeVersion == math.MaxUint64 {
		a.state = healthFaulted
		return ErrStateUntrusted
	}
	old := a.enroll
	if !old.complete() {
		return ErrEnrollmentIncomplete
	}
	if conf == nil || successor == nil {
		return fmt.Errorf("%w: missing successor context", ErrContextMismatch)
	}
	if err := conf.IsValid(); err != nil {
		return fmt.Errorf("%w: invalid successor configuration: %v", ErrContextMismatch, err)
	}
	if conf.NetworkID != old.NetworkID || conf.PartitionID != old.PartitionID || !conf.ShardID.Equal(old.ShardID) ||
		successor.NetworkID != old.NetworkID || successor.Epoch < *old.RootEpoch || conf.Epoch < old.ShardEpoch ||
		(successor.Epoch == *old.RootEpoch && conf.Epoch == old.ShardEpoch) {
		return ErrContextMismatch
	}
	pub, err := publicKeyOf(a.signer)
	if err != nil {
		return err
	}
	named := false
	for _, node := range conf.Validators {
		if node.NodeID == old.NodeID {
			named = bytes.Equal(node.SigKey, pub)
			break
		}
	}
	if !named {
		return fmt.Errorf("%w: successor configuration does not name this node and key", ErrContextMismatch)
	}
	hash, err := conf.Hash(crypto.SHA256)
	if err != nil {
		return err
	}
	if conf.Epoch == old.ShardEpoch && !bytes.Equal(hash, old.ShardConfHash) {
		return fmt.Errorf("%w: root-only advance changed the shard configuration", ErrContextMismatch)
	}
	encoded, err := types.Cbor.Marshal(successor)
	if err != nil {
		return fmt.Errorf("%w: encoding successor trust: %v", ErrContextMismatch, err)
	}
	var owned types.RootTrustBaseV1
	if err := types.Cbor.Unmarshal(encoded, &owned); err != nil {
		return fmt.Errorf("%w: decoding successor trust: %v", ErrContextMismatch, err)
	}
	if owned.Version != 1 || owned.Epoch != successor.Epoch || owned.NetworkID != old.NetworkID || len(owned.RootNodes) == 0 {
		return fmt.Errorf("%w: invalid successor trust", ErrContextMismatch)
	}
	seen := make(map[string]bool, len(owned.RootNodes))
	for _, node := range owned.RootNodes {
		if err := node.IsValid(); err != nil || seen[node.NodeID] {
			return fmt.Errorf("%w: invalid successor root node", ErrContextMismatch)
		}
		seen[node.NodeID] = true
	}
	if _, err := types.NewTrustBase(owned.NetworkID, owned.RootNodes,
		types.WithEpoch(owned.Epoch), types.WithEpochStart(owned.EpochStart),
		types.WithQuorumThreshold(owned.QuorumThreshold)); err != nil {
		return fmt.Errorf("%w: invalid successor trust: %v", ErrContextMismatch, err)
	}
	if owned.Epoch == *old.RootEpoch {
		current, err := a.trust.GetByEpoch(ctx, owned.Epoch)
		if err != nil || current == nil {
			return fmt.Errorf("%w: current root trust unavailable", ErrStateUntrusted)
		}
		currentHash, err := current.Hash(crypto.SHA256)
		if err != nil {
			return err
		}
		newHash, err := owned.Hash(crypto.SHA256)
		if err != nil {
			return err
		}
		if !bytes.Equal(currentHash, newHash) {
			return fmt.Errorf("%w: same root epoch has different trust", ErrContextMismatch)
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// The high-water record is not cleared, and old reservations cannot be
	// signed or released after the context changes.
	if conf.Epoch > old.ShardEpoch {
		// A new shard epoch: if this authority acknowledged (operated at) the epoch it leaves, that is the input-record epoch to expect
		// while the successor's acknowledgement is pending; otherwise the base it had stays (or stays unknown).
		if a.irAckSeen {
			a.irBase, a.irBaseKnown = old.ShardEpoch, true
		}
		a.irAckSeen = false
	}
	a.enroll.ShardEpoch = conf.Epoch
	a.enroll.ShardConfHash = bytes.Clone(hash)
	a.enroll.RootEpoch = PinRootEpoch(owned.Epoch)
	a.trust = currentTrust{base: &owned}
	a.scopeVersion++
	a.generation++
	return nil
}
