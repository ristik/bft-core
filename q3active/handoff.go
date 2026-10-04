package q3active

import (
	"context"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-core/handoffdelivery"
	"github.com/unicitynetwork/bft-go-base/types"
)

// ErrLegacyBundle is returned when a legacy (V2-bodied) handoff bundle names a successor epoch that the verified history holds as a
// Q3 activation: an old peer cannot deliver, or contradict, an epoch a V3 activation committed.
var ErrLegacyBundle = errors.New("q3active: a legacy handoff bundle cannot install an epoch the verified history activated")

// HandoffInstaller is the shard node's trust history (shardnode.HandoffHistory): its lookup and its installation of fetched
// legacy handoffs.
type HandoffInstaller interface {
	TrustLookup
	InstallHandoff(ctx context.Context, bundle handoffdelivery.Bundle, partition types.PartitionID, shard types.ShardID, confHash []byte) (handoffdelivery.Verified, error)
}

// GuardedHandoff is the shard follower's history over a runtime: lookups are Guarded, and a fetched legacy bundle is installed by
// the base history only if it is for an epoch the verified history does not hold as an activation. An activated epoch is installed
// by the journal, from its proof envelope, and by nothing else.
type GuardedHandoff struct {
	*Guarded
	base HandoffInstaller
}

// Handoff wraps the shard node's history. The base serves the legacy epochs and installs legacy bundles.
func (r *Runtime) Handoff(base HandoffInstaller) *GuardedHandoff {
	return &GuardedHandoff{Guarded: r.Trust(base), base: base}
}

// InstallHandoff refuses a bundle for an activated epoch and otherwise is the base's.
func (g *GuardedHandoff) InstallHandoff(ctx context.Context, bundle handoffdelivery.Bundle, partition types.PartitionID, shard types.ShardID, confHash []byte) (handoffdelivery.Verified, error) {
	if epoch := bundle.Proof.Record.Epoch; epoch == ^uint64(0) {
		return handoffdelivery.Verified{}, handoffdelivery.ErrBundle
	} else if _, activated := g.rt.Activated(epoch + 1); activated {
		return handoffdelivery.Verified{}, fmt.Errorf("%w: epoch %d", ErrLegacyBundle, epoch+1)
	}
	return g.base.InstallHandoff(ctx, bundle, partition, shard, confHash)
}
