package archivewiring

import (
	"context"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/handoffdelivery"
	"github.com/unicitynetwork/bft-go-base/types"
)

type BundleHistory interface {
	GetByEpoch(context.Context, uint64) (*types.RootTrustBaseV1, error)
}

// ErrBundleConfEpochUnknown refuses a bundle whose snapshot names a shard epoch with no installed configuration: that epoch's assignment
// has not been installed here yet. It is retryable after the install, and it never falls back to the genesis or another epoch's hash.
var ErrBundleConfEpochUnknown = errors.New("archivewiring: no installed shard configuration for the bundle snapshot's shard epoch")

// VerifyBundle is shared by local publication and replica admission. Archive
// bytes never supply a trust anchor; every epoch uses installed history.
//
// The bundle's snapshot carries the shard's configuration AS OF the handoff, which after an assignment activates is no longer the
// genesis one. With confForEpoch set, the snapshot must carry exactly the configuration installed for the shard epoch its technical
// record names (the same set the certificate client uses); nil keeps the genesis-only expectation of a node that follows no assignment.
func VerifyBundle(ctx context.Context, q archive.BundleRequest, raw []byte, history BundleHistory, confForEpoch func(uint64) ([]byte, bool)) error {
	if history == nil || len(raw) == 0 || len(raw) > archive.MaxBundleBytes {
		return archive.ErrInvalid
	}
	bundle, err := handoffdelivery.DecodeBundle(raw)
	if err != nil || bundle.Body.Epoch != q.Epoch || bundle.Proof.Record.Epoch+1 != q.Epoch {
		return archive.ErrInvalid
	}
	old, err := history.GetByEpoch(ctx, q.Epoch-1)
	if err != nil {
		return fmt.Errorf("old epoch %d unavailable: %w", q.Epoch-1, err)
	}
	conf := q.Context.FullShardConfHash[:]
	if confForEpoch != nil {
		epoch, ok := snapshotShardEpoch(bundle, q.Context.PartitionID, q.Context.ShardID)
		if !ok {
			return fmt.Errorf("%w: the snapshot does not hold this shard", handoffdelivery.ErrBundle)
		}
		installed, ok := confForEpoch(epoch)
		if !ok || len(installed) != len(conf) {
			return fmt.Errorf("%w: shard epoch %d", ErrBundleConfEpochUnknown, epoch)
		}
		conf = installed
	}
	if _, err := handoffdelivery.Verify(bundle, old, q.Context.PartitionID, q.Context.ShardID, conf); err != nil {
		return err
	}
	return nil
}

// snapshotShardEpoch is the shard epoch the bundle snapshot's technical record names for the shard. It only selects which installed
// hash to expect; Verify then requires the snapshot to carry exactly that hash, so a wrong claim is refused, not trusted.
func snapshotShardEpoch(b handoffdelivery.Bundle, partition types.PartitionID, shard types.ShardID) (uint64, bool) {
	if b.Snapshot == nil {
		return 0, false
	}
	for i := range b.Snapshot.ShardInfo {
		if e := &b.Snapshot.ShardInfo[i]; e.Partition == partition && e.Shard.Equal(shard) {
			return e.IRTR.Epoch, true
		}
	}
	return 0, false
}

func BundleAdmission(history BundleHistory, confForEpoch func(uint64) ([]byte, bool)) BundleVerifier {
	return func(ctx context.Context, q archive.BundleRequest, raw []byte) error {
		return VerifyBundle(ctx, q, raw, history, confForEpoch)
	}
}
