package archivewiring

import (
	"context"
	"fmt"

	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/handoffdelivery"
	"github.com/unicitynetwork/bft-go-base/types"
)

type BundleHistory interface {
	GetByEpoch(context.Context, uint64) (*types.RootTrustBaseV1, error)
}

// VerifyBundle is shared by local publication and replica admission. Archive
// bytes never supply a trust anchor; every epoch uses installed history.
func VerifyBundle(ctx context.Context, q archive.BundleRequest, raw []byte, history BundleHistory) error {
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
	if _, err := handoffdelivery.Verify(bundle, old, q.Context.PartitionID, q.Context.ShardID, q.Context.FullShardConfHash[:]); err != nil {
		return err
	}
	return nil
}

func BundleAdmission(history BundleHistory) BundleVerifier {
	return func(ctx context.Context, q archive.BundleRequest, raw []byte) error {
		return VerifyBundle(ctx, q, raw, history)
	}
}
