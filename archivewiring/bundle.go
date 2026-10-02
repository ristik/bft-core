package archivewiring

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"

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

// RetainBundle keeps a verified handoff bundle in the local store.
//
// Under a key that already holds different bytes, BOTH copies are verified first and then compared by what they commit to
// (handoffdelivery.SameHandoff): the same handoff with a different signature subset or entry order keeps the first copy and succeeds
// (stored is false); a semantically different one is ErrBundleConflict, logged loudly, because that is evidence of equivocation or a bug
// and is never absorbed. The incoming bytes must already have been verified by the caller; they are verified again only on this path.
func RetainBundle(ctx context.Context, store *archive.Store, q archive.BundleRequest, raw []byte, verify BundleVerifier, log *slog.Logger) (bool, error) {
	if log == nil {
		log = slog.Default()
	}
	stored, err := store.PutBundle(q, raw, func(existing, incoming []byte) (bool, error) {
		if verify == nil {
			return false, ErrConfig
		}
		if err := verify(ctx, q, existing); err != nil {
			return false, fmt.Errorf("%w: retained bundle: %w", ErrBundleUnverified, err)
		}
		if err := verify(ctx, q, incoming); err != nil {
			return false, fmt.Errorf("%w: incoming bundle: %w", ErrBundleUnverified, err)
		}
		return handoffdelivery.SameHandoff(existing, incoming)
	})
	switch {
	case errors.Is(err, archive.ErrBundleConflict):
		log.ErrorContext(ctx, "CONFLICTING HANDOFF BUNDLE: a verified bundle differs semantically from the verified one already retained for this epoch; refusing it (equivocation or a bug)", "epoch", q.Epoch)
	case err == nil && !stored:
		log.DebugContext(ctx, "handoff bundle already retained; keeping the first copy", "epoch", q.Epoch)
	}
	return stored, err
}

// SameBundle reports whether two verified bundles, fetched back from a replica or held locally, are the same handoff.
func SameBundle(ctx context.Context, q archive.BundleRequest, verify BundleVerifier, a, b []byte) (bool, error) {
	if bytes.Equal(a, b) {
		return true, nil
	}
	if verify == nil {
		return false, ErrConfig
	}
	if err := verify(ctx, q, a); err != nil {
		return false, err
	}
	if err := verify(ctx, q, b); err != nil {
		return false, err
	}
	return handoffdelivery.SameHandoff(a, b)
}

// ErrBundleUnverified is a bundle (the retained copy or the incoming one) that did not verify when the two were to be compared.
var ErrBundleUnverified = errors.New("archivewiring: a handoff bundle did not verify for comparison")

// RetainActivatedBundle is RetainBundle for the node's own activation of a handoff it has verified. The node activates from the verified
// bundle in hand, so a replica-side problem with the archive copy must never stop it: a conflicting or unverifiable second copy is logged
// (loudly, for a conflict) and the activation goes on. Only a fault of the local store itself (I/O, corruption) is returned, and that is
// the one case in which the node may stop.
func RetainActivatedBundle(ctx context.Context, store *archive.Store, q archive.BundleRequest, raw []byte, verify BundleVerifier, log *slog.Logger) error {
	if log == nil {
		log = slog.Default()
	}
	_, err := RetainBundle(ctx, store, q, raw, verify, log)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, archive.ErrBundleConflict):
		return nil // already logged as a conflict
	case errors.Is(err, ErrBundleUnverified):
		log.WarnContext(ctx, "could not compare the retained handoff bundle with the verified one; keeping the retained copy and activating from the verified bundle", "epoch", q.Epoch, "err", err)
		return nil
	default:
		return err
	}
}
