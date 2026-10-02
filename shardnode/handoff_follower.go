package shardnode

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/unicitynetwork/bft-core/handoffdelivery"
	"github.com/unicitynetwork/bft-go-base/types"
)

// ErrHandoffPeerNotReady is the refusal of an archive replica that would serve a handoff bundle but does not yet authorize this node:
// the retained validator has not installed the assignment step that admits a joiner (the joiner's restore reached it first). It is
// the only refusal CatchUp retries; the caller maps its transport's refusal onto it (the archive wiring's ErrPeerNotAllowed).
var ErrHandoffPeerNotReady = errors.New("handoff follower: an archive replica has not installed the assignment step that admits this node yet")

// ErrHandoffSourceUnavailable is a handoff epoch that no current root, old root or archive replica could serve at all (as opposed to
// a replica that answered that it has not installed the assignment step yet, ErrHandoffPeerNotReady).
var ErrHandoffSourceUnavailable = errors.New("handoff follower: no bundle source could serve the epoch")

// bundleSourceUnavailable carries the historical message text for ErrHandoffSourceUnavailable.
type bundleSourceUnavailable struct{ epoch uint64 }

func (e *bundleSourceUnavailable) Error() string {
	return fmt.Sprintf("handoff follower: epoch %d unavailable from current roots, old roots and archive replicas", e.epoch)
}

func (e *bundleSourceUnavailable) Unwrap() error { return ErrHandoffSourceUnavailable }

// BundleRetry bounds the wait of CatchUp for a replica that refuses with ErrHandoffPeerNotReady: exponential backoff from Initial to
// Max, giving up after Total with an error that wraps the sentinel. The zero value is DefaultBundleRetry. (The same shape as the
// archive restore's FetchRetry, which lives in archivewiring and cannot be imported here.)
type BundleRetry struct {
	Initial time.Duration
	Max     time.Duration
	Total   time.Duration
}

// DefaultBundleRetry waits up to 90 s: a retained validator polls the roots every second, so it installs a step within seconds of the
// bundle being served.
var DefaultBundleRetry = BundleRetry{Initial: 200 * time.Millisecond, Max: 5 * time.Second, Total: 90 * time.Second}

// HandoffFollower fetches the next committed proof and full checkpoint from
// current root peers, old root peers, then configured archive replicas.
// Old peers are chosen from verified trust history;
// every response is checked before entering local lineage or snapshot storage.
type HandoffFollower struct {
	Host            handoffdelivery.Host
	History         HandoffHistory
	Partition       types.PartitionID
	Shard           types.ShardID
	ConfHash        []byte
	AnchorEpoch     uint64
	Directory       string
	OnInstalled     func(context.Context, handoffdelivery.Bundle, handoffdelivery.Verified) error
	CurrentRoots    []peer.ID
	ArchiveReplicas []peer.ID
	FetchArchive    func(context.Context, peer.ID, uint64) (handoffdelivery.Bundle, error)
	// Retry bounds CatchUp's wait for archive replicas that have not installed the assignment step yet (zero: DefaultBundleRetry).
	Retry BundleRetry

	// active is the shard configuration hash the root certifies at the epoch being followed: ConfHash (the genesis
	// configuration) until a verified EVM assignment step activates another. Every handoff snapshot is checked against
	// it, never against the genesis hash, so rotations and supersessions after the first keep verifying.
	active   []byte
	replayed bool
}

func (f *HandoffFollower) expected() []byte {
	if len(f.active) == 32 {
		return f.active
	}
	return f.ConfHash
}

func (f *HandoffFollower) advance(v handoffdelivery.Verified) {
	if len(v.NextConfHash) == 32 {
		f.active = append([]byte(nil), v.NextConfHash...)
	}
}

type HandoffHistory interface {
	GetByEpoch(context.Context, uint64) (*types.RootTrustBaseV1, error)
	InstallHandoff(context.Context, handoffdelivery.Bundle, types.PartitionID, types.ShardID, []byte) (handoffdelivery.Verified, error)
}

// Restore replays durable handoffs before journal admission opens. A successor
// observation already on disk must never be checked while the active epoch is
// still at the original anchor after process restart.
func (f *HandoffFollower) Restore(ctx context.Context) error {
	if f == nil || f.History == nil || f.AnchorEpoch == 0 || f.Directory == "" || len(f.ConfHash) != 32 {
		return errors.New("handoff follower: incomplete configuration")
	}
	for epoch := f.AnchorEpoch + 1; epoch > f.AnchorEpoch; epoch++ {
		bundle, err := f.load(epoch)
		if errors.Is(err, os.ErrNotExist) {
			f.replayed = true
			return nil
		}
		if err != nil {
			return err
		}
		verified, err := f.History.InstallHandoff(ctx, bundle, f.Partition, f.Shard, f.expected())
		if err != nil {
			return err
		}
		if f.OnInstalled != nil {
			if err := f.OnInstalled(ctx, bundle, verified); err != nil {
				return err
			}
		}
		f.advance(verified)
	}
	return errors.New("handoff follower: epoch overflow")
}

func (f *HandoffFollower) Run(ctx context.Context) error {
	if f == nil || f.Host == nil || f.History == nil || f.AnchorEpoch == 0 || f.Directory == "" || len(f.ConfHash) != 32 {
		return errors.New("handoff follower: incomplete configuration")
	}
	if err := os.MkdirAll(f.Directory, 0700); err != nil {
		return err
	}
	start := f.AnchorEpoch
	if active, ok := f.History.(interface{ CurrentRootEpoch() (uint64, bool) }); ok {
		if epoch, ready := active.CurrentRootEpoch(); ready && epoch >= start {
			start = epoch
		}
	}
	if !f.replayed {
		// The followed configuration is derived from the durable handoffs; recompute it without repeating callbacks.
		for epoch := f.AnchorEpoch + 1; epoch <= start; epoch++ {
			bundle, err := f.load(epoch)
			if err != nil {
				break
			}
			old, err := f.History.GetByEpoch(ctx, bundle.Proof.Record.Epoch)
			if err != nil {
				return err
			}
			verified, err := handoffdelivery.Verify(bundle, old, f.Partition, f.Shard, f.expected())
			if err != nil {
				return err
			}
			f.advance(verified)
		}
		f.replayed = true
	}
	for epoch := start + 1; epoch > start; epoch++ {
		for {
			if err := ctx.Err(); err != nil {
				return nil
			}
			bundle, err := f.load(epoch)
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			if errors.Is(err, os.ErrNotExist) {
				bundle, err = f.fetch(ctx, epoch)
				if err == nil {
					verified, verifyErr := f.History.InstallHandoff(ctx, bundle, f.Partition, f.Shard, f.expected())
					if verifyErr == nil {
						// Only a bundle Verify accepted in full is stored: a stored bundle is replayed on every restart, so
						// one that failed verification afterwards would wedge the node permanently. The callback follows
						// the save so a crash between them replays it.
						if err = f.save(epoch, bundle); err != nil {
							return err
						}
						if f.OnInstalled != nil {
							err = f.OnInstalled(ctx, bundle, verified)
						}
						if err == nil {
							f.advance(verified)
							break
						}
					}
				}
			} else {
				verified, verifyErr := f.History.InstallHandoff(ctx, bundle, f.Partition, f.Shard, f.expected())
				if verifyErr != nil {
					return verifyErr
				}
				if f.OnInstalled != nil {
					if err := f.OnInstalled(ctx, bundle, verified); err != nil {
						return err
					}
				}
				f.advance(verified)
				break
			}
			timer := time.NewTimer(time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil
			case <-timer.C:
			}
		}
	}
	return errors.New("handoff follower: epoch overflow")
}

func (f *HandoffFollower) fetch(ctx context.Context, epoch uint64) (handoffdelivery.Bundle, error) {
	old, err := f.History.GetByEpoch(ctx, epoch-1)
	if err != nil {
		return handoffdelivery.Bundle{}, err
	}
	notReady := false
	try := func(id peer.ID, request func(context.Context, peer.ID, uint64) (handoffdelivery.Bundle, error)) (handoffdelivery.Bundle, bool) {
		bundle, err := request(ctx, id, epoch)
		if errors.Is(err, ErrHandoffPeerNotReady) {
			notReady = true
		}
		if err == nil && bundle.Body.Epoch == epoch && bundle.Proof.Record.Epoch+1 == epoch {
			_, err = f.History.InstallHandoff(ctx, bundle, f.Partition, f.Shard, f.expected())
		} else {
			return handoffdelivery.Bundle{}, false
		}
		return bundle, err == nil
	}
	requestRoot := func(ctx context.Context, id peer.ID, epoch uint64) (handoffdelivery.Bundle, error) {
		return handoffdelivery.Request(ctx, f.Host, id, epoch)
	}
	for _, id := range f.CurrentRoots {
		if bundle, ok := try(id, requestRoot); ok {
			return bundle, nil
		}
	}
	for _, node := range old.RootNodes {
		if node == nil {
			continue
		}
		id, err := peer.Decode(node.NodeID)
		if err != nil {
			continue
		}
		if bundle, ok := try(id, requestRoot); ok {
			return bundle, nil
		}
	}
	if f.FetchArchive != nil {
		for _, id := range f.ArchiveReplicas {
			if bundle, ok := try(id, f.FetchArchive); ok {
				return bundle, nil
			}
		}
	}
	if notReady {
		return handoffdelivery.Bundle{}, fmt.Errorf("%w: epoch %d is unavailable from current roots and old roots, and an archive replica refused it", ErrHandoffPeerNotReady, epoch)
	}
	return handoffdelivery.Bundle{}, &bundleSourceUnavailable{epoch: epoch}
}

// fetchWithRetry is fetch for CatchUp: a refusal that says the replica has not installed the assignment step yet is retried with
// bounded backoff; every other failure is returned at once, as before.
func (f *HandoffFollower) fetchWithRetry(ctx context.Context, epoch uint64) (handoffdelivery.Bundle, error) {
	policy := f.Retry
	if policy == (BundleRetry{}) {
		policy = DefaultBundleRetry
	}
	started := time.Now()
	delay := policy.Initial
	for attempt := 1; ; attempt++ {
		bundle, err := f.fetch(ctx, epoch)
		if err == nil || !errors.Is(err, ErrHandoffPeerNotReady) {
			return bundle, err
		}
		remaining := policy.Total - time.Since(started)
		if remaining <= 0 {
			return handoffdelivery.Bundle{}, fmt.Errorf("%w: epoch %d still refused after %d attempts over %s: the retained validators have not installed the assignment step that admits this node (start joiners after the retained validators have activated, or rerun the restore on a fresh archive directory)",
				ErrHandoffPeerNotReady, epoch, attempt, policy.Total)
		}
		timer := time.NewTimer(min(delay, remaining))
		select {
		case <-ctx.Done():
			timer.Stop()
			return handoffdelivery.Bundle{}, ctx.Err()
		case <-timer.C:
		}
		delay = min(delay*2, policy.Max)
	}
}

// CatchUp walks every pinned boundary before an empty-disk restore begins.
func (f *HandoffFollower) CatchUp(ctx context.Context, target uint64) (map[uint64]handoffdelivery.Bundle, error) {
	if f == nil || f.Host == nil || f.History == nil || f.AnchorEpoch == 0 || target < f.AnchorEpoch || f.Directory == "" || len(f.ConfHash) != 32 {
		return nil, errors.New("handoff follower: incomplete restore configuration")
	}
	if err := os.MkdirAll(f.Directory, 0700); err != nil {
		return nil, err
	}
	bundles := make(map[uint64]handoffdelivery.Bundle)
	for epoch := f.AnchorEpoch + 1; epoch <= target; epoch++ {
		bundle, err := f.load(epoch)
		fetched := errors.Is(err, os.ErrNotExist)
		if fetched {
			bundle, err = f.fetchWithRetry(ctx, epoch)
		}
		if err != nil {
			return nil, fmt.Errorf("epoch %d: %w", epoch, err)
		}
		verified, err := f.History.InstallHandoff(ctx, bundle, f.Partition, f.Shard, f.expected())
		if err != nil {
			return nil, fmt.Errorf("epoch %d: %w", epoch, err)
		}
		if fetched {
			if err := f.save(epoch, bundle); err != nil {
				return nil, err
			}
		}
		if f.OnInstalled != nil {
			if err := f.OnInstalled(ctx, bundle, verified); err != nil {
				return nil, err
			}
		}
		f.advance(verified)
		bundles[epoch] = bundle
		if epoch == ^uint64(0) {
			break
		}
	}
	f.replayed = true
	return bundles, nil
}

func (f *HandoffFollower) path(epoch uint64) string {
	return filepath.Join(f.Directory, fmt.Sprintf("epoch-%d.cbor", epoch))
}

func (f *HandoffFollower) load(epoch uint64) (handoffdelivery.Bundle, error) {
	raw, err := os.ReadFile(f.path(epoch))
	if err != nil {
		return handoffdelivery.Bundle{}, err
	}
	if len(raw) == 0 || len(raw) > 64<<20 {
		return handoffdelivery.Bundle{}, handoffdelivery.ErrBundle
	}
	bundle, err := handoffdelivery.DecodeBundle(raw)
	if err != nil || bundle.Body.Epoch != epoch {
		return handoffdelivery.Bundle{}, handoffdelivery.ErrBundle
	}
	return bundle, nil
}

func (f *HandoffFollower) save(epoch uint64, bundle handoffdelivery.Bundle) error {
	raw, err := handoffdelivery.EncodeBundle(bundle)
	if err != nil || len(raw) == 0 || len(raw) > 64<<20 {
		return handoffdelivery.ErrBundle
	}
	file, err := os.CreateTemp(f.Directory, ".handoff-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err := file.Write(raw); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(file.Name(), f.path(epoch)); err != nil {
		return err
	}
	return syncDirectory(f.Directory)
}
