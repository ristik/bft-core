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
}

type HandoffHistory interface {
	GetByEpoch(context.Context, uint64) (*types.RootTrustBaseV1, error)
	InstallHandoff(context.Context, handoffdelivery.Bundle, types.PartitionID, types.ShardID, []byte) (handoffdelivery.Verified, error)
}

func (f *HandoffFollower) Run(ctx context.Context) error {
	if f == nil || f.Host == nil || f.History == nil || f.AnchorEpoch == 0 || f.Directory == "" || len(f.ConfHash) != 32 {
		return errors.New("handoff follower: incomplete configuration")
	}
	if err := os.MkdirAll(f.Directory, 0700); err != nil {
		return err
	}
	for epoch := f.AnchorEpoch + 1; epoch > f.AnchorEpoch; epoch++ {
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
					verified, verifyErr := f.History.InstallHandoff(ctx, bundle, f.Partition, f.Shard, f.ConfHash)
					if verifyErr == nil {
						if err = f.save(epoch, bundle); err != nil {
							return err
						}
						if f.OnInstalled != nil {
							err = f.OnInstalled(ctx, bundle, verified)
						}
						if err == nil {
							break
						}
					}
				}
			} else {
				verified, verifyErr := f.History.InstallHandoff(ctx, bundle, f.Partition, f.Shard, f.ConfHash)
				if verifyErr != nil {
					return verifyErr
				}
				if f.OnInstalled != nil {
					if err := f.OnInstalled(ctx, bundle, verified); err != nil {
						return err
					}
				}
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
	try := func(id peer.ID, request func(context.Context, peer.ID, uint64) (handoffdelivery.Bundle, error)) (handoffdelivery.Bundle, bool) {
		bundle, err := request(ctx, id, epoch)
		if err == nil && bundle.Body.Epoch == epoch && bundle.Proof.Record.Epoch+1 == epoch {
			_, err = f.History.InstallHandoff(ctx, bundle, f.Partition, f.Shard, f.ConfHash)
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
	return handoffdelivery.Bundle{}, fmt.Errorf("handoff follower: epoch %d unavailable from current roots, old roots and archive replicas", epoch)
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
			bundle, err = f.fetch(ctx, epoch)
		}
		if err != nil {
			return nil, fmt.Errorf("epoch %d: %w", epoch, err)
		}
		verified, err := f.History.InstallHandoff(ctx, bundle, f.Partition, f.Shard, f.ConfHash)
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
		bundles[epoch] = bundle
		if epoch == ^uint64(0) {
			break
		}
	}
	return bundles, nil
}

func (f *HandoffFollower) path(epoch uint64) string {
	return filepath.Join(f.Directory, fmt.Sprintf("epoch-%d.cbor", epoch))
}

func (f *HandoffFollower) load(epoch uint64) (handoffdelivery.Bundle, error) {
	var bundle handoffdelivery.Bundle
	raw, err := os.ReadFile(f.path(epoch))
	if err != nil {
		return bundle, err
	}
	if len(raw) == 0 || len(raw) > 64<<20 || types.Cbor.Unmarshal(raw, &bundle) != nil || bundle.Body.Epoch != epoch {
		return handoffdelivery.Bundle{}, handoffdelivery.ErrBundle
	}
	return bundle, nil
}

func (f *HandoffFollower) save(epoch uint64, bundle handoffdelivery.Bundle) error {
	raw, err := types.Cbor.Marshal(bundle)
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
