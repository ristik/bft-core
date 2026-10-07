package q3shard

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/unicitynetwork/bft-core/q3active"
	"github.com/unicitynetwork/bft-core/q3format"
)

// Q3Activator is the runtime a follower activates fetched bundles through.
type Q3Activator interface {
	Activate(ctx context.Context, b q3active.Bundle) error
	ActiveEpoch() uint64
	Activated(epoch uint64) (q3format.Entry, bool)
}

// Q3Follower fetches the activation bundle of the next root epoch from the current roots, then from the old committee's roots, and hands it to
// the shard node's own runtime. The runtime verifies it against the history this node rebuilt from the pinned genesis and installs it through
// the journal; the follower decides nothing about what is valid and trusts nothing a peer serves. The durable record of what was fetched is
// the journal's staged bundle, so a restart resumes through the runtime's recovery and there is no separate directory.
type Q3Follower struct {
	Runtime Q3Activator
	// AnchorEpoch is the epoch the node's pinned genesis trust base is (1).
	AnchorEpoch  uint64
	CurrentRoots []peer.ID
	// OldRoots resolves the committee of an epoch to peer ids, for a bundle the current roots do not serve. May be nil.
	OldRoots func(ctx context.Context, epoch uint64) []peer.ID
	// Fetch asks one root for the bundle of a successor epoch.
	Fetch func(ctx context.Context, root peer.ID, epoch uint64) (q3active.Bundle, error)
	// Retry is the pause between rounds of fetching a bundle no root serves yet; zero is one second.
	Retry time.Duration
}

// ErrQ3Unavailable is returned when no root served a bundle the runtime would activate.
var ErrQ3Unavailable = errors.New("q3 follower: no root served an activation the runtime accepts")

func (f *Q3Follower) current() uint64 {
	if e := f.Runtime.ActiveEpoch(); e >= f.AnchorEpoch {
		return e
	}
	return f.AnchorEpoch
}

// activate fetches the bundle of epoch from each source in turn and activates the first the runtime accepts. A bundle that is refused is
// not retried from the same peer in this round; the error of the last refusal is kept.
func (f *Q3Follower) activate(ctx context.Context, epoch uint64) error {
	var last error
	sources := append([]peer.ID(nil), f.CurrentRoots...)
	if f.OldRoots != nil {
		sources = append(sources, f.OldRoots(ctx, epoch-1)...)
	}
	for _, id := range sources {
		bundle, err := f.Fetch(ctx, id, epoch)
		if err != nil {
			last = err
			continue
		}
		if err := f.Runtime.Activate(ctx, bundle); err != nil {
			last = err
			continue
		}
		if f.Runtime.ActiveEpoch() < epoch {
			last = fmt.Errorf("epoch %d is not active after its activation", epoch)
			continue
		}
		return nil
	}
	return errors.Join(ErrQ3Unavailable, last)
}

// CatchUp activates every epoch after the current one up to target, each from the first root that serves one the runtime accepts, and fails
// as soon as one cannot be had. It is the restore path: a node with an empty disk rebuilds the whole history from the pinned genesis.
// ErrQ3FollowerConfig is returned when a follower is run without its runtime, its fetch or its anchor epoch.
var ErrQ3FollowerConfig = errors.New("q3 follower: incomplete configuration")

func (f *Q3Follower) CatchUp(ctx context.Context, target uint64) error {
	if f == nil || f.Runtime == nil || f.Fetch == nil || f.AnchorEpoch == 0 {
		return ErrQ3FollowerConfig
	}
	for epoch := f.current() + 1; epoch <= target; epoch++ {
		if err := f.activate(ctx, epoch); err != nil {
			return fmt.Errorf("epoch %d: %w", epoch, err)
		}
	}
	return nil
}

// Run follows the roots for as long as ctx lives: whenever the next epoch's bundle is available it is activated, otherwise the follower
// waits and asks again. It returns nil on cancellation.
func (f *Q3Follower) Run(ctx context.Context) error {
	if f == nil || f.Runtime == nil || f.Fetch == nil || f.AnchorEpoch == 0 {
		return ErrQ3FollowerConfig
	}
	pause := f.Retry
	if pause == 0 {
		pause = time.Second
	}
	for {
		if ctx.Err() != nil {
			return nil
		}
		if err := f.activate(ctx, f.current()+1); err == nil {
			continue
		}
		timer := time.NewTimer(pause)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}
