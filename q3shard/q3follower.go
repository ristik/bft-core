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
	// Mirrors are the non-root holders of activation evidence (active shard validators and archive replicas that serve their staged
	// bundles, see MirrorProvider). May be nil.
	Mirrors func() []peer.ID
	// NonActive reports whether this node is currently a non-active party (a joiner, a syncing replica, an external follower). A
	// non-active node takes activation evidence from mirrors only and never asks a root: roots and old roots are not even dialled. An
	// active node asks the roots first and falls back to the mirrors. Nil means active (the roots-first policy).
	NonActive func() bool
	// IsRoot, when set, names every known root identity (any verified epoch's committee). A non-active node never asks a peer it names,
	// nor a current or old root, even when that identity also appears in the mirror list. May be nil.
	IsRoot func(peer.ID) bool
	// Fetch asks one peer (a root or a mirror) for the bundle of a successor epoch.
	Fetch func(ctx context.Context, root peer.ID, epoch uint64) (q3active.Bundle, error)
	// Retry is the pause between rounds of fetching a bundle no root serves yet; zero is one second.
	Retry time.Duration
}

// ErrQ3Unavailable is returned when no root served a bundle the runtime would activate.
var ErrQ3Unavailable = errors.New("q3 follower: no source served an activation the runtime accepts")

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
	for _, id := range f.sources(ctx, epoch) {
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

// sources is the order in which the bundle of epoch is asked for: mirrors only for a non-active node, roots first then mirrors for an active
// one. A peer is asked at most once per round.
func (f *Q3Follower) sources(ctx context.Context, epoch uint64) []peer.ID {
	var roots []peer.ID
	roots = append(roots, f.CurrentRoots...)
	if f.OldRoots != nil {
		roots = append(roots, f.OldRoots(ctx, epoch-1)...)
	}
	if f.IsRoot != nil {
		// the configured lists are locators that may mix roots and shard peers (a generated node lists both as bootnodes): with authenticated
		// root identities available, only those are roots, and a listed shard peer is a mirror like any other
		authenticated := roots[:0]
		for _, id := range roots {
			if f.IsRoot(id) {
				authenticated = append(authenticated, id)
			}
		}
		roots = authenticated
	}
	nonActive := f.NonActive != nil && f.NonActive()
	var out []peer.ID
	if !nonActive {
		out = append(out, roots...)
	}
	if f.Mirrors != nil {
		out = append(out, f.Mirrors()...)
	}
	// role separation, not just deduplication: for a non-active node a root identity is never a source, whichever list names it. With
	// IsRoot that is every authenticated root identity; without it, every identity the root lists name.
	isRoot := f.IsRoot
	if isRoot == nil {
		listed := make(map[peer.ID]struct{}, len(roots))
		for _, id := range roots {
			listed[id] = struct{}{}
		}
		isRoot = func(id peer.ID) bool { _, ok := listed[id]; return ok }
	}
	seen := make(map[peer.ID]struct{}, len(out))
	unique := make([]peer.ID, 0, len(out))
	for _, id := range out {
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		if nonActive && isRoot(id) {
			continue
		}
		unique = append(unique, id)
	}
	return unique
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
