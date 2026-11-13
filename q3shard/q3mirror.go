package q3shard

import (
	"context"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-core/q3active"
)

// StagedBundles is the part of the shard's q3active.Runtime a mirror serves from: the activations its journal staged, exactly as staged.
type StagedBundles interface {
	StagedBundle(epoch uint64) (q3active.Bundle, bool, error)
}

// ErrNotMirrored is returned for an epoch this node holds no staged activation of.
var ErrNotMirrored = errors.New("q3 mirror: activation not staged here")

// MirrorProvider serves this shard node's staged activation bundles over q3delivery, so that non-active parties (joiners, syncing replicas,
// external followers) obtain activation evidence from shard nodes and never from roots. It is read-only evidence: the bundle is served as the
// journal staged it, after this node's own verification, and every consumer verifies it again from its own pin. Serving it grants no
// archive-write, journal or consensus access.
type MirrorProvider struct {
	Runtime StagedBundles
}

// Q3Bundle implements q3delivery.Provider.
func (m MirrorProvider) Q3Bundle(_ context.Context, epoch uint64) (q3active.Bundle, error) {
	if m.Runtime == nil {
		return q3active.Bundle{}, ErrNotMirrored
	}
	b, ok, err := m.Runtime.StagedBundle(epoch)
	if err != nil {
		return q3active.Bundle{}, fmt.Errorf("%w: epoch %d: %v", ErrNotMirrored, epoch, err)
	}
	if !ok {
		return q3active.Bundle{}, fmt.Errorf("%w: epoch %d", ErrNotMirrored, epoch)
	}
	return b, nil
}
