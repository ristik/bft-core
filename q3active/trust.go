package q3active

import (
	"bytes"
	"context"
	"fmt"

	"github.com/unicitynetwork/bft-core/internal/weightvalidation"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/trusthistorystore"
	"github.com/unicitynetwork/bft-go-base/types"
)

// TrustLookup is the method set every consumer of root trust takes (shardnode.TrustBaseStore, the handoff follower's history, the
// signing authority's TrustBases, certifiedstore, rootinput, archivewiring, the engine API's verifier context).
type TrustLookup interface {
	GetByEpoch(ctx context.Context, epoch uint64) (*types.RootTrustBaseV1, error)
}

// Guarded is a trust lookup that answers from the verified history. For an activated epoch it serves the history's own
// projection, and only once the journal has completed and recovered the activation: a signing authority, shard node or certificate
// consumer holding a Guarded cannot authenticate against weights that are not installed, and cannot be handed another committee by
// its base store. For a verified legacy epoch it serves its base lookup after checking that the base agrees with the history. An
// epoch the history does not hold is refused: a known trust base with absent protocol history never silently means scheme 1.
//
// A Guarded is also the validation ModeSource: certificate consumers select the weighted rules through it and nothing else.
type Guarded struct {
	rt   *Runtime
	base TrustLookup
}

// Trust is a lookup over this runtime's history. base serves the legacy epochs (nil: the history's projection is served for
// them too).
func (r *Runtime) Trust(base TrustLookup) *Guarded { return &Guarded{rt: r, base: base} }

// BoundTo reports whether the lookup belongs to the runtime.
func (g *Guarded) BoundTo(authority any) bool {
	rt, ok := authority.(*Runtime)
	return ok && rt != nil && rt == g.rt
}

func sameTrust(a, b *types.RootTrustBaseV1) bool {
	if a == nil || b == nil || a.NetworkID != b.NetworkID || a.Epoch != b.Epoch || a.EpochStart != b.EpochStart ||
		a.QuorumThreshold != b.QuorumThreshold || len(a.RootNodes) != len(b.RootNodes) {
		return false
	}
	for i, n := range a.RootNodes {
		m := b.RootNodes[i]
		if n == nil || m == nil || n.NodeID != m.NodeID || n.Stake != m.Stake || !bytes.Equal(n.SigKey, m.SigKey) {
			return false
		}
	}
	return true
}

// GetByEpoch is the trust base of a root epoch under the rules above.
func (g *Guarded) GetByEpoch(ctx context.Context, epoch uint64) (*types.RootTrustBaseV1, error) {
	e, err := g.rt.History().ForEpoch(epoch)
	if err != nil {
		return nil, err
	}
	if _, active := e.Config(); active {
		if err := g.rt.Admit(epoch); err != nil {
			return nil, err
		}
		return e.Projection(), nil
	}
	if g.base == nil {
		return e.Projection(), nil
	}
	tb, err := g.base.GetByEpoch(ctx, epoch)
	if err != nil {
		return nil, err
	}
	if !sameTrust(tb, e.Projection()) {
		return nil, fmt.Errorf("%w: epoch %d", ErrConflict, epoch)
	}
	return tb, nil
}

// Mode implements weightvalidation.ModeSource.
func (g *Guarded) Mode(epoch uint64) (weightvalidation.Mode, error) { return g.rt.Mode(epoch) }

// RootTrustBase is the epoch's trust base as the value a certificate verifier takes, carrying the validation mode of its epoch so
// that an offline consumer (mintproof) needs no flag.
func (g *Guarded) RootTrustBase(ctx context.Context, epoch uint64) (types.RootTrustBase, error) {
	tb, err := g.GetByEpoch(ctx, epoch)
	if err != nil {
		return nil, err
	}
	m, _ := g.rt.Mode(epoch) // it answers whenever the lookup does; an unset mode is the unit world
	return modeTrustBase{RootTrustBaseV1: tb, mode: m}, nil
}

type modeTrustBase struct {
	*types.RootTrustBaseV1
	mode weightvalidation.Mode
}

func (t modeTrustBase) ValidationMode() weightvalidation.Mode { return t.mode }

var _ weightvalidation.ModeSource = (*Guarded)(nil)

// Lineage is the recovery history of a runtime: the abdrc.HistoricalTrustBases a StateMsg is verified against. An epoch the verified
// Q3 history activated is served as its own exact-weight projection, only once the journal has completed its installation; every
// other epoch is the base lineage's record, after the history has checked the base agrees with it (the genesis epoch). An epoch
// the history does not hold is refused, never answered by the base alone.
type Lineage struct {
	rt   *Runtime
	base abdrc.HistoricalTrustBases
}

var _ abdrc.HistoricalTrustBases = (*Lineage)(nil)

// Lineage is the lineage view over this runtime's history, with base serving the genesis epoch.
func (r *Runtime) Lineage(base abdrc.HistoricalTrustBases) abdrc.HistoricalTrustBases {
	return &Lineage{rt: r, base: base}
}

// ByEpoch implements abdrc.HistoricalTrustBases.
func (l *Lineage) ByEpoch(epoch uint64) (trusthistorystore.Record, error) {
	e, err := l.rt.History().ForEpoch(epoch)
	if err != nil {
		return trusthistorystore.Record{}, err
	}
	if _, active := e.Config(); !active {
		if l.base == nil {
			return trusthistorystore.Record{}, trusthistorystore.ErrNotFound
		}
		rec, err := l.base.ByEpoch(epoch)
		if err != nil {
			return trusthistorystore.Record{}, err
		}
		if rec.V1 == nil || rec.V2 != nil || rec.Verified != nil || !sameTrust(rec.V1, e.Projection()) {
			return trusthistorystore.Record{}, fmt.Errorf("%w: epoch %d", ErrConflict, epoch)
		}
		return rec, nil
	}
	if err := l.rt.Admit(epoch); err != nil {
		return trusthistorystore.Record{}, err
	}
	rec := trusthistorystore.Record{Epoch: epoch, Start: e.Start(), BodyID: e.BodyID(), Verified: e.Projection()}
	if next, err := l.rt.History().ForEpoch(epoch + 1); err == nil {
		rec.End = next.Start()
	}
	return rec, nil
}
