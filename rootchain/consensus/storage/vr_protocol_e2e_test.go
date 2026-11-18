package storage_test

import (
	"context"
	"crypto"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	"github.com/unicitynetwork/bft-core/rootchain/vrschedule"
	"github.com/unicitynetwork/bft-core/rootchain/vrstate"
	"github.com/unicitynetwork/bft-core/vrhandoff"
)

// The staged protocol among four roots over the real executor (VT-05b PR B): every root runs a vrschedule.Service over the intent derived
// from the committed block, the successors send their PoPs and readiness, the committed view's assembler assembles. View 0's assembler is
// silent, so the next HandoffView commits (after its replay floor) and view 1's assembler assembles; the first complete certificate is the
// one every root plans, and its Prepare, Freeze v5 and H execute through the real executor.

type vxBus struct {
	f        *vxReal
	services map[string]*vrschedule.Service
	silent   map[string]bool
}

func (b *vxBus) deliver(from string, ms []vrschedule.Message) {
	for _, m := range ms {
		for id, s := range b.services {
			if id == from {
				continue
			}
			_, out, _ := s.Offer(from, m)
			b.deliver(id, out)
		}
	}
}

func (f *vxReal) committedAt(t *testing.T, b *storage.ExecutedBlock) vrschedule.Committed {
	q, err := storage.VRQueryForTest(b, f.orch, f.svc, f.auth)
	require.NoError(t, err)
	d, ok, err := f.p.Derive(q)
	require.NoError(t, err)
	s := rootState(t, b)
	c := vrschedule.Committed{Derived: d, Derivable: ok, Prepared: s.Backoff.Prepared, Incumbents: map[string][]byte{}, K: f.k, Table: s.Support}
	if ok && string(s.Backoff.Intent) == string(d.Digest[:]) {
		c.CommittedView = s.Backoff.LastView
	}
	for _, m := range f.kRoot {
		c.Incumbents[m.NodeID] = m.Key
	}
	return c
}

func (b *vxBus) update(t *testing.T, at *storage.ExecutedBlock) {
	c := b.f.committedAt(t, at)
	for id, s := range b.services {
		out := s.Update(c)
		if !b.silent[id] {
			b.deliver(id, out)
		}
	}
}

// members sends every successor's PoP, and, for every assembly of a view the services hold, every successor's readiness.
func (b *vxBus) members(t *testing.T, view uint64) {
	f := b.f
	for _, m := range f.j {
		for _, x := range f.members {
			if x.evm == m.EVMNodeID {
				p, err := vrhandoff.SignPoP(f.in, m, x.ek.signer)
				require.NoError(t, err)
				b.deliver("member", []vrschedule.Message{{PoP: &p}})
			}
		}
	}
	var a *vrhandoff.Assembly
	for _, s := range b.services {
		set, ok := s.Stage(f.d, view)
		if ok && len(set.Assemblies) > 0 {
			a = &set.Assemblies[len(set.Assemblies)-1]
		}
	}
	if a == nil {
		return
	}
	body, err := vrhandoff.DeriveBody(f.in, 1, sha256Of(a.Candidate), f.bc)
	require.NoError(t, err)
	_, tb, err := vrhandoff.TrustBase(f.in, 1)
	require.NoError(t, err)
	for _, m := range f.j {
		r, err := vrhandoff.SignReadiness(f.in, *a, body, m.RootNodeID, tb, nil, f.signer(m.StakingID).signer)
		require.NoError(t, err)
		b.deliver("member", []vrschedule.Message{{Readiness: &r}})
	}
}

func TestVRStagedProtocolThroughTheExecutor(t *testing.T) {
	f := newVXReal(t)
	ids := []string{}
	for _, m := range f.k {
		ids = append(ids, m.RootNodeID)
	}
	bus := &vxBus{f: f, services: map[string]*vrschedule.Service{}, silent: map[string]bool{vrhandoff.Assembler(f.d, ids, 0): true}}
	for _, m := range f.k {
		var signer = f.signer(m.StakingID).signer
		if bus.silent[m.RootNodeID] {
			signer = nil // view 0's assembler never assembles
		}
		bus.services[m.RootNodeID] = vrschedule.NewService(vrschedule.ServiceConfig{Self: m.RootNodeID, Signer: signer})
	}
	g := f.g
	bus.update(t, g)
	bus.members(t, 0)
	for _, s := range bus.services {
		_, ok := s.Plan()
		require.False(t, ok, "view 0's assembler is silent: no certificate")
	}

	// the next view commits once its replay floor has passed (openTime(0) = 950, T(0, 0) = 10 s)
	b1 := f.must(g, f.block(g, 11, 960, nil, f.view(11, 1)))
	bus.update(t, b1)
	bus.members(t, 1)
	var plan vrschedule.PreparePlan
	for id, s := range bus.services {
		p, ok := s.Plan()
		require.True(t, ok, "root %s holds the complete verified certificate of view 1", id)
		require.EqualValues(t, 1, p.Certificate.Assembly.Slot)
		if plan.Body.Network == 0 {
			plan = p
		}
		require.Equal(t, plan.Certificate.Assembly.Candidate, p.Certificate.Assembly.Candidate, "every root plans the same certificate")
	}

	// the leader's Prepare, Freeze v5 and H for it, judged by the real executor
	prepRaw, err := vrschedule.PrepareRecord(plan, b1.ShardState.Control, 12)
	require.NoError(t, err)
	prep := f.must(b1, f.block(b1, 12, 961, [][]byte{prepRaw}))
	bus.update(t, prep)
	for _, s := range bus.services {
		_, ok := s.Plan()
		require.False(t, ok, "a committed Prepare ends planning")
		_, ok = s.Prepared()
		require.True(t, ok)
	}
	witness, _, err := vrstate.BuildOutputWitness(context.Background(), f.world, f.pins, f.r)
	require.NoError(t, err)
	freeze, err := vrschedule.FreezeRecord(plan, prep.ShardState.Control, 13, witness)
	require.NoError(t, err)
	fz := f.must(prep, f.block(prep, 13, 962, freeze))
	require.Equal(t, "endorsed", fz.ShardState.Control.Phase)
	require.Equal(t, uint8(0), rootState(t, fz).Backoff.Level, "decLevel(0, 1, 4) = 0")
	_, _, v5, _, ok := storage.VRRetainedForTest(fz)
	require.True(t, ok)
	staged := rootState(t, fz).StagedBody
	f.candidates[string(staged[:])] = v5
	h, err := vrschedule.CommitRecord(plan, fz.ShardState.Control, 14, fz.ShardState.States[vxShard], crypto.SHA256)
	require.NoError(t, err)
	committed := f.must(fz, f.block(fz, 14, 963, [][]byte{h}))
	require.Equal(t, "committed", committed.ShardState.Control.Phase)

	// no root's view state holds equivocation evidence on this honest run
	for _, s := range bus.services {
		require.Empty(t, s.Evidence())
	}
}

func sha256Of(b []byte) [32]byte { return sha256.Sum256(b) }
