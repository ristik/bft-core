package q3active_test

import (
	"context"
	"crypto"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/q3active"
	"github.com/unicitynetwork/bft-go-base/types"
)

// countingCandidates serves retained candidates and counts the loads.
type countingCandidates struct {
	m     map[string][]byte
	loads int
}

func (c *countingCandidates) HandoffCandidate(id []byte) ([]byte, error) {
	c.loads++
	return c.m[string(id)], nil
}

// activated is a runtime whose verified history holds a coupled first activation followed by root-only ones, epochs in all.
func activated(t *testing.T, epochs int) (*q3active.Runtime, *q3fixture.Fixture, *countingCandidates, *q3fixture.Fixture) {
	t.Helper()
	ctx := context.Background()
	first := q3fixture.New(t, q3fixture.Options{Assignment: true})
	p := newProcess(t, first)
	rt := p.start()
	require.NoError(t, rt.Recover(ctx))
	require.NoError(t, rt.Activate(ctx, p.bundle()))
	prev := first
	for e := 3; e <= epochs; e++ {
		next := q3fixture.New(t, q3fixture.Options{After: prev})
		l, c := evidenceOf(next)
		b, err := rt.BundleFor(l, next.Snapshot, c)
		require.NoError(t, err)
		require.NoError(t, rt.Activate(ctx, b))
		prev = next
	}
	require.EqualValues(t, epochs, rt.History().Tip().Epoch())
	id := first.Body.Identity()
	return rt, first, &countingCandidates{m: map[string][]byte{string(id[:]): first.Candidate}}, prev
}

// Every installed epoch is derived once: repeated resolutions load no candidate again, a later activation derives only its own epoch,
// and Invalidate (recovery) derives the chain again from the anchor, to the same chain.
func TestRequestHistoryDerivesEachEpochOnce(t *testing.T) {
	ctx := context.Background()
	rt, first, cands, tip := activated(t, 3)
	hist, err := rt.RequestHistory(q3active.RequestHistoryConfig{Candidates: cands, HashAlg: crypto.SHA256, Network: q3fixture.Network, Version: 1,
		Anchor: anchorOf(first.ShardConf)})
	require.NoError(t, err)
	partition := q3fixture.PartitionID + 1
	chain, err := hist.Chain(partition, types.ShardID{})
	require.NoError(t, err)
	require.Len(t, chain, 3)
	require.Equal(t, 1, cands.loads, "the coupled epoch's candidate is loaded once")
	for range 5 {
		again, err := hist.Chain(partition, types.ShardID{})
		require.NoError(t, err)
		require.Len(t, again, 3)
	}
	require.Equal(t, 1, cands.loads, "a repeated resolution derives nothing")

	// a later root-only activation extends the chain by its own epoch alone
	tipFixture := q3fixture.New(t, q3fixture.Options{After: tip})
	l, c := evidenceOf(tipFixture)
	b, err := rt.BundleFor(l, tipFixture.Snapshot, c)
	require.NoError(t, err)
	require.NoError(t, rt.Activate(ctx, b))
	extended, err := hist.Chain(partition, types.ShardID{})
	require.NoError(t, err)
	require.Len(t, extended, 4)
	require.Equal(t, 1, cands.loads, "the root-only extension loads no candidate and re-derives no earlier epoch")
	for i := range chain {
		require.Equal(t, chain[i].RootBody(), extended[i].RootBody(), "the derived prefix is kept")
	}

	hist.Invalidate()
	rebuilt, err := hist.Chain(partition, types.ShardID{})
	require.NoError(t, err)
	require.Equal(t, 2, cands.loads, "after recovery the chain is derived again from the anchor")
	require.Len(t, rebuilt, 4)
	for i := range rebuilt {
		require.Equal(t, extended[i].RootBody(), rebuilt[i].RootBody())
		require.Equal(t, extended[i].PDRHash(), rebuilt[i].PDRHash())
	}
}
