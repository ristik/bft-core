package archivewiring

import (
	"context"
	"sync"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/configuredprogress"
	"github.com/unicitynetwork/bft-core/frontier"
	"github.com/unicitynetwork/bft-core/shardnode"
)

// advanceFixture: n certified blocks, all retained locally and on both replicas, finalized through n.
func advanceFixture(t *testing.T, n int) (*wiringFixture, *FrontierWorker) {
	t.Helper()
	f := newWiringFixtureWithLimits(t, n, configuredprogress.JournalLimits{Candidates: 64, Observations: 128, Bytes: 32 << 20})
	local, err := archive.Open(t.TempDir())
	require.NoError(t, err)
	first, err := archive.Open(t.TempDir())
	require.NoError(t, err)
	second, err := archive.Open(t.TempDir())
	require.NoError(t, err)
	var top shardnode.BlockRef
	for i, entry := range f.entries {
		q, rec := f.record(t, i)
		for _, s := range []*archive.Store{local, first, second} {
			require.NoError(t, s.Put(q, rec))
		}
		if entry.Candidate.Number > top.Number {
			top = shardnode.BlockRef{Number: entry.Candidate.Number, Hash: entry.Candidate.Hash}
		}
	}
	peers := []peer.ID{"first", "second"}
	policy := frontier.Policy{Context: f.subject, Replicas: [2]string{peers[0].String(), peers[1].String()}, Binding: CertifiedBinding{Context: f.context, Subject: f.subject},
		Availability: fixtureAvailability{stores: map[string]*archive.Store{peers[0].String(): first, peers[1].String(): second}}}
	require.NoError(t, f.store.EnableFrontier(context.Background(), f.context, f.limits, policy))
	return f, &FrontierWorker{Journal: f.store, Context: f.context, Limits: f.limits, Archive: local, Subject: f.subject, Replicas: peers,
		Finalized: func(context.Context) (shardnode.BlockRef, error) { return top, nil }}
}

func anchorHeight(t *testing.T, f *wiringFixture) uint64 {
	t.Helper()
	image, err := f.store.LoadJournal(context.Background(), f.context, f.limits)
	require.NoError(t, err)
	if image.Frontier == nil || image.Frontier.Anchor == nil {
		return 0
	}
	return image.Frontier.Anchor.Height
}

func TestFrontierAdvance_CoversUpToMaxWhereAPassCoversFour(t *testing.T) {
	t.Parallel()
	f, w := advanceFixture(t, 12)
	require.NoError(t, w.Pass(context.Background()))
	require.EqualValues(t, passCoverage, anchorHeight(t, f), "a worker pass is unchanged")
	require.NoError(t, w.Advance(context.Background(), 6))
	require.EqualValues(t, passCoverage+6, anchorHeight(t, f), "Advance covers max blocks in one call")
	require.NoError(t, w.Advance(context.Background(), 64))
	require.EqualValues(t, 12, anchorHeight(t, f), "and stops at the last coverable block")
	require.NoError(t, w.Advance(context.Background(), 64), "nothing left to cover is not an error")
	require.ErrorIs(t, w.Advance(context.Background(), 0), ErrConfig)
}

// TestFrontierAdvance_IsSerializedWithTheWorkersPasses: the worker's passes and a catch-up's Advance run at once (#769 rev2 R2); neither
// sees the other's commit as a stale plan, and together they reach the top.
func TestFrontierAdvance_IsSerializedWithTheWorkersPasses(t *testing.T) {
	t.Parallel()
	f, w := advanceFixture(t, 24)
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	wg.Add(2)
	go func() {
		defer wg.Done()
		for range 8 {
			errs <- w.Pass(context.Background())
		}
	}()
	go func() {
		defer wg.Done()
		for range 8 {
			errs <- w.Advance(context.Background(), 3)
		}
	}()
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	require.EqualValues(t, 24, anchorHeight(t, f))
}
