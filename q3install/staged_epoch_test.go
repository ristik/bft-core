package q3install

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/keyvaluedb"
)

// scanCounter counts full-journal scans (iterator opens) on the shared db.
type scanCounter struct {
	keyvaluedb.KeyValueDB
	scans *atomic.Int64
}

func (d scanCounter) First() keyvaluedb.Iterator { d.scans.Add(1); return d.KeyValueDB.First() }

// The mirror's lookup of one staged activation is one indexed read: no journal scan, no journal lock (it answers while an activation
// holds the lock), the same answer for a large journal as for a small one, nothing for a missing or far-future epoch, and a cancelled
// request does no work. Concurrent activations meanwhile complete normally.
func TestStagedEpochIsAnIndexedLockFreeRead(t *testing.T) {
	const epochs = 400
	s := newStores()
	j := s.mustOpen(t)
	for e := uint64(2); e < epochs; e++ {
		c := claim(e)
		require.NoError(t, j.Install(ctx, c, bundleFor(c)))
	}
	var scans atomic.Int64
	reader := &Journal{cfg: j.cfg}
	reader.cfg.DB = scanCounter{KeyValueDB: j.cfg.DB, scans: &scans}

	a, ok, err := reader.StagedEpoch(ctx, 7)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, claim(7), a.Claim)
	require.Equal(t, bundleFor(claim(7)), a.Bundle)
	for _, missing := range []uint64{0, 1, epochs + 5, ^uint64(0)} {
		_, ok, err := reader.StagedEpoch(ctx, missing)
		require.NoError(t, err)
		require.False(t, ok, "epoch %d", missing)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	_, _, err = reader.StagedEpoch(cancelled, 7)
	require.ErrorIs(t, err, context.Canceled)
	require.Zero(t, scans.Load(), "no lookup scans the journal")

	// an activation holds the journal lock: the lookup still answers
	j.mu.Lock()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, ok, err := j.StagedEpoch(ctx, 9)
		require.NoError(t, err)
		require.True(t, ok)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the lookup waited for the activation lock")
	}
	j.mu.Unlock()

	// concurrent readers while activations continue
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_, _, err := j.StagedEpoch(ctx, 3)
				require.NoError(t, err)
				_, _, _ = j.StagedEpoch(ctx, 1<<40)
			}
		}()
	}
	for e := uint64(epochs); e < epochs+20; e++ {
		c := claim(e)
		require.NoError(t, j.Install(ctx, c, bundleFor(c)))
	}
	close(stop)
	wg.Wait()
	_, ok, err = j.StagedEpoch(ctx, epochs+19)
	require.NoError(t, err)
	require.True(t, ok)
}
