package q3shard

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/q3active"
	"github.com/unicitynetwork/bft-core/q3format"
)

type fakeActivator struct {
	mu        sync.Mutex
	active    uint64
	activated []uint64
	refuse    map[string]bool // bundles tagged by their Candidate byte
	stall     bool            // Activate returns nil without advancing
}

func (a *fakeActivator) Activate(_ context.Context, b q3active.Bundle) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.refuse[string(b.Candidate)] {
		return errors.New("refused by the history")
	}
	if a.stall {
		return nil
	}
	a.active++
	a.activated = append(a.activated, a.active)
	return nil
}
func (a *fakeActivator) ActiveEpoch() uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.active
}
func (a *fakeActivator) Activated(uint64) (q3format.Entry, bool) { return q3format.Entry{}, false }

func ids(t *testing.T, n int) []peer.ID {
	t.Helper()
	out := make([]peer.ID, n)
	for i := range out {
		out[i] = peer.ID(string(rune('a' + i)))
	}
	return out
}

func TestQ3FollowerActivatesTheFirstBundleTheRuntimeAcceptsAndNeverTrustsAPeer(t *testing.T) {
	roots := ids(t, 3)
	act := &fakeActivator{active: 1, refuse: map[string]bool{"bad": true}}
	var asked []peer.ID
	f := &Q3Follower{Runtime: act, AnchorEpoch: 1, CurrentRoots: roots[:2], OldRoots: func(context.Context, uint64) []peer.ID { return roots[2:] },
		Fetch: func(_ context.Context, id peer.ID, epoch uint64) (q3active.Bundle, error) {
			asked = append(asked, id)
			switch id {
			case roots[0]:
				return q3active.Bundle{}, errors.New("not committed here")
			case roots[1]:
				return q3active.Bundle{Candidate: []byte("bad")}, nil // served, but the history refuses it
			}
			return q3active.Bundle{Candidate: []byte("good")}, nil
		}}
	require.NoError(t, f.CatchUp(context.Background(), 2))
	require.Equal(t, []peer.ID{roots[0], roots[1], roots[2]}, asked, "current roots first, then the old committee's")
	require.Equal(t, []uint64{2}, act.activated)
}

func TestQ3FollowerCatchUpWalksEveryEpochAndFailsOnTheFirstItCannotHave(t *testing.T) {
	roots := ids(t, 1)
	act := &fakeActivator{active: 1}
	f := &Q3Follower{Runtime: act, AnchorEpoch: 1, CurrentRoots: roots,
		Fetch: func(_ context.Context, _ peer.ID, epoch uint64) (q3active.Bundle, error) {
			if epoch > 3 {
				return q3active.Bundle{}, errors.New("not yet")
			}
			return q3active.Bundle{}, nil
		}}
	require.NoError(t, f.CatchUp(context.Background(), 3))
	require.Equal(t, []uint64{2, 3}, act.activated)

	err := f.CatchUp(context.Background(), 4)
	require.ErrorIs(t, err, ErrQ3Unavailable)
	require.Contains(t, err.Error(), "epoch 4")
	require.Equal(t, []uint64{2, 3}, act.activated, "nothing past the epoch that could not be had")

	require.NoError(t, f.CatchUp(context.Background(), 3), "already there: nothing to fetch")
}

func TestQ3FollowerRefusesAnActivationThatLeavesTheEpochInactive(t *testing.T) {
	act := &fakeActivator{active: 1, stall: true}
	f := &Q3Follower{Runtime: act, AnchorEpoch: 1, CurrentRoots: ids(t, 1),
		Fetch: func(context.Context, peer.ID, uint64) (q3active.Bundle, error) { return q3active.Bundle{}, nil }}
	require.ErrorIs(t, f.CatchUp(context.Background(), 2), ErrQ3Unavailable)
}

func TestQ3FollowerRunWaitsForTheNextBundleAndStopsOnCancel(t *testing.T) {
	act := &fakeActivator{active: 1}
	var mu sync.Mutex
	available := false
	f := &Q3Follower{Runtime: act, AnchorEpoch: 1, CurrentRoots: ids(t, 1), Retry: 5 * time.Millisecond,
		Fetch: func(_ context.Context, _ peer.ID, epoch uint64) (q3active.Bundle, error) {
			mu.Lock()
			defer mu.Unlock()
			if epoch == 2 && available {
				return q3active.Bundle{}, nil
			}
			return q3active.Bundle{}, errors.New("not committed yet")
		}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- f.Run(ctx) }()
	time.Sleep(30 * time.Millisecond)
	require.EqualValues(t, 1, act.ActiveEpoch(), "nothing is activated before a root serves it")
	mu.Lock()
	available = true
	mu.Unlock()
	require.Eventually(t, func() bool { return act.ActiveEpoch() == 2 }, time.Second, 5*time.Millisecond)
	cancel()
	require.NoError(t, <-done)

	require.ErrorIs(t, (*Q3Follower)(nil).CatchUp(context.Background(), 2), ErrQ3FollowerConfig)
	require.ErrorIs(t, (&Q3Follower{Runtime: act}).Run(context.Background()), ErrQ3FollowerConfig)
}

// A non-active node (joiner, syncing replica, external follower) takes activation evidence from mirrors only: a root is never dialled, even
// when every mirror fails. This is the transport boundary: Fetch is the only way the follower reaches a peer.
func TestQ3FollowerNonActiveNeverAsksARoot(t *testing.T) {
	all := ids(t, 5)
	roots, old, mirrors := all[:2], all[2:3], all[3:]
	isRoot := map[peer.ID]bool{roots[0]: true, roots[1]: true, old[0]: true}
	act := &fakeActivator{active: 1, refuse: map[string]bool{"forged": true}}
	var asked []peer.ID
	f := &Q3Follower{Runtime: act, AnchorEpoch: 1, CurrentRoots: roots, OldRoots: func(context.Context, uint64) []peer.ID { return old },
		Mirrors: func() []peer.ID { return mirrors }, NonActive: func() bool { return true },
		Fetch: func(_ context.Context, id peer.ID, epoch uint64) (q3active.Bundle, error) {
			require.False(t, isRoot[id], "a non-active node dialled root %s", id)
			asked = append(asked, id)
			if id == mirrors[0] {
				return q3active.Bundle{Candidate: []byte("forged")}, nil // a mirror serving bytes the history refuses
			}
			return q3active.Bundle{Candidate: []byte("good")}, nil
		}}
	require.NoError(t, f.CatchUp(context.Background(), 2))
	require.Equal(t, []peer.ID{mirrors[0], mirrors[1]}, asked, "a refused mirror is followed by the next mirror")
	require.Equal(t, []uint64{2}, act.activated)

	// every mirror unavailable: the follower fails rather than falling back to a root
	asked = nil
	f.Fetch = func(_ context.Context, id peer.ID, _ uint64) (q3active.Bundle, error) {
		require.False(t, isRoot[id], "a non-active node dialled root %s", id)
		asked = append(asked, id)
		return q3active.Bundle{}, errors.New("not staged here")
	}
	err := f.CatchUp(context.Background(), 3)
	require.ErrorIs(t, err, ErrQ3Unavailable)
	require.Equal(t, mirrors, asked)
}

// An active node asks the roots first (the fastest path), then the old committee, then the mirrors as backup; each peer once per round.
func TestQ3FollowerActiveAsksRootsThenMirrors(t *testing.T) {
	all := ids(t, 4)
	roots, mirrors := all[:2], all[2:]
	act := &fakeActivator{active: 1}
	var asked []peer.ID
	f := &Q3Follower{Runtime: act, AnchorEpoch: 1, CurrentRoots: roots,
		Mirrors:   func() []peer.ID { return append([]peer.ID{roots[1]}, mirrors...) }, // a peer listed twice is asked once
		NonActive: func() bool { return false },
		Fetch: func(_ context.Context, id peer.ID, _ uint64) (q3active.Bundle, error) {
			asked = append(asked, id)
			if id != mirrors[1] {
				return q3active.Bundle{}, errors.New("unavailable")
			}
			return q3active.Bundle{Candidate: []byte("good")}, nil
		}}
	require.NoError(t, f.CatchUp(context.Background(), 2))
	require.Equal(t, []peer.ID{roots[0], roots[1], mirrors[0], mirrors[1]}, asked)
}

type stagedRuntime map[uint64]q3active.Bundle

func (s stagedRuntime) StagedBundleAt(_ context.Context, epoch uint64) (q3active.Bundle, bool, error) {
	b, ok := s[epoch]
	return b, ok, nil
}

func TestMirrorProviderServesOnlyStagedActivations(t *testing.T) {
	staged := q3active.Bundle{Envelope: []byte{1}, Candidate: []byte("c")}
	m := MirrorProvider{Runtime: stagedRuntime{2: staged}}
	got, err := m.Q3Bundle(context.Background(), 2)
	require.NoError(t, err)
	require.Equal(t, staged, got, "served exactly as staged")
	_, err = m.Q3Bundle(context.Background(), 3)
	require.ErrorIs(t, err, ErrNotMirrored)
	_, err = MirrorProvider{}.Q3Bundle(context.Background(), 2)
	require.ErrorIs(t, err, ErrNotMirrored)
}
