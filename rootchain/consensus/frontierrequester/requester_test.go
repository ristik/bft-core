package frontierrequester

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/rootchain/consensus/frontierclient"
)

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time                            { return c.now }
func (c fixedClock) Wait(context.Context, time.Duration) error { return nil }

func TestAcquireRefusesConcurrentOwner(t *testing.T) {
	r := &Requester{running: true}
	result := r.Acquire(context.Background())
	require.ErrorIs(t, result.Err, ErrUnavailable)
}

func TestReceiptRejectsAnotherOwnerAndExpiredContext(t *testing.T) {
	a, b := &Requester{}, &Requester{}
	receipt := Receipt{owner: a, generation: 1}
	require.ErrorIs(t, b.Validate(receipt), ErrInvalidated)
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	require.True(t, contextExpired(ctx))
}

func TestReceiptExpiryAndReplacementInvalidateCopiesBeforeEvidenceAccess(t *testing.T) {
	now := time.Now()
	r := &Requester{process: context.Background(), caller: context.Background(), clock: fixedClock{now: now}, generation: 1}
	receipt := Receipt{owner: r, generation: 1, expires: now}
	r.receipt = receipt
	require.ErrorIs(t, r.Validate(receipt), ErrInvalidated)
	r.clock = fixedClock{now: now.Add(-time.Second)}
	r.generation = 2
	require.ErrorIs(t, r.Validate(receipt), ErrInvalidated)
}

// Owner §49: the committee may have 256 roots and bootstrap freshness passes every root of the trust base as a peer
// (configuredadmission.RootPeers), so the requester must accept as many peers as the frontier collector accepts roots.
func TestMaxPeersCoversTheLargestCommittee(t *testing.T) {
	require.Equal(t, frontierclient.MaxRoots, MaxPeers)
	require.GreaterOrEqual(t, MaxPeers, 256)
}
