package archivewiring

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/archive"
)

type nullReceiptsNotReady struct{}

func (nullReceiptsNotReady) Error() string   { return "eth_getBlockReceipts returned null" }
func (nullReceiptsNotReady) Temporary() bool { return true }

type nullThenSuccessReceiptSource struct {
	calls atomic.Int32
	until int32
}

func (s *nullThenSuccessReceiptSource) GetBlockReceipts(context.Context, [32]byte) ([][]byte, error) {
	if s.calls.Add(1) <= s.until {
		return nil, nullReceiptsNotReady{}
	}
	return [][]byte{{0xc0}}, nil
}

type alwaysNullReceiptSource struct{ calls atomic.Int32 }

func (s *alwaysNullReceiptSource) GetBlockReceipts(context.Context, [32]byte) ([][]byte, error) {
	s.calls.Add(1)
	return nil, nullReceiptsNotReady{}
}

func TestCaptureBlockReceiptsRetriesNullUntilSuccess(t *testing.T) {
	source := &nullThenSuccessReceiptSource{until: 2}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()

	got, err := captureBlockReceipts(ctx, source, [32]byte{1})
	require.NoError(t, err)
	require.Equal(t, [][]byte{{0xc0}}, got)
	require.EqualValues(t, 3, source.calls.Load())
}

func TestPublisherDoesNotPublishReceiptsStillNullAfterBound(t *testing.T) {
	f := newWiringFixture(t, 1)
	local, err := archive.Open(t.TempDir())
	require.NoError(t, err)
	source := &alwaysNullReceiptSource{}
	p := &Publisher{
		Journal: f.store, Context: f.context, JournalLimits: f.limits,
		Archive: local, Subject: f.subject, ReceiptSource: source,
	}

	started := time.Now()
	err = p.pass(t.Context())
	require.ErrorIs(t, err, archive.ErrUnavailable)
	var retryable interface{ Temporary() bool }
	require.ErrorAs(t, err, &retryable)
	require.True(t, retryable.Temporary())
	require.GreaterOrEqual(t, time.Since(started), 5*time.Second)
	require.Less(t, time.Since(started), 6*time.Second)
	require.Greater(t, source.calls.Load(), int32(1))

	q, _ := f.record(t, 0)
	_, err = local.Get(q)
	require.ErrorIs(t, err, archive.ErrUnavailable)
}
