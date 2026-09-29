package archivewiring

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/archive"
)

type captureReceiptSource struct{ called [][32]byte }

func (s *captureReceiptSource) GetBlockReceipts(_ context.Context, hash [32]byte) ([][]byte, error) {
	s.called = append(s.called, hash)
	return [][]byte{}, nil
}

type failingReceiptSource struct{ err error }

func (s failingReceiptSource) GetBlockReceipts(context.Context, [32]byte) ([][]byte, error) {
	return nil, s.err
}

func TestPublisherCapturesReceiptsByExactCertifiedHash(t *testing.T) {
	f := newWiringFixture(t, 1)
	source := &captureReceiptSource{}
	p := &Publisher{Context: f.context, Subject: f.subject, ReceiptSource: source}
	q, rec, err := p.fromJournal(context.Background(), f.entries[0])
	require.NoError(t, err)
	require.Equal(t, [][32]byte{q.BlockHash}, source.called)
	require.True(t, archive.HasReceiptList(rec))
	receipts, err := DecodeReceiptList(rec)
	require.NoError(t, err)
	require.Empty(t, receipts)
}

func TestPublisherReportsReceiptCaptureUnavailableForRetry(t *testing.T) {
	f := newWiringFixture(t, 1)
	q, rec := f.record(t, 0)
	local, err := archive.Open(t.TempDir())
	require.NoError(t, err)
	require.NoError(t, local.Put(q, receiptFreeCopy(rec)))
	p := &Publisher{
		Journal: f.store, Context: f.context, JournalLimits: f.limits,
		Archive: local, Subject: f.subject,
		ReceiptSource: failingReceiptSource{err: errors.New("execution RPC unavailable")},
	}

	err = p.pass(context.Background())
	require.ErrorIs(t, err, archive.ErrUnavailable)
	_, err = local.GetReceiptComplete(q)
	require.ErrorIs(t, err, archive.ErrUnavailable, "the v1 record remains while a later pass retries receipt capture")
	got, err := local.Get(q)
	require.NoError(t, err)
	require.False(t, archive.HasReceiptList(got), "v1 remains immutable")
}
