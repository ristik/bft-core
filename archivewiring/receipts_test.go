package archivewiring

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/archive"
)

type captureReceiptSource struct{ called [][32]byte }

func (s *captureReceiptSource) GetBlockReceipts(_ context.Context, hash [32]byte) ([][]byte, error) {
	s.called = append(s.called, hash)
	return [][]byte{}, nil
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
