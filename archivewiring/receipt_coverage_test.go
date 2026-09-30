package archivewiring

import (
	"bytes"
	"context"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/frontier"
)

func receiptFreeCopy(rec *archive.Record) *archive.Record {
	cp := *rec
	cp.Extensions = make(map[string][]byte)
	for k, v := range rec.Extensions {
		if k != archive.ReceiptListKey {
			cp.Extensions[k] = bytes.Clone(v)
		}
	}
	return &cp
}

func TestCertifiedBindingRequiresReceiptCompleteV2(t *testing.T) {
	f := newWiringFixture(t, 1)
	q, rec := f.record(t, 0)
	var state [32]byte
	copy(state[:], f.entries[0].Candidate.StateRoot)
	anchor := frontier.Record{Sequence: 1, Round: f.entries[0].ResultingUC.GetRootRoundNumber(), Height: 1, StateRoot: state, Subject: q}
	err := (CertifiedBinding{Context: f.context, Subject: f.subject}).VerifyCertified(anchor, receiptFreeCopy(rec))
	require.ErrorIs(t, err, frontier.ErrInvalid, "a receipt-free v1 archive must never count as F7 coverage")
}

func TestFrontierDoesNotCoverReceiptFreeV1Record(t *testing.T) {
	t.Parallel()
	f := newWiringFixture(t, 1)
	local, err := archive.Open(t.TempDir())
	require.NoError(t, err)
	q, rec := f.record(t, 0)
	require.NoError(t, local.Put(q, receiptFreeCopy(rec)))
	first, err := archive.Open(t.TempDir())
	require.NoError(t, err)
	second, err := archive.Open(t.TempDir())
	require.NoError(t, err)
	peers := [2]peer.ID{"first", "second"}
	policy := frontier.Policy{Context: f.subject, Replicas: [2]string{peers[0].String(), peers[1].String()},
		Binding: CertifiedBinding{Context: f.context, Subject: f.subject}, Availability: fixtureAvailability{stores: map[string]*archive.Store{"first": first, "second": second}}}
	require.NoError(t, f.store.EnableFrontier(context.Background(), f.context, f.limits, policy))
	worker := &FrontierWorker{Journal: f.store, Context: f.context, Limits: f.limits, Archive: local, Subject: f.subject, Replicas: peers}
	require.ErrorIs(t, worker.Pass(context.Background()), archive.ErrUnavailable)
	image, err := f.store.LoadJournal(context.Background(), f.context, f.limits)
	require.NoError(t, err)
	require.Nil(t, image.Frontier, "missing receipts leave the record outside pruning coverage")
}

func TestPublisherUpgradesV1AndFrontierAdvances(t *testing.T) {
	t.Parallel()
	f := newWiringFixture(t, 1)
	local, err := archive.Open(t.TempDir())
	require.NoError(t, err)
	q, record := f.record(t, 0)
	require.NoError(t, local.Put(q, receiptFreeCopy(record)))
	_, err = local.GetReceiptComplete(q)
	require.ErrorIs(t, err, archive.ErrUnavailable)

	source := &captureReceiptSource{}
	publisher := &Publisher{
		Journal: f.store, Context: f.context, JournalLimits: f.limits,
		Archive: local, Subject: f.subject, ReceiptSource: source,
	}
	require.NoError(t, publisher.pass(context.Background()))
	require.Equal(t, [][32]byte{q.BlockHash}, source.called)
	upgraded, err := local.GetReceiptComplete(q)
	require.NoError(t, err)
	require.True(t, archive.HasReceiptList(upgraded))
	latest, err := local.Get(q)
	require.NoError(t, err)
	require.True(t, archive.HasReceiptList(latest), "new reads prefer the v2 record")

	first, err := archive.Open(t.TempDir())
	require.NoError(t, err)
	second, err := archive.Open(t.TempDir())
	require.NoError(t, err)
	require.NoError(t, first.Put(q, upgraded))
	require.NoError(t, second.Put(q, upgraded))
	peers := [2]peer.ID{"first", "second"}
	policy := frontier.Policy{
		Context:  f.subject,
		Replicas: [2]string{peers[0].String(), peers[1].String()},
		Binding:  CertifiedBinding{Context: f.context, Subject: f.subject},
		Availability: fixtureAvailability{stores: map[string]*archive.Store{
			peers[0].String(): first,
			peers[1].String(): second,
		}},
	}
	require.NoError(t, f.store.EnableFrontier(context.Background(), f.context, f.limits, policy))
	worker := &FrontierWorker{
		Journal: f.store, Context: f.context, Limits: f.limits, Archive: local,
		Subject: f.subject, Replicas: peers,
	}
	require.NoError(t, worker.Pass(context.Background()))
	advanced, err := f.store.LoadFrontier(context.Background(), f.context, f.limits)
	require.NoError(t, err)
	require.NotNil(t, advanced.Anchor)
	require.Equal(t, uint64(1), advanced.Anchor.Height)
}
