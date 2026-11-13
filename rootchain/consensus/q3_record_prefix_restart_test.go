package consensus

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/q3active"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	"github.com/unicitynetwork/bft-core/rootrecords"
)

// prefixChain is a linked P85 record log of n records and the source state that commits it.
func prefixChain(n int) ([]rootrecords.Record, rootrecords.State) {
	var out []rootrecords.Record
	var prev [32]byte
	for i := 0; i < n; i++ {
		r := rootrecords.Record{Index: uint64(i), Predecessor: prev, Kind: rootrecords.KindSessionClosed, Progress: uint64(10 + i), UCTime: uint64(100 + i), Data: make([]byte, 32)}
		r.ID = rootrecords.RecordID(r.Index, r.Predecessor, r.Kind, r.Progress, r.UCTime, r.Data)
		prev = r.ID
		out = append(out, r)
	}
	state := rootrecords.NewState(1, 2)
	state.Count, state.Tip = uint64(n), prev
	return out, state
}

// peerRecords is the record log another root serves: what rootRecordFetcher fetches over the records feed in root-node run.
type peerRecords struct {
	recs  []rootrecords.Record
	calls int
}

func (p *peerRecords) Records(_ context.Context, from uint64, max int) ([]rootrecords.Record, error) {
	p.calls++
	end := min(from+uint64(max), uint64(len(p.recs)))
	if from >= end {
		return nil, nil
	}
	return append([]rootrecords.Record(nil), p.recs[from:end]...), nil
}

// #1028: an install interrupted because the checkpoint's record-log prefix was not at hand leaves an unfinished installation in the
// journal, and the runtime's recovery on the next start completes it. The recovery needs the prefix too, so a start that runs it before the
// record fetcher is installed fails on every restart; one that installs the fetcher first completes the activation from the fetched and
// verified records. A fetcher that serves another log is still refused.
func TestARestartAfterAnInstallInterruptedForTheRecordPrefixCompletesWithTheFetcher(t *testing.T) {
	recs, state := prefixChain(3)
	c := newQ3Cluster(t, q3fixture.Options{SourceState: state.Bytes()})
	ctx := context.Background()
	r := c.replicas[1]

	// the first start (installQ3Epochs): no peer serves the records, the root install fails and the journal holds the unfinished install
	require.NoError(t, r.rt.Recover(ctx))
	require.ErrorIs(t, r.rt.Activate(ctx, r.bundle()), storage.ErrRecordPrefixMissing)
	require.Nil(t, r.manager.epochAnchor)
	require.ErrorIs(t, r.rt.Admit(2), q3active.ErrNotActive)

	// a restart whose recovery runs before any fetcher exists fails, every time: the crash loop of #1028
	for i := 0; i < 2; i++ {
		r.close()
		r.mustOpen(true)
		require.ErrorIs(t, r.rt.Recover(ctx), storage.ErrRecordPrefixMissing)
		require.Nil(t, r.manager.epochAnchor)
	}

	// a fetcher whose records are not the checkpoint's log does not complete it
	r.close()
	r.mustOpen(true)
	other, _ := prefixChain(4)
	r.manager.SetRecordFetcher(&peerRecords{recs: other[1:]})
	require.Error(t, r.rt.Recover(ctx))
	require.Nil(t, r.manager.epochAnchor)

	// the start of the fix: the fetcher is installed before the recovery, which fetches the prefix and completes the exact activation
	r.close()
	r.mustOpen(true)
	peer := &peerRecords{recs: recs}
	r.manager.SetRecordFetcher(peer)
	require.NoError(t, r.rt.Recover(ctx))
	require.Positive(t, peer.calls)
	require.NotNil(t, r.manager.epochAnchor)
	require.NoError(t, r.rt.Admit(2))
	require.NoError(t, r.rt.Gate(ctx, c.f.Claim))
	have, err := r.db.RecordCount()
	require.NoError(t, err)
	require.EqualValues(t, len(recs), have, "the fetched prefix is retained")

	// a later restart needs no fetcher: the prefix is retained and the installation complete
	anchor := r.manager.epochAnchor
	r.close()
	r.mustOpen(true)
	require.NoError(t, r.rt.Recover(ctx))
	require.NoError(t, r.rt.Admit(2))
	require.Equal(t, anchor, r.manager.epochAnchor)
}
