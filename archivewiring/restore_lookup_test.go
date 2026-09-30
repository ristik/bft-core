package archivewiring

import (
	"bytes"
	"context"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/frontier"
	"github.com/unicitynetwork/bft-go-base/types"
)

func TestRoundIndexedArchiveLookupSurvivesRestartAndRefusesWrongContext(t *testing.T) {
	t.Parallel()
	f := newWiringFixture(t, 3)
	dir := t.TempDir()
	store, err := archive.Open(dir)
	require.NoError(t, err)
	requests := make(map[uint64]archive.Request)
	for _, entry := range f.entries {
		q, rec, err := FromJournal(context.Background(), f.context, f.subject, nil, entry)
		require.NoError(t, err)
		require.NoError(t, store.Put(q, rec))
		requests[entry.Candidate.Round] = q
	}
	for _, round := range []uint64{1, 2, 3, 90} {
		q, rec, err := store.GetLatest(archive.RoundRequest{Context: f.subject, Round: round})
		require.NoError(t, err)
		index := int(round) - 1
		if index > 2 {
			index = 2
		}
		require.Equal(t, requests[uint64(index+1)].BlockHash, q.BlockHash)
		require.NotEmpty(t, rec.Header)
	}
	reopened, err := archive.Open(dir)
	require.NoError(t, err)
	q, rec, err := reopened.GetLatest(archive.RoundRequest{Context: f.subject, Round: 3})
	require.NoError(t, err)
	require.Equal(t, requests[3].BlockHash, q.BlockHash)
	require.NotEmpty(t, rec.Body)
	foreign := f.subject
	foreign.RootEpoch++
	_, _, err = reopened.GetLatest(archive.RoundRequest{Context: foreign, Round: 3})
	require.ErrorIs(t, err, archive.ErrUnavailable)

	server, err := NewServer(reopened, f.subject, func(context.Context, archive.Request, *archive.Record) error { return nil }, []peer.ID{"configured"}, DefaultLimits())
	require.NoError(t, err)
	raw, err := archive.EncodeRoundRequest(archive.RoundRequest{Context: f.subject, Round: 3})
	require.NoError(t, err)
	answer, err := serveOne(t, server, append([]byte{3}, raw...))
	require.NoError(t, err)
	require.Equal(t, byte(archive.OK), answer[0])
	response, err := archive.DecodeResponse(answer[1:])
	require.NoError(t, err)
	require.Equal(t, requests[3].BlockHash, response.Request.BlockHash)
	raw, err = archive.EncodeRoundRequest(archive.RoundRequest{Context: foreign, Round: 3})
	require.NoError(t, err)
	_, err = serveOne(t, server, append([]byte{3}, raw...))
	require.ErrorIs(t, err, archive.ErrInvalid)
}

func TestQuietTipMatchUsesCertifiedStateAndRound(t *testing.T) {
	f := newWiringFixture(t, 1)
	q, rec, err := FromJournal(context.Background(), f.context, f.subject, nil, f.entries[0])
	require.NoError(t, err)
	var resulting types.UnicityCertificate
	require.NoError(t, types.Cbor.Unmarshal(rec.ResultingUC, &resulting))
	tip := resulting
	ir := *resulting.InputRecord
	ir.RoundNumber++
	ir.PreviousHash = bytes.Clone(ir.Hash)
	ir.BlockHash = nil
	tip.InputRecord = &ir
	r := &SingleEpochRestore{TipUC: &tip}
	require.True(t, r.matchesTip(&resulting), "a genuine quiet round can retain the preceding block's unique state")
	tip.InputRecord.Hash = bytes.Repeat([]byte{0xaa}, 32)
	require.False(t, r.matchesTip(&resulting))
	tip.InputRecord.Hash = bytes.Clone(resulting.InputRecord.Hash)
	tip.InputRecord.RoundNumber = resulting.InputRecord.RoundNumber - 1
	require.False(t, r.matchesTip(&resulting))
	_ = q
}

func TestRestoreRecordAuthenticationRefusesForgedEpochAndIdentity(t *testing.T) {
	f := newWiringFixture(t, 1)
	q, rec, err := FromJournal(context.Background(), f.context, f.subject, nil, f.entries[0])
	require.NoError(t, err)
	r := &SingleEpochRestore{Context: f.context, Subject: f.subject, TipUC: f.entries[0].ResultingUC}
	_, _, err = r.checkRecord(q, rec)
	require.NoError(t, err)
	for _, change := range []struct {
		name string
		edit func(*types.UnicityCertificate)
		want error
	}{
		{"forged state", func(uc *types.UnicityCertificate) { uc.InputRecord.Hash[0] ^= 1 }, frontier.ErrInvalid},
		{"wrong epoch", func(uc *types.UnicityCertificate) { uc.UnicitySeal.Epoch++ }, ErrRestore},
		{"wrong round", func(uc *types.UnicityCertificate) { uc.InputRecord.RoundNumber++ }, frontier.ErrInvalid},
	} {
		t.Run(change.name, func(t *testing.T) {
			altered := *rec
			var uc types.UnicityCertificate
			require.NoError(t, types.Cbor.Unmarshal(rec.ResultingUC, &uc))
			change.edit(&uc)
			altered.ResultingUC, err = types.Cbor.Marshal(&uc)
			require.NoError(t, err)
			_, _, err = r.checkRecord(q, &altered)
			require.ErrorIs(t, err, change.want)
		})
	}
	foreign := q
	foreign.Context.ExecutionIdentity = []byte("another execution identity")
	_, _, err = r.checkRecord(foreign, rec)
	require.ErrorIs(t, err, frontier.ErrContext)
}
