package shardnode

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type journalProviderStub struct {
	entries []JournalFetchEntry
	calls   int
}

func (p *journalProviderStub) FetchJournal(context.Context, JournalFetchRequest) ([]JournalFetchEntry, error) {
	p.calls++
	return p.entries, nil
}

func TestJournalSuffixTransportBoundsAndFraming(t *testing.T) {
	p := &journalProviderStub{entries: []JournalFetchEntry{{Block: Block{Number: 1, Hash: bytes.Repeat([]byte{2}, 32), ParentHash: bytes.Repeat([]byte{1}, 32), Raw: []byte{1}}}}}
	limits := DefaultJournalTransportLimits()
	limits.MaxResponseBytes = 4096
	limits.MaxTotalBytes = 1024
	s, err := NewJournalServer(p, limits)
	require.NoError(t, err)
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	done := make(chan error, 1)
	go func() { done <- s.Serve(context.Background(), server) }()
	require.NoError(t, client.SetDeadline(time.Now().Add(time.Second)))
	req := JournalFetchRequest{TargetHash: bytes.Repeat([]byte{2}, 32), AfterHash: bytes.Repeat([]byte{1}, 32)}
	require.NoError(t, writeFrame(client, req, limits.MaxRequestBytes))
	var resp journalFetchResponse
	require.NoError(t, readFrame(bufio.NewReader(client), &resp, limits.MaxResponseBytes))
	require.Empty(t, resp.Error)
	require.Len(t, resp.Entries, 1)
	require.Equal(t, []byte{1}, resp.Entries[0].Block.Raw)
	require.NoError(t, <-done)
	require.Equal(t, 1, p.calls)
	// The length cap is checked before any response body is allocated.
	reader := bufio.NewReader(&prefixOnlyReader{data: uvarint(uint64(limits.MaxResponseBytes + 1))})
	require.ErrorContains(t, readFrame(reader, &resp, limits.MaxResponseBytes), "over the")
}

func TestJournalSuffixQuietRequestIsPinnedAndBounded(t *testing.T) {
	good := JournalFetchRequest{AfterHash: bytes.Repeat([]byte{1}, 32), HeldRound: 3, HeldIdentity: []byte{1, 2, 3}}
	require.NoError(t, checkJournalFetch(good))
	good.HeldIdentity = bytes.Repeat([]byte{0xff}, 2049)
	require.Error(t, checkJournalFetch(good))
	require.Error(t, checkJournalFetch(JournalFetchRequest{TargetHash: bytes.Repeat([]byte{2}, 32)}))
}
