package parentwitness

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	libp2pnetwork "github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
)

type testRequesterOpener struct{}

func (*testRequesterOpener) CreateStream(context.Context, peer.ID, string) (libp2pnetwork.Stream, error) {
	return nil, errors.New("unused")
}

func TestRequesterRejectsProviderListBeyondBudgetBeforeCopy(t *testing.T) {
	_, err := NewRequester(context.Background(), RequesterConfig{
		Opener: &testRequesterOpener{}, Providers: []peer.ID{"a", "b"},
		Budget: RequesterBudget{MaxAttempts: 2, MaxProviders: 1, Overall: time.Second, PerAttempt: time.Second, MaxDownloadedBytes: 10, Backoff: time.Second},
	})
	require.Error(t, err)
}

func TestBudgetedFrameCountsPrefixAndPartialBody(t *testing.T) {
	// 0x03 declares a three-byte body; a two-byte budget must fail after consuming
	// the prefix and the first body byte, without allocating the declared body.
	var used int64
	_, err := readFrameBudgeted(bytes.NewReader([]byte{3, 1, 2, 3}), MaxResponseBytes, &used, 2)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrDownloadedBytes))
	require.EqualValues(t, 2, used)
}
