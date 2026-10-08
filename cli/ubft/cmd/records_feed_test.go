package cmd

import (
	"context"
	"testing"

	"github.com/libp2p/go-libp2p/core/network"
	libp2ppeer "github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/b1paired"
	"github.com/unicitynetwork/bft-core/evmroot"
)

type noHost struct{}

func (noHost) CreateStream(context.Context, libp2ppeer.ID, string) (network.Stream, error) {
	return nil, context.Canceled
}

func TestThePairIsGivenAnAuthenticatedRecordsRouteThroughEveryRootItKnows(t *testing.T) {
	cfg := &b1paired.Config{}
	attachRecordsFeed(cfg, noHost{}, []libp2ppeer.AddrInfo{{ID: "root-a"}, {ID: "root-b"}})
	require.NotNil(t, cfg.Records)
	// no root reachable: unavailable, never an empty feed
	_, err := cfg.Records.Cursor(context.Background(), evmroot.RootOriginV2{RootRound: 3})
	require.Error(t, err)
}
