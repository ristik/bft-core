package cmd

import (
	"context"
	"testing"

	"github.com/libp2p/go-libp2p/core/network"
	libp2ppeer "github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/b1paired"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/keyvaluedb/memorydb"
	"github.com/unicitynetwork/bft-core/recordsfeed"
	"github.com/unicitynetwork/bft-core/rootrecords"
)

type noHost struct{}

func (noHost) CreateStream(context.Context, libp2ppeer.ID, string) (network.Stream, error) {
	return nil, context.Canceled
}

func TestThePairIsGivenAnAuthenticatedRecordsRouteThroughEveryRootItKnows(t *testing.T) {
	cfg := &b1paired.Config{}
	require.NoError(t, attachRecordsFeed(cfg, noHost{}, []libp2ppeer.AddrInfo{{ID: "root-a"}, {ID: "root-b"}}, newRootFreeRole(false, nil), nil, nil))
	require.NotNil(t, cfg.Records)
	// no root reachable: unavailable, never an empty feed
	_, err := cfg.Records.Cursor(context.Background(), evmroot.RootOriginV2{RootRound: 3})
	require.Error(t, err)
}

type dialRecorder struct{ dialled []libp2ppeer.ID }

func (d *dialRecorder) CreateStream(_ context.Context, to libp2ppeer.ID, _ string) (network.Stream, error) {
	d.dialled = append(d.dialled, to)
	return nil, context.Canceled
}

// A root-free follower that is not active asks the mirrors for root records and never a root; once active it asks its roots first.
func TestARootFreeFollowerAsksMirrorsNotRootsForRecords(t *testing.T) {
	cfg := &b1paired.Config{}
	host := &dialRecorder{}
	roots := []libp2ppeer.AddrInfo{{ID: "root-a"}, {ID: "root-b"}}
	role := newRootFreeRole(true, nil)
	role.setMirrors(func() []libp2ppeer.ID { return []libp2ppeer.ID{"mirror-1", "mirror-2"} })
	member := false
	role.setRole(func() bool { return member })
	require.NoError(t, attachRecordsFeed(cfg, host, roots, role, nil, nil))
	_, err := cfg.Records.Cursor(context.Background(), evmroot.RootOriginV2{RootRound: 3, UnicityTreeRoot: make([]byte, 32)})
	require.Error(t, err)
	require.Equal(t, []libp2ppeer.ID{"mirror-1", "mirror-2"}, host.dialled, "a non-active follower dials no root")

	member, host.dialled = true, nil
	_, _ = cfg.Records.Cursor(context.Background(), evmroot.RootOriginV2{RootRound: 3, UnicityTreeRoot: make([]byte, 32)})
	require.Equal(t, []libp2ppeer.ID{"root-a", "root-b", "mirror-1", "mirror-2"}, host.dialled, "active: roots first, mirrors as backup")
}

// The production construction restores the retained record log from the store (recordsfeed's restart test exercises the same
// NewSource+SetCutStore path with real records): a retained log that does not verify refuses the attach, an empty store attaches, and a
// store that cannot be opened is an error, not a silent volatile fallback.
func TestTheRecordsFeedRefusesAnUnverifiableOrUnopenableStore(t *testing.T) {
	require.NoError(t, attachRecordsFeed(&b1paired.Config{}, noHost{}, nil, newRootFreeRole(false, nil), recordsfeed.KVCutStore{DB: memorydb.New()}, nil))

	tampered := recordsfeed.KVCutStore{DB: memorydb.New()}
	require.NoError(t, tampered.AppendRecords([]rootrecords.Record{{Index: 0, Kind: rootrecords.KindClosure}}))
	require.Error(t, attachRecordsFeed(&b1paired.Config{}, noHost{}, nil, newRootFreeRole(false, nil), tampered, nil))

	_, err := openRecordCuts(t.TempDir() + "/missing-dir/journal.db")
	require.Error(t, err)
}
