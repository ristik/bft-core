package archivewiring

import (
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/archive"
	testpeer "github.com/unicitynetwork/bft-core/internal/testutils/peer"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-go-base/types"
)

type followRecord struct {
	q   archive.Request
	rec *archive.Record
}

// followSource is an archive replica holding the given records that serves a non-validator follower through its public read budget.
func followSource(t *testing.T, follower *network.Peer, f *wiringFixture, records []followRecord) peer.ID {
	t.Helper()
	remote := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	follower.Network().Peerstore().AddAddrs(remote.ID(), remote.MultiAddresses(), peerstore.PermanentAddrTTL)
	store, err := archive.Open(t.TempDir())
	require.NoError(t, err)
	for _, r := range records {
		require.NoError(t, store.Put(r.q, r.rec))
	}
	server, err := NewServer(store, f.subject, func(context.Context, archive.Request, *archive.Record) error { return nil }, []peer.ID{"validator"}, DefaultLimits())
	require.NoError(t, err)
	require.NoError(t, server.SetPublicReads(Limits{Deadline: 5 * time.Second, Pending: 4, PerPeer: 2}))
	server.Register(context.Background(), remote)
	return remote.ID()
}

// The root-free head follower offers the newest certificate it can verify from any source, ignores a source whose newer head is forged,
// offers nothing twice, and offers nothing while the node is active.
func TestHeadFollowerOffersTheNewestVerifiedHeadOnly(t *testing.T) {
	t.Parallel()
	f := newWiringFixture(t, 4)
	follower := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	var all, behind []followRecord
	for i := range f.entries {
		q, rec := f.record(t, i)
		all = append(all, followRecord{q, rec})
		if i < 2 {
			behind = append(behind, followRecord{q, rec})
		}
	}
	// a source whose newest record (block 4) carries a forged resulting certificate: a higher root round with a broken seal
	forged := append([]followRecord(nil), behind...)
	q4, rec4 := f.record(t, 3)
	bad := *rec4
	var result types.UnicityCertificate
	require.NoError(t, types.Cbor.Unmarshal(rec4.ResultingUC, &result))
	result.UnicitySeal.RootChainRoundNumber += 100
	raw, err := types.Cbor.Marshal(&result)
	require.NoError(t, err)
	bad.ResultingUC = raw
	forged = append(forged, followRecord{q4, &bad})

	sources := []peer.ID{followSource(t, follower, f, forged), followSource(t, follower, f, behind), followSource(t, follower, f, all)}
	var offered []*types.UnicityCertificate
	active := false
	h := &HeadFollower{Binding: CertifiedBinding{Context: f.context, Subject: f.subject}, Host: follower, Limits: DefaultLimits(),
		Sources: func() []peer.ID { return sources }, Active: func() bool { return active },
		Offer: func(uc *types.UnicityCertificate, _ *certification.TechnicalRecord) bool {
			offered = append(offered, uc)
			return true
		}}
	require.True(t, h.Poll(context.Background()))
	require.Len(t, offered, 1)
	var want types.UnicityCertificate
	newest := uint64(0)
	for _, r := range all { // the newest genuine record's resulting certificate
		var uc types.UnicityCertificate
		require.NoError(t, types.Cbor.Unmarshal(r.rec.ResultingUC, &uc))
		if uc.GetRootRoundNumber() > newest {
			newest, want = uc.GetRootRoundNumber(), uc
		}
	}
	require.Equal(t, want.GetRootRoundNumber(), offered[0].GetRootRoundNumber(), "the newest verified head, not the forged one")
	require.Equal(t, want.InputRecord.BlockHash, offered[0].InputRecord.BlockHash)
	require.False(t, h.Poll(context.Background()), "the same head is not offered twice")

	active = true
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	h.offered, h.Interval = nil, 10*time.Millisecond
	require.NoError(t, h.Run(ctx))
	require.Len(t, offered, 1, "an active node takes its certificates from the roots, not the follower")
}
