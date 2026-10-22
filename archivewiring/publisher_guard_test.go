package archivewiring

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	libp2pnetwork "github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/configuredprogress"
	testpeer "github.com/unicitynetwork/bft-core/internal/testutils/peer"
)

func TestJournalVerifierRejectsChangedBytesAndUncertifiedHash(t *testing.T) {
	f := newWiringFixture(t, 1)
	q, rec := f.record(t, 0)
	verify := JournalVerifier(f.store, f.context, f.limits, f.subject)
	require.NoError(t, verify(context.Background(), q, rec))
	changed := *rec
	changed.Body = []byte{0xc1, 0x80}
	require.ErrorIs(t, verify(context.Background(), q, &changed), ErrBinding)
	unknown := q
	unknown.BlockHash = [32]byte{0x88}
	require.ErrorIs(t, verify(context.Background(), unknown, rec), ErrUncertified)
	last := f.entries[0]
	uncertified := configuredprogress.JournalCandidate{Round: 2, Number: 2, ParentNumber: 1, Hash: bytes.Repeat([]byte{0x77}, 32), StateRoot: bytes.Repeat([]byte{0x66}, 32),
		ParentHash: last.Candidate.Hash, ParentState: last.Candidate.StateRoot, Raw: []byte{1}, BlockSize: 1,
		AuthorizingUC: last.ResultingUC, AuthorizingTR: last.ResultingTR}
	require.NoError(t, f.store.PutJournalCandidate(context.Background(), f.context, f.limits, uncertified))
	copy(unknown.BlockHash[:], uncertified.Hash)
	require.ErrorIs(t, verify(context.Background(), unknown, rec), ErrUncertified)
}

func TestFromJournalChecksResultingCertificateBlockHash(t *testing.T) {
	f := newWiringFixture(t, 1)
	e := f.entries[0]
	ir := *e.ResultingUC.InputRecord
	ir.BlockHash = bytes.Repeat([]byte{0xa5}, 32)
	wrong, _ := signWiring(t, f.chain, &ir, 2, 5)
	e.ResultingUC = wrong
	_, _, err := FromJournal(context.Background(), f.context, f.subject, nil, e)
	require.ErrorIs(t, err, ErrBinding)
}

func TestPublisherBacklogDoesNotUseConsensusWitnessAndRotates(t *testing.T) {
	t.Parallel()
	f := newWiringFixture(t, 6)
	local, err := archive.Open(t.TempDir())
	require.NoError(t, err)
	p := &Publisher{Journal: f.store, Context: f.context, JournalLimits: f.limits, Archive: local, Subject: f.subject, ack: make(map[[32]byte]ackSet)}
	// No adapter or witness requester is supplied. A backlog must still publish.
	require.NoError(t, p.pass(context.Background()))
	firstPass := 0
	for i := range f.entries {
		q, _ := f.record(t, i)
		if _, err := local.Get(q); err == nil {
			firstPass++
		} else {
			require.ErrorIs(t, err, archive.ErrUnavailable)
		}
	}
	require.Equal(t, 4, firstPass)
	require.NoError(t, p.pass(context.Background()))
	for i := range f.entries {
		q, want := f.record(t, i)
		got, err := local.Get(q)
		require.NoError(t, err)
		a, err := archive.ManifestDigest(q, got)
		require.NoError(t, err)
		b, err := archive.ManifestDigest(q, want)
		require.NoError(t, err)
		require.Equal(t, b, a)
	}
	require.Equal(t, Status{Pending: 6}, p.Snapshot())
	var stale [32]byte
	stale[0] = 0xff
	p.ack[stale] = 3
	var first, second [32]byte
	copy(first[:], f.entries[0].Candidate.Hash)
	copy(second[:], f.entries[1].Candidate.Hash)
	p.ack[first], p.ack[second] = 3, 1
	require.NoError(t, p.pass(context.Background()))
	require.Equal(t, Status{Pending: 4, Acknowledged: 1, Lagging: 1}, p.Snapshot())
	_, stalePresent := p.ack[stale]
	require.False(t, stalePresent)
}

func TestPublisherRejectsMismatchedLocalCopy(t *testing.T) {
	t.Parallel()
	f := newWiringFixture(t, 1)
	q, rec := f.record(t, 0)
	local, err := archive.Open(t.TempDir())
	require.NoError(t, err)
	wrong := *rec
	wrong.Body = []byte{0xc1, 0x80}
	require.NoError(t, local.Put(q, &wrong))
	p := &Publisher{Journal: f.store, Context: f.context, JournalLimits: f.limits, Archive: local, Subject: f.subject}
	require.True(t, errors.Is(p.pass(context.Background()), ErrBinding))
}

func TestPublisherReplicaDeliveryIsIndependent(t *testing.T) {
	t.Parallel()
	f := newWiringFixture(t, 1)
	q, rec := f.record(t, 0)
	local, err := archive.Open(t.TempDir())
	require.NoError(t, err)
	require.NoError(t, local.Put(q, rec))
	sender := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	good := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	slow := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	sender.Network().Peerstore().AddAddrs(good.ID(), good.MultiAddresses(), peerstore.PermanentAddrTTL)
	sender.Network().Peerstore().AddAddrs(slow.ID(), slow.MultiAddresses(), peerstore.PermanentAddrTTL)
	goodStore, err := archive.Open(t.TempDir())
	require.NoError(t, err)
	server, err := NewServer(goodStore, q.Context, func(context.Context, archive.Request, *archive.Record) error { return nil }, []peer.ID{sender.ID()}, DefaultLimits())
	require.NoError(t, err)
	server.Register(context.Background(), good)
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	var once sync.Once
	releasePeer := func() { once.Do(func() { close(release) }) }
	slow.RegisterProtocolHandler(ProtocolArchive, func(stream libp2pnetwork.Stream) {
		defer stream.Close()
		started <- struct{}{}
		<-release
	})
	limits := DefaultLimits()
	p := &Publisher{Journal: f.store, Context: f.context, JournalLimits: f.limits, Archive: local, Subject: f.subject, Host: sender, Replicas: []peer.ID{good.ID(), slow.ID()}, Limits: limits, ack: make(map[[32]byte]ackSet)}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	defer releasePeer()
	slowDone := make(chan error, 1)
	go func() { slowDone <- p.replicaPass(ctx, 1) }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("slow replica was not contacted")
	}
	goodDone := make(chan error, 1)
	go func() { goodDone <- p.replicaPass(ctx, 0) }()
	select {
	case err := <-goodDone:
		require.NoError(t, err)
	case <-ctx.Done():
		t.Fatal("healthy replica waited for blocked replica")
	}
	select {
	case <-slowDone:
		t.Fatal("slow replica completed before the healthy replica")
	default:
	}
	releasePeer()
	cancel()
	<-slowDone
}

// With three replicas and one unreachable, the other two still make every block durable: status reports it acknowledged, the local pass
// stops rebuilding it, and the third replica is published to as well when it is reachable again.
func TestPublisherTwoOfThreeAcknowledgesWithOneReplicaDown(t *testing.T) {
	t.Parallel()
	f := newWiringFixture(t, 3)
	local, err := archive.Open(t.TempDir())
	require.NoError(t, err)
	for i := range f.entries {
		q, rec := f.record(t, i)
		require.NoError(t, local.Put(q, rec))
	}
	sender := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	var ids []peer.ID
	stores := make([]*archive.Store, 3)
	for i := range stores {
		remote := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
		ids = append(ids, remote.ID())
		stores[i], err = archive.Open(t.TempDir())
		require.NoError(t, err)
		if i == 1 {
			continue // never reachable: no address, no server
		}
		sender.Network().Peerstore().AddAddrs(remote.ID(), remote.MultiAddresses(), peerstore.PermanentAddrTTL)
		server, err := NewServer(stores[i], f.subject, JournalVerifier(f.store, f.context, f.limits, f.subject), []peer.ID{sender.ID()}, DefaultLimits())
		require.NoError(t, err)
		server.Register(context.Background(), remote)
	}
	p := &Publisher{Journal: f.store, Context: f.context, JournalLimits: f.limits, Archive: local, Subject: f.subject, Host: sender, Replicas: ids, Limits: DefaultLimits(), ack: make(map[[32]byte]ackSet)}
	require.NoError(t, p.Validate())
	ctx := context.Background()
	require.NoError(t, p.replicaPass(ctx, 0))
	require.Error(t, p.replicaPass(ctx, 1))
	require.NoError(t, p.replicaPass(ctx, 2))
	require.NoError(t, p.pass(ctx))
	require.Equal(t, Status{Acknowledged: int64(len(f.entries))}, p.Snapshot(), "two verified copies are enough")
	for hash, set := range p.ack {
		require.Equal(t, ackSet(0b101), set, "block %x", hash)
	}
	progress := p.ReplicaProgress()
	require.Len(t, progress, 3)
	require.NotEmpty(t, progress[1].Error)
	require.Empty(t, progress[0].Error)
	require.Empty(t, progress[2].Error)
	for i := range f.entries {
		q, _ := f.record(t, i)
		_, err := stores[0].Get(q)
		require.NoError(t, err)
		_, err = stores[2].Get(q)
		require.NoError(t, err)
		_, err = stores[1].Get(q)
		require.Error(t, err)
	}
	// One copy is not enough.
	p.ack = map[[32]byte]ackSet{}
	require.NoError(t, p.replicaPass(ctx, 2))
	require.NoError(t, p.pass(ctx))
	require.Equal(t, Status{Lagging: int64(len(f.entries))}, p.Snapshot())
}

func TestPublisherRefusesAnInvalidReplicaSet(t *testing.T) {
	f := newWiringFixture(t, 1)
	local, err := archive.Open(t.TempDir())
	require.NoError(t, err)
	sender := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	for name, replicas := range map[string][]peer.ID{"none": nil, "one": {"a"}, "four": {"a", "b", "c", "d"}, "duplicate": {"a", "a", "b"}} {
		p := &Publisher{Journal: f.store, Context: f.context, JournalLimits: f.limits, Archive: local, Subject: f.subject, Host: sender, Replicas: replicas, Limits: DefaultLimits()}
		require.ErrorIs(t, p.Validate(), ErrConfig, name)
	}
}

// A record this node has not built yet is not a failure of the replica being served: with one real replica fault and the local record
// missing, only the faulty replica reports an error.
func TestReplicaPassLocalRecordMissingIsNotAReplicaError(t *testing.T) {
	t.Parallel()
	f := newWiringFixture(t, 2)
	local, err := archive.Open(t.TempDir())
	require.NoError(t, err)
	sender := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	ids := []peer.ID{testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t)).ID(), testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t)).ID()}
	p := &Publisher{Journal: f.store, Context: f.context, JournalLimits: f.limits, Archive: local, Subject: f.subject, Host: sender, Replicas: ids, Limits: DefaultLimits(), ack: make(map[[32]byte]ackSet)}
	require.NoError(t, p.replicaPass(context.Background(), 0))
	for _, r := range p.ReplicaProgress() {
		require.Empty(t, r.Error)
	}
}
