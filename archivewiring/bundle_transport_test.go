package archivewiring

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/unicitynetwork/bft-core/archive"
	testpeer "github.com/unicitynetwork/bft-core/internal/testutils/peer"
)

func TestReplicaBundlePutGetAndRefusal(t *testing.T) {
	request, _ := transportFixture()
	store, err := archive.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(store, request.Context, func(context.Context, archive.Request, *archive.Record) error { return nil }, []peer.ID{"configured"}, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	q := archive.BundleRequest{Context: request.Context, Epoch: 2}
	encoded, err := archive.EncodeBundleRequest(q)
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte("locally checked bundle")
	put := make([]byte, 3+len(encoded)+len(raw))
	put[0] = 5
	binary.BigEndian.PutUint16(put[1:], uint16(len(encoded)))
	copy(put[3:], encoded)
	copy(put[3+len(encoded):], raw)
	if _, err := serveOne(t, server, put); !errors.Is(err, archive.ErrInvalid) {
		t.Fatalf("unconfigured bundle verifier: %v", err)
	}
	if _, err := store.GetBundle(q); !errors.Is(err, archive.ErrUnavailable) {
		t.Fatalf("unverified bytes retained: %v", err)
	}
	server.SetBundleVerifier(func(_ context.Context, got archive.BundleRequest, value []byte) error {
		if got.Epoch != q.Epoch || !bytes.Equal(value, raw) {
			return ErrBinding
		}
		return nil
	})
	answer, err := serveOne(t, server, put)
	if err != nil || !bytes.Equal(answer, []byte{1}) {
		t.Fatalf("put: %x %v", answer, err)
	}
	answer, err = serveOne(t, server, append([]byte{4}, encoded...))
	if err != nil || len(answer) == 0 || answer[0] != 1 || !bytes.Equal(answer[1:], raw) {
		t.Fatalf("get: %x %v", answer, err)
	}
	foreign := q
	foreign.Context.RootEpoch++
	foreignEncoded, err := archive.EncodeBundleRequest(foreign)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := serveOne(t, server, append([]byte{4}, foreignEncoded...)); !errors.Is(err, archive.ErrInvalid) {
		t.Fatalf("foreign context: %v", err)
	}
}

func TestBundlePublisherContinuesAfterOneReplicaFails(t *testing.T) {
	request, _ := transportFixture()
	q := archive.BundleRequest{Context: request.Context, Epoch: 2}
	raw := []byte("verified bundle")
	local, err := archive.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := local.PutBundle(q, raw, nil); err != nil {
		t.Fatal(err)
	}
	remote, err := archive.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	client := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	good := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	bad := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	client.Network().Peerstore().AddAddrs(good.ID(), good.MultiAddresses(), peerstore.PermanentAddrTTL)
	server, err := NewServer(remote, request.Context, func(context.Context, archive.Request, *archive.Record) error { return nil }, []peer.ID{client.ID()}, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	server.SetBundleVerifier(func(_ context.Context, _ archive.BundleRequest, got []byte) error {
		if !bytes.Equal(got, raw) {
			return ErrBinding
		}
		return nil
	})
	server.Register(context.Background(), good)
	p := &Publisher{Archive: local, Subject: request.Context, Host: client, Replicas: []peer.ID{bad.ID(), good.ID()}, Limits: DefaultLimits(),
		BundleVerifier: func(context.Context, archive.BundleRequest, []byte) error { return nil }, bundleAck: make(map[uint64]uint8)}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := p.publishBundles(ctx); err == nil {
		t.Fatal("unreachable replica should be reported")
	}
	got, err := remote.GetBundle(q)
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("healthy replica starved: %x %v", got, err)
	}
}

// A bundle every replica has acknowledged is not read and verified again on every pass (bft-core#1018); one a replica still lacks is.
func TestBundlePublisherSkipsBundlesEveryReplicaAcknowledged(t *testing.T) {
	request, _ := transportFixture()
	raw := []byte("verified bundle")
	local, err := archive.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, epoch := range []uint64{2, 3} {
		if _, err := local.PutBundle(archive.BundleRequest{Context: request.Context, Epoch: epoch}, raw, nil); err != nil {
			t.Fatal(err)
		}
	}
	client := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	var replicas []peer.ID
	for range 2 {
		remote, err := archive.Open(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		replica := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
		client.Network().Peerstore().AddAddrs(replica.ID(), replica.MultiAddresses(), peerstore.PermanentAddrTTL)
		server, err := NewServer(remote, request.Context, func(context.Context, archive.Request, *archive.Record) error { return nil }, []peer.ID{client.ID()}, DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		server.SetBundleVerifier(func(context.Context, archive.BundleRequest, []byte) error { return nil })
		server.Register(context.Background(), replica)
		replicas = append(replicas, replica.ID())
	}
	verified := map[uint64]int{}
	p := &Publisher{Archive: local, Subject: request.Context, Host: client, Replicas: replicas, Limits: DefaultLimits(), bundleAck: make(map[uint64]uint8),
		BundleVerifier: func(_ context.Context, q archive.BundleRequest, _ []byte) error { verified[q.Epoch]++; return nil }}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := p.publishBundles(ctx); err != nil {
		t.Fatal(err)
	}
	afterFirst := map[uint64]int{2: verified[2], 3: verified[3]}
	if afterFirst[2] == 0 || afterFirst[3] == 0 {
		t.Fatalf("the first pass verifies each bundle: %v", verified)
	}
	for pass := 0; pass < 3; pass++ {
		if err := p.publishBundles(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if verified[2] != afterFirst[2] || verified[3] != afterFirst[3] {
		t.Fatalf("an acknowledged bundle was read and verified again: %v after the first pass, %v after three more", afterFirst, verified)
	}
	p.mu.Lock()
	p.bundleAck[3] &^= 1 // the first replica no longer acknowledges epoch 3 (a new replica in its place)
	p.mu.Unlock()
	if err := p.publishBundles(ctx); err != nil {
		t.Fatal(err)
	}
	if verified[2] != afterFirst[2] || verified[3] == afterFirst[3] {
		t.Fatalf("only the bundle a replica lacks is published again: %v", verified)
	}
}
