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
	p := &Publisher{Archive: local, Subject: request.Context, Host: client, Replicas: [2]peer.ID{bad.ID(), good.ID()}, Limits: DefaultLimits(),
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
