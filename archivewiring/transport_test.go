package archivewiring

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/unicitynetwork/bft-core/archive"
	testpeer "github.com/unicitynetwork/bft-core/internal/testutils/peer"
	"github.com/unicitynetwork/bft-core/network"
)

func transportFixture() (archive.Request, *archive.Record) {
	rec := &archive.Record{Header: []byte{0xc1, 0x80}, Body: []byte{0xc0}, CanonicalRootInput: []byte{1}, OriginalUC: []byte{2}, OriginalTR: []byte{3}, ResultingUC: []byte{4}, ResultingTR: []byte{5}, Companion: []byte{6}}
	q := archive.Request{Context: archive.Context{NetworkID: 1, PartitionID: 2, ExecutionIdentity: []byte("config")}}
	q.Context.FullShardConfHash[0], q.Context.RegistryAddress[0], q.Context.RegistryCodeHash[0] = 1, 2, 3
	q.Context.GenesisCommitment[0], q.Context.EVMGenesisHash[0] = 4, 5
	copy(q.BlockHash[:], crypto.Keccak256(rec.Header))
	return q, rec
}

func serveOne(t *testing.T, s *Server, request []byte) ([]byte, error) {
	t.Helper()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	done := make(chan error, 1)
	go func() { done <- s.Serve(context.Background(), server) }()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	if err := writeFrame(client, request); err != nil {
		t.Fatal(err)
	}
	answer, err := readFrame(client, archive.MaxWireBytes)
	if err != nil {
		_ = client.Close()
	}
	serverErr := <-done
	if err != nil {
		return nil, serverErr
	}
	return answer, serverErr
}

func TestReplicaStoresOnlyVerifiedRecordsAndServesExactSubject(t *testing.T) {
	q, rec := transportFixture()
	store, err := archive.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	s, err := NewServer(store, q.Context, func(_ context.Context, got archive.Request, gotRec *archive.Record) error {
		checked++
		if got.BlockHash != q.BlockHash || !bytes.Equal(gotRec.Body, rec.Body) {
			return ErrBinding
		}
		return nil
	}, []peer.ID{"configured"}, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := archive.EncodeResponse(archive.Response{Request: q, Outcome: archive.OK, Record: rec})
	if err != nil {
		t.Fatal(err)
	}
	answer, err := serveOne(t, s, append([]byte{1}, encoded...))
	if err != nil || !bytes.Equal(answer, []byte{1}) || checked != 1 {
		t.Fatalf("put: %x %v, checks=%d", answer, err, checked)
	}
	request, _ := archive.EncodeRequest(q)
	answer, err = serveOne(t, s, append([]byte{2}, request...))
	if err != nil {
		t.Fatal(err)
	}
	got, err := archive.DecodeFor(q, answer)
	if err != nil || got.Outcome != archive.OK || !bytes.Equal(got.Record.Body, rec.Body) {
		t.Fatalf("get: %+v %v", got, err)
	}
	wrong := q
	wrong.Context.RootEpoch++
	request, _ = archive.EncodeRequest(wrong)
	answer, err = serveOne(t, s, append([]byte{2}, request...))
	if err != nil {
		t.Fatalf("foreign context response: %v", err)
	}
	refusal, err := archive.DecodeFor(wrong, answer)
	if err != nil || refusal.Outcome != archive.Invalid || refusal.Record != nil {
		t.Fatalf("foreign context: %+v %v", refusal, err)
	}
}

func TestReplicaRefusalAndFrameAdmission(t *testing.T) {
	q, rec := transportFixture()
	store, err := archive.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewServer(store, q.Context, func(context.Context, archive.Request, *archive.Record) error { return ErrBinding }, []peer.ID{"configured"}, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := archive.EncodeResponse(archive.Response{Request: q, Outcome: archive.OK, Record: rec})
	if err != nil {
		t.Fatal(err)
	}
	_, err = serveOne(t, s, append([]byte{1}, encoded...))
	if !errors.Is(err, ErrReplica) {
		t.Fatalf("unverified put: %v", err)
	}
	if _, err := store.Get(q); !errors.Is(err, archive.ErrUnavailable) {
		t.Fatalf("refused bytes stored: %v", err)
	}
	var oversized [4]byte
	binary.BigEndian.PutUint32(oversized[:], uint32(archive.MaxWireBytes+2))
	if _, err := readFrame(bytes.NewReader(oversized[:]), archive.MaxWireBytes+1); !errors.Is(err, archive.ErrInvalid) {
		t.Fatalf("oversize frame: %v", err)
	}
}

func TestTwoInProcessReplicaReadbacksAndOneReplicaLoss(t *testing.T) {
	q, rec := transportFixture()
	sender := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	first := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	second := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	for _, remote := range []*network.Peer{first, second} {
		sender.Network().Peerstore().AddAddrs(remote.ID(), remote.MultiAddresses(), peerstore.PermanentAddrTTL)
	}
	for _, remote := range []*network.Peer{first, second} {
		store, err := archive.Open(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		server, err := NewServer(store, q.Context, func(context.Context, archive.Request, *archive.Record) error { return nil }, []peer.ID{sender.ID()}, DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		server.Register(remote)
	}
	for _, id := range []peer.ID{first.ID(), second.ID()} {
		if err := PutAndReadBack(context.Background(), sender, id, q, rec, DefaultLimits()); err != nil {
			t.Fatalf("replica %s: %v", id, err)
		}
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	short := DefaultLimits()
	short.Deadline = 250 * time.Millisecond
	if err := PutAndReadBack(context.Background(), sender, second.ID(), q, rec, short); !errors.Is(err, ErrTransport) {
		t.Fatalf("lost replica: %v", err)
	}
	if err := PutAndReadBack(context.Background(), sender, first.ID(), q, rec, DefaultLimits()); err != nil {
		t.Fatalf("surviving replica: %v", err)
	}
}
