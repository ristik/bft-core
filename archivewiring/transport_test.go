package archivewiring

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	libp2pnetwork "github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/frontier"
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

// serveOneDeadline bounds every wait in serveOne. The server answers only after it has verified and durably stored the record, which
// can take seconds when the disk is busy (the full suite runs many fsync-heavy packages at once), so the bound is generous; what matters
// is that it exists. The production server bounds the same work by Limits.Deadline (20 s, DefaultLimits).
var (
	serveOneDeadline = 15 * time.Second
	// serveOneDrain bounds the wait for Serve to return after the client has given up: the server may still be verifying and storing
	// the record, and returns as soon as its reply write fails.
	serveOneDrain = 60 * time.Second
)

func serveOne(t *testing.T, s *Server, request []byte) ([]byte, error) {
	t.Helper()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	done := make(chan error, 1)
	go func() { done <- s.Serve(context.Background(), server) }()
	_ = client.SetDeadline(time.Now().Add(serveOneDeadline))
	if err := writeFrame(client, request); err != nil {
		t.Fatal(err)
	}
	type readResult struct {
		answer []byte
		err    error
	}
	read := make(chan readResult, 1)
	go func() {
		answer, err := readFrame(client, archive.MaxWireBytes)
		read <- readResult{answer: answer, err: err}
	}()
	// waitServer collects Serve's own result without blocking forever. A net.Pipe write blocks until the peer reads, so a server
	// whose reply the client has stopped waiting for would never return; closing the client first lets that write fail.
	waitServer := func() error {
		select {
		case err := <-done:
			return err
		case <-time.After(serveOneDrain):
			t.Fatalf("serveOne: the server did not return within %v", serveOneDrain)
			return nil
		}
	}
	select {
	case result := <-read:
		if result.err != nil {
			_ = client.Close()
			serverErr := waitServer()
			return nil, fmt.Errorf("serveOne: no reply within %v: %w (server: %v)", serveOneDeadline, result.err, serverErr)
		}
		return result.answer, waitServer()
	case serverErr := <-done:
		if serverErr == nil {
			select {
			case result := <-read: // a successful Serve has written a full response.
				return result.answer, result.err
			case <-time.After(serveOneDeadline):
				t.Fatalf("serveOne: the server returned but its reply was not readable within %v", serveOneDeadline)
			}
		}
		select {
		case result := <-read:
			return result.answer, serverErr
		default:
			return nil, serverErr
		}
	}
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
	t.Parallel()
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
		server.Register(context.Background(), remote)
	}
	for _, id := range []peer.ID{first.ID(), second.ID()} {
		if err := PutAndReadBack(context.Background(), sender, id, q, rec, DefaultLimits()); err != nil {
			t.Fatalf("replica %s: %v", id, err)
		}
	}
	digest, err := archive.ManifestDigest(q, rec)
	if err != nil {
		t.Fatal(err)
	}
	availability := ReplicaAvailability{Host: sender, Replicas: [2]peer.ID{first.ID(), second.ID()}, Limits: DefaultLimits()}
	for _, id := range []peer.ID{first.ID(), second.ID()} {
		if err := availability.VerifyAvailable(id.String(), q, digest); err != nil {
			t.Fatalf("frontier read-back %s: %v", id, err)
		}
	}
	if err := availability.VerifyAvailable("not configured", q, digest); !errors.Is(err, frontier.ErrContext) {
		t.Fatalf("unconfigured frontier replica: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	short := DefaultLimits()
	short.Deadline = 250 * time.Millisecond
	availability.Limits = short
	if err := availability.VerifyAvailable(second.ID().String(), q, digest); !errors.Is(err, frontier.ErrUnavailable) {
		t.Fatalf("lost frontier copy: %v", err)
	}
	if err := PutAndReadBack(context.Background(), sender, second.ID(), q, rec, short); !errors.Is(err, ErrTransport) {
		t.Fatalf("lost replica: %v", err)
	}
	if err := PutAndReadBack(context.Background(), sender, first.ID(), q, rec, DefaultLimits()); err != nil {
		t.Fatalf("surviving replica: %v", err)
	}
}

func TestReplicaRejectsWrongPutAckAndChangedReadBack(t *testing.T) {
	for _, change := range []string{"ack", "read-back"} {
		t.Run(change, func(t *testing.T) {
			q, rec := transportFixture()
			sender := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
			receiver := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
			sender.Network().Peerstore().AddAddrs(receiver.ID(), receiver.MultiAddresses(), peerstore.PermanentAddrTTL)
			var reads atomic.Int32
			receiver.RegisterProtocolHandler(ProtocolArchive, func(stream libp2pnetwork.Stream) {
				defer stream.Close()
				frame, err := readFrame(stream, archive.MaxWireBytes+1)
				if err != nil || len(frame) == 0 {
					return
				}
				if frame[0] == 1 {
					if change == "ack" {
						_ = writeFrame(stream, []byte{2})
					} else {
						_ = writeFrame(stream, []byte{1})
					}
					return
				}
				reads.Add(1)
				changed := *rec
				changed.Body = []byte{0xc1, 0x80}
				response, err := archive.EncodeResponse(archive.Response{Request: q, Outcome: archive.OK, Record: &changed})
				if err == nil {
					_ = writeFrame(stream, response)
				}
			})
			err := PutAndReadBack(context.Background(), sender, receiver.ID(), q, rec, DefaultLimits())
			if !errors.Is(err, ErrReplica) {
				t.Fatalf("%s: %v", change, err)
			}
			if change == "ack" && reads.Load() != 0 || change == "read-back" && reads.Load() != 1 {
				t.Fatalf("%s: read-backs %d", change, reads.Load())
			}
		})
	}
}

func TestReplicaAdmissionLimitsAndAllowlist(t *testing.T) {
	q, _ := transportFixture()
	store, err := archive.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	limits := Limits{Deadline: time.Second, Pending: 2, PerPeer: 1}
	s, err := NewServer(store, q.Context, func(context.Context, archive.Request, *archive.Record) error { return nil }, []peer.ID{"first", "second", "third"}, limits)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.reservePending("outsider"); !errors.Is(err, ErrPeerNotAllowed) {
		t.Fatalf("unconfigured peer: %v", err)
	}
	if err := s.reservePending("first"); err != nil {
		t.Fatalf("first global slot refused: %v", err)
	}
	if err := s.reservePeer("first"); err != nil {
		t.Fatalf("first peer slot refused: %v", err)
	}
	if err := s.reservePending("second"); err != nil {
		t.Fatalf("second global slot refused: %v", err)
	}
	if err := s.reservePeer("second"); err != nil {
		t.Fatalf("second peer slot refused: %v", err)
	}
	if err := s.reservePending("third"); !errors.Is(err, ErrPendingLimit) {
		t.Fatalf("global slot limit ignored: %v", err)
	}
	s.leave("first")
	if err := s.reservePending("third"); err != nil {
		t.Fatalf("released global slot unavailable: %v", err)
	}
	if err := s.reservePeer("third"); err != nil {
		t.Fatalf("released peer slot unavailable: %v", err)
	}
	s.leave("second")
	s.leave("third")
}

func TestArchiveAdmissionRejectsUnlistedPeerWithSentinel(t *testing.T) {
	s := admissionTestServer(t, Limits{Deadline: time.Second, Pending: 4, PerPeer: 4})
	if err := s.reservePending("outsider"); !errors.Is(err, ErrPeerNotAllowed) {
		t.Fatalf("unlisted peer refusal: %v", err)
	}
}

func TestArchiveAdmissionRejectsPerPeerOverflowWithSentinel(t *testing.T) {
	s := admissionTestServer(t, Limits{Deadline: time.Second, Pending: 8, PerPeer: 4})
	for i := 0; i < 4; i++ {
		if err := s.reservePending("sender"); err != nil {
			t.Fatal(err)
		}
		if err := s.reservePeer("sender"); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.reservePending("sender"); err != nil {
		t.Fatal(err)
	}
	if err := s.reservePeer("sender"); !errors.Is(err, ErrPeerLimit) {
		t.Fatalf("per-peer overflow: %v", err)
	}
	for i := 0; i < 4; i++ {
		s.leave("sender")
	}
}

func TestArchiveAdmissionRejectsGlobalPendingOverflowWithSentinel(t *testing.T) {
	s := admissionTestServer(t, Limits{Deadline: time.Second, Pending: 2, PerPeer: 2})
	if err := s.reservePending("sender"); err != nil {
		t.Fatal(err)
	}
	if err := s.reservePending("sender"); err != nil {
		t.Fatal(err)
	}
	if err := s.reservePending("sender"); !errors.Is(err, ErrPendingLimit) {
		t.Fatalf("global pending overflow: %v", err)
	}
	s.releasePending()
	s.releasePending()
}

func TestArchiveVerifierRefusalHasSpecificSentinel(t *testing.T) {
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
	if !errors.Is(err, ErrVerifier) {
		t.Fatalf("verifier refusal: %v", err)
	}
}

func TestArchiveHandlerFailureHasSpecificSentinel(t *testing.T) {
	q, _ := transportFixture()
	store, err := archive.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewServer(store, q.Context, func(context.Context, archive.Request, *archive.Record) error { return nil }, []peer.ID{"configured"}, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	_, err = serveOne(t, s, []byte{99, 0})
	if !errors.Is(err, ErrHandler) {
		t.Fatalf("handler failure: %v", err)
	}
}

func admissionTestServer(t *testing.T, limits Limits) *Server {
	t.Helper()
	q, _ := transportFixture()
	store, err := archive.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewServer(store, q.Context, func(context.Context, archive.Request, *archive.Record) error { return nil }, []peer.ID{"sender"}, limits)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// A server given a peer authorizer asks it at every request, so the set of peers it serves changes with the active assignment
// without rebuilding the server; the static set it was built with no longer decides.
func TestArchiveAdmissionFollowsThePeerAuthorizer(t *testing.T) {
	s := admissionTestServer(t, Limits{Deadline: time.Second, Pending: 8, PerPeer: 4})
	active := map[peer.ID]bool{"joiner": false}
	s.SetPeerAuthorizer(func(id peer.ID) bool { return active[id] })
	if err := s.reservePending("joiner"); !errors.Is(err, ErrPeerNotAllowed) {
		t.Fatalf("a peer the authorizer does not allow: %v", err)
	}
	active["joiner"] = true
	if err := s.reservePending("joiner"); err != nil {
		t.Fatalf("a peer the authorizer allows after the install: %v", err)
	}
	s.leave("joiner")
	// the static genesis set no longer decides: a genesis peer the authorizer does not know is refused
	if err := s.reservePending("sender"); !errors.Is(err, ErrPeerNotAllowed) {
		t.Fatalf("a peer only the static set allows: %v", err)
	}
	active["joiner"] = false
	if err := s.reservePending("joiner"); !errors.Is(err, ErrPeerNotAllowed) {
		t.Fatalf("a retired peer: %v", err)
	}
}

// A peer the replica does not (yet) authorize is told so by name, over the real transport and without its request being read: the
// client sees a StreamResetError carrying ErrPeerNotAllowed (not a bare reset), for fetches and for bundle fetches alike, and is served
// as soon as the authorizer admits it.
func TestAnUnauthorizedPeerIsRefusedByNameAndServedOnceAdmitted(t *testing.T) {
	t.Parallel()
	q, rec := transportFixture()
	sender := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	remote := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	sender.Network().Peerstore().AddAddrs(remote.ID(), remote.MultiAddresses(), peerstore.PermanentAddrTTL)
	store, err := archive.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(q, rec); err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(store, q.Context, func(context.Context, archive.Request, *archive.Record) error { return nil }, []peer.ID{sender.ID()}, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	var admitted atomic.Bool
	server.SetPeerAuthorizer(func(peer.ID) bool { return admitted.Load() })
	server.Register(context.Background(), remote)

	_, err = Fetch(context.Background(), sender, remote.ID(), q, DefaultLimits())
	var reset *StreamResetError
	if !errors.Is(err, ErrPeerNotAllowed) || !errors.As(err, &reset) {
		t.Fatalf("a not yet admitted peer must be refused by name, got: %v", err)
	}
	_, err = FetchBundle(context.Background(), sender, remote.ID(), archive.BundleRequest{Context: q.Context, Epoch: 2}, DefaultLimits())
	if !errors.Is(err, ErrPeerNotAllowed) {
		t.Fatalf("bundle fetch of a not yet admitted peer: %v", err)
	}
	admitted.Store(true)
	got, err := Fetch(context.Background(), sender, remote.ID(), q, DefaultLimits())
	if err != nil || !equalRecord(q, rec, got) {
		t.Fatalf("an admitted peer is served: %v", err)
	}
}

// serveOne used to wait on the server forever when the client's read deadline expired first: the server's reply write on the pipe
// then had no reader and the client was closed only after serveOne returned, so one slow verify-and-store turned into the package's
// 30-minute timeout. A server slower than the deadline must now fail the call promptly, as an error that names the missed reply.
func TestServeOneFailsInsteadOfHangingWhenTheServerIsSlowerThanItsDeadline(t *testing.T) {
	savedDeadline, savedDrain := serveOneDeadline, serveOneDrain
	serveOneDeadline, serveOneDrain = 300*time.Millisecond, 5*time.Second
	defer func() { serveOneDeadline, serveOneDrain = savedDeadline, savedDrain }()
	q, rec := transportFixture()
	store, err := archive.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewServer(store, q.Context, func(context.Context, archive.Request, *archive.Record) error {
		time.Sleep(time.Second)
		return nil
	}, []peer.ID{"configured"}, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := archive.EncodeResponse(archive.Response{Request: q, Outcome: archive.OK, Record: rec})
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	answer, err := serveOne(t, s, append([]byte{1}, encoded...))
	if err == nil || answer != nil || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("a server slower than the deadline must fail the call with the deadline error: answer=%x err=%v", answer, err)
	}
	if elapsed := time.Since(started); elapsed > 10*time.Second {
		t.Fatalf("serveOne took %v: it is waiting on the server again", elapsed)
	}
}

// stalledStream is a libp2p stream over a net.Pipe whose far end stops reading, which makes the server's reply write block exactly
// as it does to a peer that has stopped draining its connection. Like a real stream it honours SetDeadline for reads and writes.
type stalledStream struct {
	libp2pnetwork.Stream
	conn net.Conn
	id   peer.ID
}

type stalledConn struct {
	libp2pnetwork.Conn
	id peer.ID
}

func (c stalledConn) RemotePeer() peer.ID             { return c.id }
func (s stalledStream) Conn() libp2pnetwork.Conn      { return stalledConn{id: s.id} }
func (s stalledStream) Read(p []byte) (int, error)    { return s.conn.Read(p) }
func (s stalledStream) Write(p []byte) (int, error)   { return s.conn.Write(p) }
func (s stalledStream) SetDeadline(t time.Time) error { return s.conn.SetDeadline(t) }
func (s stalledStream) Close() error                  { return s.conn.Close() }
func (s stalledStream) Reset() error                  { return s.conn.Close() }

// A peer that sends a valid request and then never reads the reply must not pin a server goroutine or its reservation: the production
// stream handler gives the whole exchange Limits.Deadline (transport.go handle), so the blocked reply write fails at that bound, the
// handler returns, and the global and per-peer reservations are released. This is the product-side half of the serveOne hang: the
// pipe in that test had no deadline, a real stream does.
func TestHandlerExitsAtItsDeadlineWhenThePeerStopsReading(t *testing.T) {
	q, rec := transportFixture()
	store, err := archive.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(q, rec); err != nil {
		t.Fatal(err)
	}
	const id = peer.ID("configured")
	limits := Limits{Deadline: 400 * time.Millisecond, Pending: 4, PerPeer: 4}
	s, err := NewServer(store, q.Context, func(context.Context, archive.Request, *archive.Record) error { return nil }, []peer.ID{id}, limits)
	if err != nil {
		t.Fatal(err)
	}
	s.ctx = context.Background() // what Register sets; the handler derives its exchange context from it
	client, server := net.Pipe()
	defer client.Close()
	request, err := archive.EncodeRequest(q)
	if err != nil {
		t.Fatal(err)
	}
	exited := make(chan struct{})
	started := time.Now()
	go func() {
		defer close(exited)
		s.handle(stalledStream{conn: server, id: id})
	}()
	if err := writeFrame(client, append([]byte{2}, request...)); err != nil {
		t.Fatal(err) // the request is delivered; the client now stops reading and never drains the reply
	}
	select {
	case <-exited:
	case <-time.After(10 * limits.Deadline):
		t.Fatalf("the handler is still blocked writing to a peer that stopped reading after %v (Limits.Deadline %v)", time.Since(started), limits.Deadline)
	}
	if elapsed := time.Since(started); elapsed < limits.Deadline/2 {
		t.Fatalf("the handler returned after %v, before the reply write could have blocked: the test no longer stalls the write", elapsed)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending != 0 || len(s.byPeer) != 0 {
		t.Fatalf("reservations leaked after the handler exited: pending=%d byPeer=%v", s.pending, s.byPeer)
	}
}
