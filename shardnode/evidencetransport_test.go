package shardnode

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

/*
Tests for the wire between the two halves (docs/design/f6b-quiet-tail-anchor-recovery.md §4, §6.1).

Two levels, deliberately. The framing and exchange tests run over net.Pipe, so what is asserted is
the bytes and the bounds rather than libp2p's behaviour; the end-to-end test in
evidencetransport_p2p_test.go then runs the same code over two real hosts. Every successful exchange
here ends by feeding the received bundle to the real VerifyAnchorEvidence with the held certificate
the request was pinned to: a transport that delivers something the predicate refuses has not
delivered anything.
*/

// errReachedForBody is returned by prefixOnlyReader if anything reads past the length prefix. A
// stand-in for what a real peer would do instead: send the gigabyte it just announced.
var errReachedForBody = errors.New("readFrame reached for the body")

// prefixOnlyReader yields the bytes it is given and then refuses to produce more, so a bound that is
// applied to the declared length can be told apart from one applied after the body arrives.
type prefixOnlyReader struct {
	data []byte
	pos  int
}

func (r *prefixOnlyReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, errReachedForBody
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

func uvarint(n uint64) []byte {
	b := make([]byte, binary.MaxVarintLen64)
	return b[:binary.PutUvarint(b, n)]
}

func TestEvidenceFraming(t *testing.T) {
	t.Run("a message round-trips", func(t *testing.T) {
		var buf bytes.Buffer
		require.NoError(t, writeFrame(&buf, &evidenceRequestMsg{HeldRound: 16, HeldIdentity: []byte{1, 2, 3}}, 4096))
		var got evidenceRequestMsg
		require.NoError(t, readFrame(bufio.NewReader(&buf), &got, 4096))
		require.EqualValues(t, 16, got.HeldRound)
		require.Equal(t, []byte{1, 2, 3}, got.HeldIdentity)
	})

	t.Run("a declared length over the bound is refused before the body is touched", func(t *testing.T) {
		// The whole point of not reusing the shared helper: the bound applies to the DECLARED
		// length, before anything is allocated or decoded. The reader blocks forever past the
		// prefix, so a reader that looked at the body would hang here instead of returning.
		r := &prefixOnlyReader{data: uvarint(1 << 30)}
		var got evidenceResponseMsg
		err := readFrame(bufio.NewReader(r), &got, 1024)
		require.ErrorIs(t, err, ErrEvidenceTransport)
		require.ErrorContains(t, err, "over the 1024 bound")
		require.NotErrorIs(t, err, errReachedForBody, "nothing may be allocated or read for a frame already over the bound")
		require.Equal(t, len(r.data), r.pos, "exactly the length prefix was read")
	})

	t.Run("a frame shorter than it declares is an error, not a partial message", func(t *testing.T) {
		body := append(uvarint(100), bytes.Repeat([]byte{0xa0}, 10)...)
		var got evidenceResponseMsg
		err := readFrame(bufio.NewReader(bytes.NewReader(body)), &got, 4096)
		require.ErrorIs(t, err, ErrEvidenceTransport)
		require.ErrorContains(t, err, "reading 100-byte frame")
	})

	t.Run("a zero-length frame is refused", func(t *testing.T) {
		var got evidenceResponseMsg
		err := readFrame(bufio.NewReader(bytes.NewReader(uvarint(0))), &got, 4096)
		require.ErrorIs(t, err, ErrEvidenceTransport)
		require.ErrorContains(t, err, "zero-length frame", "named as what it is, not as a decode failure")
	})

	t.Run("an oversized message is refused rather than truncated", func(t *testing.T) {
		var buf bytes.Buffer
		err := writeFrame(&buf, &evidenceRequestMsg{HeldIdentity: bytes.Repeat([]byte{0xff}, 512)}, 64)
		require.ErrorIs(t, err, ErrEvidenceTransport)
		require.ErrorIs(t, err, errFrameTooLarge)
		require.Zero(t, buf.Len(), "nothing may reach the peer, so a refusal can still be sent")
	})
}

// stubProvider answers with whatever it is given, so the serving policy can be tested against every
// named outcome without constructing the buffer state that produces it.
type stubProvider struct {
	ev  AnchorEvidence
	err error
}

func (p stubProvider) Assemble(EvidenceRequest) (AnchorEvidence, error) { return p.ev, p.err }

// exchange runs one request against one server over an in-memory pipe and returns what the client
// side made of the answer.
func exchange(t *testing.T, s *EvidenceServer, req EvidenceRequest, limits EvidenceTransportLimits) (AnchorEvidence, error) {
	t.Helper()
	return exchangeFrom(t, s, "test-peer", req, limits)
}

// exchangeFrom is the same, naming the peer the request appears to come from, so that admission can
// be exercised with more than one of them.
func exchangeFrom(t *testing.T, s *EvidenceServer, from string, req EvidenceRequest, limits EvidenceTransportLimits) (AnchorEvidence, error) {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = s.Serve(context.Background(), server, from)
		_ = server.Close()
	}()
	require.NoError(t, client.SetDeadline(time.Now().Add(5*time.Second)))
	ev, err := exchangeEvidence(client, req, limits)
	_ = client.Close()
	wg.Wait()
	return ev, err
}

func testServer(t *testing.T, p EvidenceProvider) *EvidenceServer {
	t.Helper()
	s, err := NewEvidenceServer(p, DefaultEvidenceTransportLimits, nil)
	require.NoError(t, err)
	return s
}

func TestEvidenceTransport_ServesAChainThePredicateAccepts(t *testing.T) {
	f := newEvidenceFixture(t)
	b := newTestBuffer(t)
	obs := quietTailObserved(t, f)
	mustObserve(t, b, obs...)
	held := obs[2].UC

	ev, err := exchange(t, testServer(t, b), requestFor(t, held), DefaultEvidenceTransportLimits)
	require.NoError(t, err)

	anchor, err := verifyAssembled(t, f, ev, held)
	require.NoError(t, err)
	require.Equal(t, Hash(h32(0xbb)), anchor.BlockHash)
	require.EqualValues(t, 10, anchor.Round)
}

func TestEvidenceTransport_NamedRefusalsSurviveTheWire(t *testing.T) {
	req := EvidenceRequest{HeldRound: 16, HeldIdentity: []byte{0x01}}

	for _, tc := range []struct {
		name string
		from error
		want error
	}{
		{"not ready", ErrProviderNotReady, ErrProviderNotReady},
		{"evicted", ErrProviderEvicted, ErrProviderEvicted},
		{"behind", ErrProviderBehind, ErrProviderBehind},
		{"mismatch", ErrProviderMismatch, ErrProviderMismatch},
		{"anything else is reported as no less specific than not-ready", errors.New("something local"), ErrProviderNotReady},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := exchange(t, testServer(t, stubProvider{err: tc.from}), req, DefaultEvidenceTransportLimits)
			require.ErrorIs(t, err, tc.want)
			require.NotErrorIs(t, err, ErrEvidenceTransport, "a refusal delivered intact is not a transport failure")
		})
	}
}

func TestEvidenceTransport_RefusesWhatItCannotStandBehind(t *testing.T) {
	f := newEvidenceFixture(t)

	t.Run("a request that names no certificate is refused", func(t *testing.T) {
		// Round alone is not an identity. Answering it would mean choosing which certificate for
		// that round the requester "probably" meant.
		_, err := exchange(t, testServer(t, stubProvider{}), EvidenceRequest{HeldRound: 16}, DefaultEvidenceTransportLimits)
		require.ErrorIs(t, err, ErrEvidenceTransport)
		require.ErrorContains(t, err, "pinned")
	})

	// longChain is five certificates, so that a bound of three is exceeded at both ends.
	longChain := func() AnchorEvidence {
		src := f.cert(10, 100, h32(0x0a), h32(0x0b), h32(0xbb), 12)
		long := AnchorEvidence{Source: src.UC, SourceTechnical: src.Technical}
		for i := 0; i < 4; i++ {
			long.Tail = append(long.Tail, f.cert(12, 110, h32(0x0b), h32(0x0b), nil, 16))
		}
		return long
	}

	// The two ends are tested separately and asserted on their OWN wording. Testing them together
	// proves nothing about either: with both bounds in force, whichever end refuses first satisfies
	// an assertion that only looks for "a refusal".
	t.Run("a provider does not send a chain longer than the transport carries", func(t *testing.T) {
		tight := DefaultEvidenceTransportLimits
		tight.MaxCertificates = 3
		s, err := NewEvidenceServer(stubProvider{ev: longChain()}, tight, nil)
		require.NoError(t, err)

		_, err = exchange(t, s, EvidenceRequest{HeldRound: 12, HeldIdentity: []byte{0x01}}, DefaultEvidenceTransportLimits)
		require.ErrorIs(t, err, ErrEvidenceTransport)
		require.ErrorContains(t, err, "5 certificates, over the 3 this transport carries",
			"the refusal is the provider's own, reached before it sent anything")
	})

	t.Run("a requester does not accept a chain longer than it will verify", func(t *testing.T) {
		// The mirror image: a provider running looser bounds, or none, cannot make a requester
		// carry around a chain it has already established it will refuse.
		s, err := NewEvidenceServer(stubProvider{ev: longChain()}, DefaultEvidenceTransportLimits, nil)
		require.NoError(t, err)
		tight := DefaultEvidenceTransportLimits
		tight.MaxCertificates = 3

		_, err = exchange(t, s, EvidenceRequest{HeldRound: 12, HeldIdentity: []byte{0x01}}, tight)
		require.ErrorIs(t, err, ErrEvidenceTransport)
		require.ErrorContains(t, err, "5 certificates, over the 3 bound")
	})

	t.Run("a bundle over the byte bound is a named refusal too", func(t *testing.T) {
		src := f.cert(10, 100, h32(0x0a), h32(0x0b), h32(0xbb), 12)
		big := AnchorEvidence{Source: src.UC, SourceTechnical: src.Technical}
		for i := 0; i < 8; i++ {
			big.Tail = append(big.Tail, f.cert(12, 110, h32(0x0b), h32(0x0b), nil, 16))
		}
		limits := DefaultEvidenceTransportLimits
		limits.MaxResponseBytes = evidenceMinResponseBytes // room for a refusal, not for this chain

		s, err := NewEvidenceServer(stubProvider{ev: big}, limits, nil)
		require.NoError(t, err)
		_, err = exchange(t, s, EvidenceRequest{HeldRound: 10, HeldIdentity: []byte{0x01}}, limits)
		require.ErrorIs(t, err, ErrEvidenceTransport)
		require.ErrorContains(t, err, "larger than this transport carries")
	})

	t.Run("beyond the concurrency bound requests are refused, not queued", func(t *testing.T) {
		// A queue under load is somewhere for an attacker's work to accumulate. The first request
		// is held inside Assemble; the second must come back immediately.
		release := make(chan struct{})
		p := &blockingProvider{release: release, entered: make(chan struct{}, 1)}
		s, err := NewEvidenceServer(p, EvidenceTransportLimits{
			MaxRequestBytes: 4096, MaxResponseBytes: 4096, MaxCertificates: 8,
			Deadline: 5 * time.Second, MaxConcurrentServes: 1,
			MaxPendingStreams: 8, MaxPendingStreamsPerPeer: 8,
		}, nil)
		require.NoError(t, err)

		first, firstServer := net.Pipe()
		go func() { _ = s.Serve(context.Background(), firstServer, "peer-a") }()
		require.NoError(t, first.SetDeadline(time.Now().Add(5*time.Second)))
		go func() {
			_, _ = exchangeEvidence(first, EvidenceRequest{HeldRound: 1, HeldIdentity: []byte{1}}, DefaultEvidenceTransportLimits)
		}()
		<-p.entered

		_, err = exchange(t, s, EvidenceRequest{HeldRound: 1, HeldIdentity: []byte{1}}, DefaultEvidenceTransportLimits)
		require.ErrorIs(t, err, ErrEvidenceTransport)
		require.ErrorContains(t, err, "maximum number of requests")

		close(release)
		_ = first.Close()
		_ = firstServer.Close()
	})
}

// blockingProvider holds one Assemble call open until released, and announces that it has been
// entered, so the concurrency bound can be tested without sleeping.
type blockingProvider struct {
	release chan struct{}
	entered chan struct{}
}

func (p *blockingProvider) Assemble(EvidenceRequest) (AnchorEvidence, error) {
	select {
	case p.entered <- struct{}{}:
	default:
	}
	select {
	case <-p.release:
	case <-time.After(2 * time.Second):
		// A ceiling, so that a bound which stops working shows up as a wrong answer rather than as
		// a test that hangs until the suite times out.
	}
	return AnchorEvidence{}, ErrProviderNotReady
}

func TestEvidenceTransport_TrustsNothingItIsTold(t *testing.T) {
	f := newEvidenceFixture(t)

	// hostile writes a response of the caller's choosing straight onto the wire, standing in for a
	// provider that does not follow the protocol.
	hostile := func(t *testing.T, resp *evidenceResponseMsg, limits EvidenceTransportLimits) error {
		t.Helper()
		client, server := net.Pipe()
		t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
		go func() {
			var req evidenceRequestMsg
			if err := readFrame(bufio.NewReader(server), &req, 4096); err != nil {
				return
			}
			_ = writeFrame(server, resp, 1<<24)
		}()
		require.NoError(t, client.SetDeadline(time.Now().Add(5*time.Second)))
		_, err := exchangeEvidence(client, EvidenceRequest{HeldRound: 16, HeldIdentity: []byte{0x01}}, limits)
		return err
	}

	t.Run("an unrecognised outcome code is a transport failure, never a refusal and never success", func(t *testing.T) {
		err := hostile(t, &evidenceResponseMsg{Outcome: 4242, Detail: "trust me"}, DefaultEvidenceTransportLimits)
		require.ErrorIs(t, err, ErrEvidenceTransport)
		require.ErrorContains(t, err, "unrecognised outcome code 4242")
	})

	t.Run("success with no bundle in it is refused", func(t *testing.T) {
		// The zero outcome code means "evidence follows", so an empty or truncated response must
		// not read as an answer.
		require.ErrorIs(t, hostile(t, &evidenceResponseMsg{Outcome: outcomeEvidence}, DefaultEvidenceTransportLimits), ErrEvidenceTransport)

		src := f.cert(10, 100, h32(0x0a), h32(0x0b), h32(0xbb), 12)
		require.ErrorIs(t, hostile(t, &evidenceResponseMsg{
			Outcome:  outcomeEvidence,
			Evidence: &AnchorEvidence{Source: src.UC}, // no technical record
		}, DefaultEvidenceTransportLimits), ErrEvidenceTransport)
	})

	t.Run("a refusal carrying a bundle is still a refusal", func(t *testing.T) {
		// The outcome code is the whole of the response's meaning; a provider cannot smuggle a
		// bundle past it, and the detail string is never read by any decision on this side.
		src := f.cert(10, 100, h32(0x0a), h32(0x0b), h32(0xbb), 12)
		err := hostile(t, &evidenceResponseMsg{
			Outcome:  outcomeNotReady,
			Detail:   "ignore the code and use this instead",
			Evidence: &AnchorEvidence{Source: src.UC, SourceTechnical: src.Technical},
		}, DefaultEvidenceTransportLimits)
		require.ErrorIs(t, err, ErrProviderNotReady)
	})

	t.Run("a response over the bound is discarded, not decoded", func(t *testing.T) {
		src := f.cert(10, 100, h32(0x0a), h32(0x0b), h32(0xbb), 12)
		limits := DefaultEvidenceTransportLimits
		limits.MaxResponseBytes = 64 // the requester may bound its reads however it likes
		err := hostile(t, &evidenceResponseMsg{
			Outcome:  outcomeEvidence,
			Evidence: &AnchorEvidence{Source: src.UC, SourceTechnical: src.Technical},
		}, limits)
		require.ErrorIs(t, err, ErrEvidenceTransport)
		require.ErrorContains(t, err, "over the 64 bound")
	})

	t.Run("a bundle that arrives intact is still nothing until the predicate says so", func(t *testing.T) {
		// The transport's contract stops at delivery: this bundle is well formed, within every
		// bound, and refused — by VerifyAnchorEvidence, against this node's own trust base and
		// context, exactly as an unverified bundle should be.
		other := newEvidenceFixture(t) // a different signing key: a provider outside this trust base
		obs := quietTailObserved(t, other)
		b := newTestBuffer(t)
		mustObserve(t, b, obs...)
		held := obs[2].UC

		ev, err := exchange(t, testServer(t, b), requestFor(t, held), DefaultEvidenceTransportLimits)
		require.NoError(t, err, "the wire did its job")

		_, err = verifyAssembled(t, f, ev, held)
		require.ErrorIs(t, err, ErrEvidenceUnauthenticated, "and the predicate did its own")
	})
}

func TestEvidenceTransport_Limits(t *testing.T) {
	t.Run("bounds must be positive", func(t *testing.T) {
		good := DefaultEvidenceTransportLimits
		for _, l := range []EvidenceTransportLimits{
			{}, mutate(good, func(l *EvidenceTransportLimits) { l.MaxRequestBytes = 0 }),
			mutate(good, func(l *EvidenceTransportLimits) { l.MaxResponseBytes = 0 }),
			mutate(good, func(l *EvidenceTransportLimits) { l.MaxResponseBytes = 8 }), // no room for a refusal
			mutate(good, func(l *EvidenceTransportLimits) { l.MaxCertificates = 0 }),
			mutate(good, func(l *EvidenceTransportLimits) { l.Deadline = 0 }),
			mutate(good, func(l *EvidenceTransportLimits) { l.MaxConcurrentServes = 0 }),
		} {
			_, err := NewEvidenceServer(stubProvider{}, l, nil)
			require.Error(t, err)
		}
	})

	t.Run("a server needs a provider", func(t *testing.T) {
		_, err := NewEvidenceServer(nil, DefaultEvidenceTransportLimits, nil)
		require.Error(t, err)
	})

	t.Run("the response bound is not tighter than what the predicate accepts", func(t *testing.T) {
		// The two bounds must not disagree about the same bundle: a chain the predicate would
		// accept must not be refused by the transport carrying it.
		require.Greater(t, DefaultEvidenceTransportLimits.MaxResponseBytes, DefaultAnchorEvidenceLimits.MaxBytes)
		require.Equal(t, DefaultEvidenceTransportLimits.MaxCertificates, DefaultAnchorEvidenceLimits.MaxCertificates)
	})

	t.Run("a request cannot be sent without the certificate it is pinned to", func(t *testing.T) {
		_, err := RequestAnchorEvidence(context.Background(), nil, "", EvidenceRequest{HeldRound: 3}, DefaultEvidenceTransportLimits)
		require.ErrorIs(t, err, ErrEvidenceTransport)
	})
}

func mutate(l EvidenceTransportLimits, f func(*EvidenceTransportLimits)) EvidenceTransportLimits {
	f(&l)
	return l
}

/*
Admission: the tier that bounds streams which never become requests.

The second tier (MaxConcurrentServes) counts assembly, which only a well-formed request reaches, so
by itself it bounds nothing against a peer that opens streams and sends nothing, half a length
prefix, or a body it never finishes. libp2p multiplexes as many streams as a peer likes over one
connection, so "one request per stream" is not "one request per connection".
*/

// stalledStreams starts n Serve calls from one peer whose clients never write, and returns a
// function that closes them. Each Serve that is admitted blocks inside readFrame.
func stalledStreams(t *testing.T, s *EvidenceServer, from string, n int) func() {
	t.Helper()
	var conns []net.Conn
	for i := 0; i < n; i++ {
		client, server := net.Pipe()
		conns = append(conns, client, server)
		go func() { _ = s.Serve(context.Background(), server, from) }()
	}
	return func() {
		for _, c := range conns {
			_ = c.Close()
		}
	}
}

func admissionServer(t *testing.T, provider EvidenceProvider, total, perPeer int) *EvidenceServer {
	t.Helper()
	limits := DefaultEvidenceTransportLimits
	limits.MaxPendingStreams = total
	limits.MaxPendingStreamsPerPeer = perPeer
	s, err := NewEvidenceServer(provider, limits, nil)
	require.NoError(t, err)
	return s
}

// serveExpectingRefusal runs one Serve that admission should turn away, with a ceiling: a bound that
// stops working shows up as an admitted stream blocked on a read that nobody will ever satisfy, and
// this reports that as a wrong answer rather than hanging the suite.
func serveExpectingRefusal(t *testing.T, s *EvidenceServer, from string) error {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	done := make(chan error, 1)
	go func() { done <- s.Serve(context.Background(), server, from) }()
	select {
	case err := <-done:
		return err
	case <-time.After(2 * time.Second):
		return errors.New("Serve did not return: the stream was admitted and is blocked reading")
	}
}

func waitForPending(t *testing.T, s *EvidenceServer, want int) {
	t.Helper()
	require.Eventually(t, func() bool {
		got, _ := s.Pending()
		return got == want
	}, 3*time.Second, 5*time.Millisecond, "expected %d admitted streams", want)
}

func TestEvidenceTransport_Admission(t *testing.T) {
	f := newEvidenceFixture(t)
	buffer := newTestBuffer(t)
	obs := quietTailObserved(t, f)
	mustObserve(t, buffer, obs...)
	held := obs[2].UC

	t.Run("stalled streams are counted before anything is read", func(t *testing.T) {
		// The reproduction: with the bound applied only after readFrame, every one of these reaches
		// a blocked reader and none of them is counted anywhere.
		s := admissionServer(t, buffer, 2, 2)
		closeAll := stalledStreams(t, s, "peer-a", 2)
		defer closeAll()
		waitForPending(t, s, 2)

		require.ErrorIs(t, serveExpectingRefusal(t, s, "peer-a"), ErrNotAdmitted)

		got, _ := s.Pending()
		require.Equal(t, 2, got, "a refused stream takes no slot")
	})

	t.Run("a peer cannot spend more than its own share", func(t *testing.T) {
		// Without a per-peer bound, one peer holding the whole global budget refuses every honest
		// validator — the availability loss this protocol exists to repair, from the other side.
		s := admissionServer(t, buffer, 8, 2)
		closeAll := stalledStreams(t, s, "greedy", 2)
		defer closeAll()
		waitForPending(t, s, 2)

		require.ErrorIs(t, serveExpectingRefusal(t, s, "greedy"), ErrNotAdmitted)

		// And the honest peer is served, over the same server, at the same moment.
		ev, err := exchangeFrom(t, s, "honest", requestFor(t, held), DefaultEvidenceTransportLimits)
		require.NoError(t, err)
		_, err = verifyAssembled(t, f, ev, held)
		require.NoError(t, err)
	})

	t.Run("the global bound applies to a peer still inside its own share", func(t *testing.T) {
		s := admissionServer(t, buffer, 2, 2)
		closeA := stalledStreams(t, s, "peer-a", 1)
		defer closeA()
		closeB := stalledStreams(t, s, "peer-b", 1)
		defer closeB()
		waitForPending(t, s, 2)

		require.ErrorIs(t, serveExpectingRefusal(t, s, "peer-c"), ErrNotAdmitted)
	})

	t.Run("a stream that is not admitted is told nothing", func(t *testing.T) {
		// No busy frame: writing a refusal into a stream whose peer may still be writing its own
		// request is the deadlock the read-first ordering exists to avoid, and the reset says all
		// there is to say.
		s := admissionServer(t, buffer, 1, 1)
		closeAll := stalledStreams(t, s, "peer-a", 1)
		defer closeAll()
		waitForPending(t, s, 1)

		client, server := net.Pipe()
		defer func() { _ = client.Close(); _ = server.Close() }()
		done := make(chan error, 1)
		go func() { done <- s.Serve(context.Background(), server, "peer-b") }()

		// Read first, and concurrently with the handler: a server that answers a stream it did not
		// admit would block here writing, which is the deadlock this rule avoids.
		require.NoError(t, client.SetReadDeadline(time.Now().Add(300*time.Millisecond)))
		buf := make([]byte, 1)
		_, err := client.Read(buf)
		require.Error(t, err, "nothing may be written to a stream that was not admitted")

		select {
		case err := <-done:
			require.ErrorIs(t, err, ErrNotAdmitted)
		case <-time.After(2 * time.Second):
			t.Fatal("Serve did not return")
		}
	})

	t.Run("every exit path releases its slot", func(t *testing.T) {
		// A slot leaked by one early return is a bound that erodes to zero over a process's life.
		s := admissionServer(t, buffer, 4, 4)

		// success
		_, err := exchangeFrom(t, s, "p", requestFor(t, held), DefaultEvidenceTransportLimits)
		require.NoError(t, err)
		// a malformed request
		_, err = exchangeFrom(t, s, "p", EvidenceRequest{HeldRound: 3}, DefaultEvidenceTransportLimits)
		require.Error(t, err)
		// a provider refusal
		_, err = exchangeFrom(t, s, "p", EvidenceRequest{HeldRound: 99, HeldIdentity: []byte{9}}, DefaultEvidenceTransportLimits)
		require.Error(t, err)
		// a read that fails: the client closes without writing anything
		client, server := net.Pipe()
		go func() { _ = client.Close() }()
		require.Error(t, s.Serve(context.Background(), server, "p"))
		_ = server.Close()

		streams, peers := s.Pending()
		require.Zero(t, streams)
		require.Zero(t, peers, "the per-peer map does not grow with every peer ever seen")
	})

	t.Run("admission bounds are validated", func(t *testing.T) {
		good := DefaultEvidenceTransportLimits
		for _, l := range []EvidenceTransportLimits{
			mutate(good, func(l *EvidenceTransportLimits) { l.MaxPendingStreams = 0 }),
			mutate(good, func(l *EvidenceTransportLimits) { l.MaxPendingStreamsPerPeer = 0 }),
			// A per-peer bound above the global one could never apply.
			mutate(good, func(l *EvidenceTransportLimits) { l.MaxPendingStreamsPerPeer = l.MaxPendingStreams + 1 }),
		} {
			_, err := NewEvidenceServer(stubProvider{}, l, nil)
			require.Error(t, err)
		}
	})

	t.Run("the assembly bound is not the stream bound", func(t *testing.T) {
		require.LessOrEqual(t, DefaultEvidenceTransportLimits.MaxConcurrentServes, DefaultEvidenceTransportLimits.MaxPendingStreams,
			"a server that admits fewer streams than it will assemble has one tier, not two")
	})
}

/*
Cancellation and deadlines, after the stream is open.

A context cannot interrupt a read or a write already inside the transport; only acting on the stream
can. These tests drive requestOverStream — the whole client half except CreateStream — over a pipe,
so what is asserted is that a cancelled caller is released promptly, and that the budget the caller
set is the budget the stream gets.
*/

// pipeStream adapts a net.Pipe end to the small stream contract the client half needs. Reset closes
// the connection, which is what a libp2p reset does to I/O in flight: aborts it.
type pipeStream struct {
	net.Conn
	mu       sync.Mutex
	deadline time.Time
	reset    bool
}

func (p *pipeStream) CloseWrite() error { return nil }

func (p *pipeStream) SetDeadline(t time.Time) error {
	p.mu.Lock()
	p.deadline = t
	p.mu.Unlock()
	return p.Conn.SetDeadline(t)
}

func (p *pipeStream) Reset() error {
	p.mu.Lock()
	p.reset = true
	p.mu.Unlock()
	return p.Conn.Close()
}

func (p *pipeStream) state() (time.Time, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.deadline, p.reset
}

func TestEvidenceTransport_CancellationAfterDialing(t *testing.T) {
	f := newEvidenceFixture(t)
	buffer := newTestBuffer(t)
	obs := quietTailObserved(t, f)
	mustObserve(t, buffer, obs...)
	held := obs[2].UC
	req := requestFor(t, held)

	// A deadline long enough that nothing but cancellation could end these calls.
	patient := DefaultEvidenceTransportLimits
	patient.Deadline = 30 * time.Second

	t.Run("a cancelled caller is released from a blocked read", func(t *testing.T) {
		client, server := net.Pipe()
		defer func() { _ = server.Close() }()
		st := &pipeStream{Conn: client}

		// The peer reads the request and then holds the response forever.
		read := make(chan struct{})
		release := make(chan struct{})
		peerDone := make(chan struct{})
		defer func() { close(release); _ = server.Close(); <-peerDone }()
		go func() {
			defer close(peerDone)
			var got evidenceRequestMsg
			_ = readFrame(bufio.NewReader(server), &got, 4096)
			close(read)
			<-release
		}()

		ctx, cancel := context.WithTimeout(context.Background(), patient.Deadline)
		defer cancel()
		done := make(chan error, 1)
		go func() {
			_, err := requestOverStream(ctx, st, req, patient)
			done <- err
		}()
		<-read
		cancel()

		select {
		case err := <-done:
			require.ErrorIs(t, err, ErrEvidenceTransport)
			require.ErrorIs(t, err, context.Canceled, "the reason is reported, not whatever I/O error the reset produced")
		case <-time.After(5 * time.Second):
			t.Fatal("cancellation did not interrupt the blocked read")
		}
		_, wasReset := st.state()
		require.True(t, wasReset)
	})

	t.Run("a cancelled caller is released from a blocked write", func(t *testing.T) {
		// Nobody ever reads, so the request write itself blocks on an unbuffered stream.
		client, server := net.Pipe()
		defer func() { _ = server.Close() }()
		st := &pipeStream{Conn: client}

		ctx, cancel := context.WithTimeout(context.Background(), patient.Deadline)
		defer cancel()
		done := make(chan error, 1)
		go func() {
			_, err := requestOverStream(ctx, st, req, patient)
			done <- err
		}()
		time.Sleep(50 * time.Millisecond) // let the write block
		cancel()

		select {
		case err := <-done:
			require.ErrorIs(t, err, context.Canceled)
		case <-time.After(5 * time.Second):
			t.Fatal("cancellation did not interrupt the blocked write")
		}
	})

	t.Run("the caller's own deadline is the stream's, not a fresh interval", func(t *testing.T) {
		// A budget restarted after dialing is a budget the caller did not set. The stream gets the
		// derived context's deadline, so dialing and the exchange spend the same one.
		client, server := net.Pipe()
		defer func() { _ = server.Close() }()
		st := &pipeStream{Conn: client}

		ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
		defer cancel()
		want, ok := ctx.Deadline()
		require.True(t, ok)

		start := time.Now()
		_, err := requestOverStream(ctx, st, req, patient) // nobody reads; only the deadline can end this
		require.ErrorIs(t, err, context.DeadlineExceeded)
		require.Less(t, time.Since(start), 5*time.Second, "the 30s transport deadline must not have replaced the caller's")

		got, _ := st.state()
		require.WithinDuration(t, want, got, time.Millisecond, "the stream deadline is the context's")
	})

	t.Run("a completed exchange leaves nothing that could reset the stream later", func(t *testing.T) {
		s := admissionServer(t, buffer, 4, 4)
		client, server := net.Pipe()
		defer func() { _ = server.Close() }()
		st := &pipeStream{Conn: client}
		go func() { _ = s.Serve(context.Background(), server, "peer") }()

		ctx, cancel := context.WithTimeout(context.Background(), patient.Deadline)
		ev, err := requestOverStream(ctx, st, req, patient)
		require.NoError(t, err)
		_, err = verifyAssembled(t, f, ev, held)
		require.NoError(t, err)

		_, wasReset := st.state()
		require.False(t, wasReset, "a successful exchange is closed, not reset")

		cancel() // the watcher is stopped and joined before the call returned, so this does nothing
		time.Sleep(50 * time.Millisecond)
		_, wasReset = st.state()
		require.False(t, wasReset, "cancelling afterwards must not reach a stream this call has finished with")
	})
}
