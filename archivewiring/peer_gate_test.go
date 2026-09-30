package archivewiring

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/unicitynetwork/bft-core/archive"
	testpeer "github.com/unicitynetwork/bft-core/internal/testutils/peer"
)

func TestDefaultArchivePeerLimitIsFourAndGlobalLimitRemainsBounded(t *testing.T) {
	limits := DefaultLimits()
	if limits.PerPeer != 4 || limits.Pending <= 0 || limits.Pending > 64 {
		t.Fatalf("unexpected archive limits: %+v", limits)
	}
}

func TestPeerGateAllowsFourArchiveStreamsAndQueuesFifth(t *testing.T) {
	q, rec := transportFixture()
	sender := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	receiver := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	sender.Network().Peerstore().AddAddrs(receiver.ID(), receiver.MultiAddresses(), peerstore.PermanentAddrTTL)
	store, err := archive.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{}, 5)
	release := make(chan struct{})
	var active, peak atomic.Int32
	server, err := NewServer(store, q.Context, func(context.Context, archive.Request, *archive.Record) error {
		n := active.Add(1)
		for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
		}
		entered <- struct{}{}
		<-release
		active.Add(-1)
		return nil
	}, []peer.ID{sender.ID()}, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	server.Register(context.Background(), receiver)
	gated, err := NewPeerGatedHost(sender, DefaultLimits().PerPeer)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	errCh := make(chan error, 5)
	for i := 0; i < 5; i++ {
		go func() { errCh <- PutAndReadBack(ctx, gated, receiver.ID(), q, rec, DefaultLimits()) }()
	}
	for i := 0; i < 4; i++ {
		select {
		case <-entered:
		case <-ctx.Done():
			t.Fatal("fourth archive operation did not reach receiver")
		}
	}
	waitFor(t, 2*time.Second, func() bool {
		gated.mu.Lock()
		defer gated.mu.Unlock()
		return gated.peers[receiver.ID()] != nil && gated.peers[receiver.ID()].refs == 5
	})
	if got := peak.Load(); got != 4 {
		t.Fatalf("receiver concurrency before release = %d, want 4", got)
	}
	close(release)
	for i := 0; i < 5; i++ {
		select {
		case err := <-errCh:
			if err != nil {
				t.Fatalf("archive operation %d: %v", i, err)
			}
		case <-ctx.Done():
			t.Fatal("queued archive operation did not finish")
		}
	}
	if got := peak.Load(); got > 4 {
		t.Fatalf("peer gate allowed %d concurrent verifier calls", got)
	}
}

func TestPerPeerResetIsTypedLoggedAndRetried(t *testing.T) {
	q, rec := transportFixture()
	sender := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	receiver := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	sender.Network().Peerstore().AddAddrs(receiver.ID(), receiver.MultiAddresses(), peerstore.PermanentAddrTTL)
	store, err := archive.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	resetEvents := make(chan slog.Record, 4)
	entered := make(chan struct{}, 4)
	release := make(chan struct{})
	server, err := NewServer(store, q.Context, func(context.Context, archive.Request, *archive.Record) error {
		entered <- struct{}{}
		<-release
		return nil
	}, []peer.ID{sender.ID()}, Limits{Deadline: 5 * time.Second, Pending: 8, PerPeer: 4})
	if err != nil {
		t.Fatal(err)
	}
	server.SetLogger(slog.New(resetCaptureHandler{events: resetEvents}))
	server.Register(context.Background(), receiver)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	first := make(chan error, 4)
	for i := 0; i < 4; i++ {
		go func() {
			first <- PutAndReadBack(ctx, sender, receiver.ID(), q, rec, Limits{Deadline: 5 * time.Second, Pending: 8, PerPeer: 4})
		}()
	}
	for i := 0; i < 4; i++ {
		select {
		case <-entered:
		case <-ctx.Done():
			t.Fatal("four archive streams did not enter verifier")
		}
	}
	// Verify a direct decoding of the admission response yields the typed peer
	// limit before the end-to-end call exercises its bounded retry path.
	if err := decodeResetFrame(resetFrame(ErrPeerLimit), receiver.ID(), []byte{1}); !errors.Is(err, ErrPeerLimit) {
		t.Fatalf("typed peer reset: %v", err)
	}
	fifth := make(chan error, 1)
	go func() {
		fifth <- PutAndReadBack(ctx, sender, receiver.ID(), q, rec, Limits{Deadline: 5 * time.Second, Pending: 8, PerPeer: 4})
	}()
	select {
	case event := <-resetEvents:
		attrs := make(map[string]string)
		event.Attrs(func(a slog.Attr) bool {
			if value, ok := a.Value.Any().(string); ok {
				attrs[a.Key] = value
			}
			return true
		})
		if event.Message != "archive stream reset" || attrs["peer"] != sender.ID().String() || attrs["operation"] != "put" || attrs["reason"] != "per_peer_limit" {
			t.Fatalf("reset log did not identify peer, operation, and typed reason: %q %#v", event.Message, attrs)
		}
	case <-ctx.Done():
		t.Fatal("fifth operation did not receive a per-peer reset")
	}
	close(release)
	for i := 0; i < 4; i++ {
		select {
		case err := <-first:
			if err != nil {
				t.Fatalf("initial archive operation: %v", err)
			}
		case <-ctx.Done():
			t.Fatal("initial archive operation did not finish")
		}
	}
	select {
	case err := <-fifth:
		if err != nil {
			t.Fatalf("fifth operation was not retried successfully: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("fifth operation retry did not finish")
	}
}

func waitFor(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition did not become true before timeout")
}

type resetCaptureHandler struct{ events chan slog.Record }

func (h resetCaptureHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h resetCaptureHandler) Handle(_ context.Context, r slog.Record) error {
	if r.Message == "archive stream reset" {
		select {
		case h.events <- r.Clone():
		default:
		}
	}
	return nil
}

func (h resetCaptureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h resetCaptureHandler) WithGroup(string) slog.Handler      { return h }
