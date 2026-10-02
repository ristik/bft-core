package archivewiring

import (
	"bytes"
	"context"
	"encoding/binary"
	"log/slog"
	"os"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/handoffdelivery"
	"github.com/unicitynetwork/bft-core/internal/testutils/handoffbundle"
	testpeer "github.com/unicitynetwork/bft-core/internal/testutils/peer"
)

type logSink struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *logSink) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}
func (l *logSink) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.buf.String() }

// handoffCopies is one handoff certified by two different valid three-of-four quorum subsets, and a third bundle that verifies as a
// handoff of its own but is semantically different (another successor activation).
type handoffCopies struct {
	q                archive.BundleRequest
	one, other, diff []byte
	verify           BundleVerifier
}

func newHandoffCopies(t *testing.T) handoffCopies {
	t.Helper()
	f := handoffbundle.New(t)
	base := handoffdelivery.Bundle{Proof: f.Proof, Body: f.Body, Snapshot: f.Snapshot}
	raw, err := handoffdelivery.EncodeBundle(base)
	require.NoError(t, err)
	clone := func() handoffdelivery.Bundle {
		b, err := handoffdelivery.DecodeBundle(raw)
		require.NoError(t, err)
		return b
	}
	full := clone()
	message, err := full.Proof.CommitQC.LedgerCommitInfo.SigBytes()
	require.NoError(t, err)
	sig, err := f.Nodes[3].Signer.SignBytes(message)
	require.NoError(t, err)
	full.Proof.CommitQC.Signatures[f.Nodes[3].PeerConf.ID.String()] = sig
	full.Snapshot.CommitQc = full.Proof.CommitQC
	var ids []string
	for id := range full.Proof.CommitQC.Signatures {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	drop := func(id string) []byte {
		b, err := handoffdelivery.DecodeBundle(mustEncode(t, full))
		require.NoError(t, err)
		delete(b.Proof.CommitQC.Signatures, id)
		b.Snapshot.CommitQc = b.Proof.CommitQC
		return mustEncode(t, b)
	}
	diff := clone()
	diff.Body.EarliestActivation++
	c := handoffCopies{q: archive.BundleRequest{Epoch: f.Body.Epoch}, one: drop(ids[0]), other: drop(ids[1]), diff: mustEncode(t, diff)}
	// Verification of the fixture's own bundles; the semantically different one is accepted by the stub (it is "verified" as far as
	// this test goes: the point is what the comparison does with two verified, different handoffs).
	c.verify = func(_ context.Context, _ archive.BundleRequest, raw []byte) error {
		b, err := handoffdelivery.DecodeBundle(raw)
		if err != nil {
			return err
		}
		if bytes.Equal(raw, c.diff) {
			return nil
		}
		_, err = handoffdelivery.Verify(b, f.Old, f.Partition, f.Shard, f.ConfHash)
		return err
	}
	return c
}

func mustEncode(t *testing.T, b handoffdelivery.Bundle) []byte {
	t.Helper()
	raw, err := handoffdelivery.EncodeBundle(b)
	require.NoError(t, err)
	return raw
}

func openStore(t *testing.T) *archive.Store {
	t.Helper()
	s, err := archive.Open(t.TempDir())
	require.NoError(t, err)
	return s
}

func quietLog() (*slog.Logger, *logSink) {
	sink := &logSink{}
	return slog.New(slog.NewTextHandler(sink, &slog.HandlerOptions{Level: slog.LevelDebug})), sink
}

func ctxQ(c handoffCopies) archive.BundleRequest {
	request, _ := transportFixture()
	c.q.Context = request.Context
	return c.q
}

// The same handoff under another valid signature subset keeps the first copy and succeeds.
func TestRetainBundleKeepsTheFirstCopyOfTheSameHandoff(t *testing.T) {
	c := newHandoffCopies(t)
	q := ctxQ(c)
	store := openStore(t)
	log, sink := quietLog()
	require.NotEqual(t, c.one, c.other)
	stored, err := RetainBundle(t.Context(), store, q, c.one, c.verify, log)
	require.NoError(t, err)
	require.True(t, stored)
	stored, err = RetainBundle(t.Context(), store, q, c.other, c.verify, log)
	require.NoError(t, err)
	require.False(t, stored, "the first copy is kept")
	got, err := store.GetBundle(q)
	require.NoError(t, err)
	require.Equal(t, c.one, got)
	require.Contains(t, sink.String(), "keeping the first copy")
	require.NotContains(t, sink.String(), "CONFLICTING")
}

// A verified bundle that differs in what it commits to is refused with ErrBundleConflict, loudly, and nothing is replaced.
func TestRetainBundleRefusesASemanticallyDifferentHandoffLoudly(t *testing.T) {
	c := newHandoffCopies(t)
	q := ctxQ(c)
	store := openStore(t)
	log, sink := quietLog()
	_, err := RetainBundle(t.Context(), store, q, c.one, c.verify, log)
	require.NoError(t, err)
	_, err = RetainBundle(t.Context(), store, q, c.diff, c.verify, log)
	require.ErrorIs(t, err, archive.ErrBundleConflict)
	require.Contains(t, sink.String(), "CONFLICTING HANDOFF BUNDLE")
	require.Contains(t, sink.String(), "level=ERROR")
	got, _ := store.GetBundle(q)
	require.Equal(t, c.one, got)
}

// Both bundles are verified BEFORE any comparison: a bundle that does not verify is refused as such, never reported as the same handoff
// or as a conflict.
func TestRetainBundleVerifiesBothCopiesBeforeComparing(t *testing.T) {
	c := newHandoffCopies(t)
	q := ctxQ(c)
	store := openStore(t)
	log, _ := quietLog()
	_, err := RetainBundle(t.Context(), store, q, c.one, c.verify, log)
	require.NoError(t, err)

	tampered := bytes.Clone(c.other)
	tampered[len(tampered)/2] ^= 0xff
	_, err = RetainBundle(t.Context(), store, q, tampered, c.verify, log)
	require.ErrorIs(t, err, ErrBundleUnverified, "an incoming bundle that does not verify")
	require.NotErrorIs(t, err, archive.ErrBundleConflict)

	refuseRetained := func(_ context.Context, _ archive.BundleRequest, raw []byte) error {
		if bytes.Equal(raw, c.one) {
			return ErrBinding
		}
		return c.verify(t.Context(), q, raw)
	}
	_, err = RetainBundle(t.Context(), store, q, c.other, refuseRetained, log)
	require.ErrorIs(t, err, ErrBundleUnverified, "a retained copy that does not verify")
	got, _ := store.GetBundle(q)
	require.Equal(t, c.one, got)
}

// A publication or replication problem never stops the node: the node's own activation from a verified bundle survives a conflicting or
// unverifiable archive copy. Only a fault of the local store may.
func TestActivationSurvivesAConflictingOrUnverifiableArchiveCopy(t *testing.T) {
	c := newHandoffCopies(t)
	q := ctxQ(c)
	store := openStore(t)
	log, sink := quietLog()
	require.NoError(t, RetainActivatedBundle(t.Context(), store, q, c.one, c.verify, log))
	require.NoError(t, RetainActivatedBundle(t.Context(), store, q, c.other, c.verify, log), "the same handoff")
	require.NoError(t, RetainActivatedBundle(t.Context(), store, q, c.diff, c.verify, log), "a conflicting copy is logged, not fatal")
	require.Contains(t, sink.String(), "CONFLICTING HANDOFF BUNDLE")
	tampered := bytes.Clone(c.other)
	tampered[len(tampered)/2] ^= 0xff
	require.NoError(t, RetainActivatedBundle(t.Context(), store, q, tampered, c.verify, log), "an unverifiable copy is logged, not fatal")
	require.Contains(t, sink.String(), "could not compare")

	if os.Geteuid() == 0 {
		t.Skip("a read-only directory does not stop root")
	}
	dir := t.TempDir()
	ro, err := archive.Open(dir)
	require.NoError(t, err)
	require.NoError(t, os.Chmod(dir, 0o500))
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	require.Error(t, RetainActivatedBundle(t.Context(), ro, q, c.one, c.verify, log), "a fault of the local store is returned")
}

// The replica keeps the first copy it was given, so a publisher whose copy is another valid subset of the same handoff must accept the
// read-back; a different handoff, or no way to verify, is not accepted.
func TestPublisherAcceptsTheReplicasEquivalentCopyOnReadBack(t *testing.T) {
	c := newHandoffCopies(t)
	request, _ := transportFixture()
	q := c.q
	q.Context = request.Context
	remote := openStore(t)
	log, _ := quietLog()
	_, err := RetainBundle(t.Context(), remote, q, c.one, c.verify, log)
	require.NoError(t, err)

	server, err := NewServer(remote, request.Context, func(context.Context, archive.Request, *archive.Record) error { return nil }, []peer.ID{"configured"}, DefaultLimits())
	require.NoError(t, err)
	server.SetBundleVerifier(c.verify)
	server.SetLogger(log)
	encoded, err := archive.EncodeBundleRequest(q)
	require.NoError(t, err)
	put := func(raw []byte) []byte {
		payload := append([]byte{5, 0, 0}, encoded...)
		binary.BigEndian.PutUint16(payload[1:3], uint16(len(encoded)))
		return append(payload, raw...)
	}
	answer, err := serveOne(t, server, put(c.other))
	require.NoError(t, err)
	require.Equal(t, []byte{1}, answer, "the replica accepts the other subset and keeps its first copy")
	got, _ := remote.GetBundle(q)
	require.Equal(t, c.one, got)
	_, err = serveOne(t, server, put(c.diff))
	require.ErrorIs(t, err, archive.ErrBundleConflict, "the replica refuses a semantically different handoff")

	same, err := SameBundle(t.Context(), q, c.verify, got, c.other)
	require.NoError(t, err)
	require.True(t, same)
	same, err = SameBundle(t.Context(), q, c.verify, got, c.diff)
	require.NoError(t, err)
	require.False(t, same)
	_, err = SameBundle(t.Context(), q, nil, got, c.other)
	require.ErrorIs(t, err, ErrConfig, "no verifier: the read-back cannot be judged equivalent")
}

// Over the wire: the replica keeps the first copy, and the publisher's read-back accepts it as the same handoff.
func TestPutBundleAndReadBackAcceptsTheReplicasEquivalentCopy(t *testing.T) {
	c := newHandoffCopies(t)
	request, _ := transportFixture()
	q := c.q
	q.Context = request.Context
	remote := openStore(t)
	log, _ := quietLog()
	_, err := RetainBundle(t.Context(), remote, q, c.one, c.verify, log)
	require.NoError(t, err)

	client := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	good := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	client.Network().Peerstore().AddAddrs(good.ID(), good.MultiAddresses(), peerstore.PermanentAddrTTL)
	server, err := NewServer(remote, request.Context, func(context.Context, archive.Request, *archive.Record) error { return nil }, []peer.ID{client.ID()}, DefaultLimits())
	require.NoError(t, err)
	server.SetBundleVerifier(c.verify)
	server.SetLogger(log)
	server.Register(context.Background(), good)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, PutBundleAndReadBack(ctx, client, good.ID(), q, c.other, DefaultLimits(), c.verify))
	require.ErrorIs(t, PutBundleAndReadBack(ctx, client, good.ID(), q, c.other, DefaultLimits(), nil), ErrReplica,
		"without a verifier only identical bytes are a successful read-back")
}

func TestReadBackMatchesOnlyTheSameHandoff(t *testing.T) {
	c := newHandoffCopies(t)
	q := ctxQ(c)
	require.True(t, readBackMatches(t.Context(), q, c.verify, c.one, c.one))
	require.True(t, readBackMatches(t.Context(), q, c.verify, c.one, c.other), "another subset of the same handoff")
	require.False(t, readBackMatches(t.Context(), q, c.verify, c.one, c.diff), "a different handoff")
	require.False(t, readBackMatches(t.Context(), q, nil, c.one, c.other), "no way to verify")
	tampered := bytes.Clone(c.other)
	tampered[len(tampered)/2] ^= 0xff
	require.False(t, readBackMatches(t.Context(), q, c.verify, c.one, tampered), "a copy that does not verify")
}
