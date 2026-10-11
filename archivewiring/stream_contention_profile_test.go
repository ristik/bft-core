package archivewiring

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/archive"
	testpeer "github.com/unicitynetwork/bft-core/internal/testutils/peer"
	"github.com/unicitynetwork/bft-core/shardnode"
)

// TestArchiveStreamContentionProfile measures one replica under the load a joiner meets on a running shard: publishers putting new
// records (each put is a put and a read-back) while the joiner fetches stored records one after another. It reports the joiner's
// fetch rate and latency and how many of its streams the replica reset for the global stream limit. STREAM_PROFILE_SECONDS selects
// the duration, STREAM_PROFILE_PUBLISHERS the number of publishers (unset: skipped).
func TestArchiveStreamContentionProfile(t *testing.T) {
	seconds, _ := strconv.Atoi(os.Getenv("STREAM_PROFILE_SECONDS"))
	if seconds == 0 {
		t.Skip("set STREAM_PROFILE_SECONDS")
	}
	publishers, _ := strconv.Atoi(os.Getenv("STREAM_PROFILE_PUBLISHERS"))
	if publishers == 0 {
		publishers = 3
	}
	f := newWiringFixture(t, 8)
	replica := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	storeDir := t.TempDir()
	store, err := archive.Open(storeDir)
	require.NoError(t, err)
	var stored []archive.Request
	var template *archive.Record
	var templateQ archive.Request
	for _, entry := range f.entries {
		q, rec, err := FromJournal(context.Background(), f.context, f.subject, nil, entry)
		require.NoError(t, err)
		require.NoError(t, store.Put(q, rec))
		stored = append(stored, q)
		template, templateQ = rec, q
	}
	clients := make([]peer.ID, 0, publishers+1)
	joiner := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	joiner.Network().Peerstore().AddAddrs(replica.ID(), replica.MultiAddresses(), peerstore.PermanentAddrTTL)
	clients = append(clients, joiner.ID())
	pubs := make([]*testPublisher, publishers)
	for i := range pubs {
		h := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
		h.Network().Peerstore().AddAddrs(replica.ID(), replica.MultiAddresses(), peerstore.PermanentAddrTTL)
		pubs[i] = &testPublisher{host: h}
		clients = append(clients, h.ID())
	}
	server, err := NewServer(store, f.subject, func(context.Context, archive.Request, *archive.Record) error { return nil }, clients, DefaultLimits())
	require.NoError(t, err)
	server.Register(context.Background(), replica)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(seconds)*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	var puts, putResets atomic.Int64
	for i, p := range pubs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; ctx.Err() == nil; n++ {
				// a new valid record of the same context: the template with a distinct header, addressed by that header's hash
				rec := *template
				rec.Header = append(slices.Clone(template.Header), byte(i), byte(n>>16), byte(n>>8), byte(n))
				q := templateQ
				q.BlockHash = [32]byte(crypto.Keccak256(rec.Header))
				err := PutAndReadBack(ctx, p.host, replica.ID(), q, &rec, DefaultLimits())
				switch {
				case err == nil:
					puts.Add(1)
				case busy(err):
					putResets.Add(1)
					select { // a real publisher waits for its next 2 s tick after a refusal
					case <-ctx.Done():
					case <-time.After(2 * time.Second):
					}
				case ctx.Err() != nil:
				default:
					t.Errorf("publisher %d: %v", i, err)
					return
				}
			}
		}()
	}
	var latencies []time.Duration
	var fetchResets, backoffs int
	var waited time.Duration
	delay := joinerBusyBackoffStart(t)
	started := time.Now()
	for i := 0; ctx.Err() == nil; {
		t0 := time.Now()
		_, err := Fetch(ctx, joiner, replica.ID(), stored[i%len(stored)], DefaultLimits())
		switch {
		case err == nil:
			latencies = append(latencies, time.Since(t0))
			i++
			delay = joinerBusyBackoffStart(t)
		case busy(err):
			// what the restore does when its replicas are busy: wait, doubling up to its ceiling, and ask again
			fetchResets++
			backoffs++
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
			case <-timer.C:
			}
			timer.Stop()
			waited += delay
			delay = min(delay*2, joinerBusyBackoffMax(t))
		case ctx.Err() != nil:
		default:
			t.Fatalf("joiner: %v", err)
		}
	}
	elapsed := time.Since(started)
	cancel()
	wg.Wait()
	// the replica may still be finishing requests it had accepted: wait until its store is quiet, so the temporary directory can go
	for quiet := 0; quiet < 3; {
		time.Sleep(200 * time.Millisecond)
		if staging, _ := filepath.Glob(filepath.Join(storeDir, ".writing-*")); len(staging) == 0 {
			quiet++
		} else {
			quiet = 0
		}
	}
	slices.Sort(latencies)
	pct := func(p float64) time.Duration {
		if len(latencies) == 0 {
			return 0
		}
		return latencies[min(len(latencies)-1, int(float64(len(latencies))*p))]
	}
	t.Logf("%d publishers, %s: joiner fetched %d records (%.1f/s), latency p50 %s p95 %s max %s; %d of its streams reset for a stream limit, %s spent backing off (start %s, ceiling %s)",
		publishers, elapsed.Round(time.Second), len(latencies), float64(len(latencies))/elapsed.Seconds(), pct(0.5).Round(time.Millisecond), pct(0.95).Round(time.Millisecond),
		pct(1).Round(time.Millisecond), fetchResets, waited.Round(time.Millisecond), joinerBusyBackoffStart(t), joinerBusyBackoffMax(t))
	t.Logf("publishers: %d records put and read back (%.1f/s), %d attempts reset for a stream limit", puts.Load(), float64(puts.Load())/elapsed.Seconds(), putResets.Load())
}

type testPublisher struct{ host shardnode.EvidenceHost }

// the joiner's wait when its replica is busy: the restore's flat FetchRetry.Busy. STREAM_PROFILE_BACKOFF_START_MS and
// STREAM_PROFILE_BACKOFF_MAX_MS model another policy (200 and 5000 are the doubling backoff the restore used for every failure).
func joinerBusyBackoffStart(*testing.T) time.Duration {
	if ms, _ := strconv.Atoi(os.Getenv("STREAM_PROFILE_BACKOFF_START_MS")); ms > 0 {
		return time.Duration(ms) * time.Millisecond
	}
	return DefaultFetchRetry.Busy
}
func joinerBusyBackoffMax(*testing.T) time.Duration {
	if ms, _ := strconv.Atoi(os.Getenv("STREAM_PROFILE_BACKOFF_MAX_MS")); ms > 0 {
		return time.Duration(ms) * time.Millisecond
	}
	return DefaultFetchRetry.Busy
}

// busy: the replica refused the stream for a limit. The global limit is refused before the request is read, and the client usually
// sees that as a bare stream reset (ErrTransport), not as the named ErrPendingLimit.
func busy(err error) bool {
	return errors.Is(err, ErrPendingLimit) || errors.Is(err, ErrPeerLimit) || errors.Is(err, ErrTransport)
}
