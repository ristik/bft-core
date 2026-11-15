package network

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"

	libp2pnetwork "github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/internal/testutils/logger"
)

// #1082: a joiner behind NAT or an isolated bridge (its announced address unreachable from the host) cannot be dialled by the host's roots,
// so a vote or proposal a host root sends it is lost and its leader slots time out. The joiner's keeper dials the host members itself;
// the host then reaches it over that inbound connection, and after the host restarts (an install) within one keeper interval, past the
// swarm's dial backoff.
const keeperProtocol = "/test/keeper/1"

func keeperPeer(t *testing.T, ctx context.Context, address string, keys *PeerKeyPair, announce []string) *Peer {
	t.Helper()
	conf, err := NewPeerConfiguration(address, announce, keys, nil, nil)
	require.NoError(t, err)
	p, err := newPeer(ctx, conf, logger.New(t), nil, noTCPPortReuse)
	require.NoError(t, err)
	return p
}

// reach opens a stream from p to id and reports how long it took (or the failure).
func reach(ctx context.Context, p *Peer, id peer.ID, budget time.Duration) (time.Duration, error) {
	start := time.Now()
	c, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	s, err := p.host.NewStream(c, id, keeperProtocol)
	if err != nil {
		return time.Since(start), err
	}
	_ = s.Close()
	return time.Since(start), nil
}

func TestAMemberThatCannotBeDialledIsReachedOverItsOwnOutboundConnection(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hostKeys := generateKeyPair(t)
	host := keeperPeer(t, ctx, "/ip4/127.0.0.1/tcp/0", hostKeys, nil)
	hostAddr := host.MultiAddresses()
	// the joiner announces only an address the host cannot reach (TEST-NET-1: the dial hangs, as a private bridge address did)
	joiner := keeperPeer(t, ctx, "/ip4/127.0.0.1/tcp/0", generateKeyPair(t), []string{"/ip4/192.0.2.1/tcp/8000"})
	defer func() { _ = joiner.Close() }()
	joiner.RegisterProtocolHandler(keeperProtocol, func(s libp2pnetwork.Stream) { _ = s.Close() })
	host.host.Peerstore().AddAddrs(joiner.ID(), []ma.Multiaddr{mustAddr(t, "/ip4/192.0.2.1/tcp/8000")}, peerstore.PermanentAddrTTL)
	joiner.host.Peerstore().AddAddrs(host.ID(), hostAddr, peerstore.PermanentAddrTTL) // its bootnode: the host is reachable from it

	_, err := reach(ctx, host, joiner.ID(), time.Second)
	require.Error(t, err, "without the keeper the host cannot reach the joiner")

	keeper := joiner.NewMemberProtector("root-committee")
	keeper.Set(ctx, []peer.ID{host.ID()})
	go keeper.Maintain(ctx, MaintainConfig{Interval: 100 * time.Millisecond, RapidWindow: time.Minute, DialTimeout: 2 * time.Second})
	require.Eventually(t, func() bool { return len(keeper.Disconnected()) == 0 }, 5*time.Second, 20*time.Millisecond)
	took, err := reach(ctx, host, joiner.ID(), time.Second)
	require.NoError(t, err, "the host reaches the joiner over the joiner's own connection")
	t.Logf("host to joiner over the inbound connection: %s", took)

	// the host restarts (an install restart): the same identity on the same address
	require.NoError(t, host.Close())
	down := time.Now()
	time.Sleep(300 * time.Millisecond) // the keeper's dials fail meanwhile and would put the address in the swarm's dial backoff
	host = keeperPeer(t, ctx, hostAddr[0].String(), hostKeys, nil)
	defer func() { _ = host.Close() }()
	host.host.Peerstore().AddAddrs(joiner.ID(), []ma.Multiaddr{mustAddr(t, "/ip4/192.0.2.1/tcp/8000")}, peerstore.PermanentAddrTTL)
	up := time.Now()
	var reconnected time.Duration
	require.Eventually(t, func() bool {
		if _, err := reach(ctx, host, joiner.ID(), 200*time.Millisecond); err != nil {
			return false
		}
		reconnected = time.Since(up)
		return true
	}, 5*time.Second, 20*time.Millisecond, "the keeper dials the restarted host again, past the dial backoff")
	t.Logf("down %s, reachable again %s after the restarted host listened", up.Sub(down), reconnected)
	require.Less(t, reconnected, 2*time.Second, "within a few keeper intervals, not the swarm's 5 s backoff")
}

func mustAddr(t *testing.T, s string) ma.Multiaddr {
	t.Helper()
	a, err := ma.NewMultiaddr(s)
	require.NoError(t, err)
	return a
}

// keeperLoad runs a protector over n unreachable members with a fake dial, and records every attempt.
type keeperLoad struct {
	mu      sync.Mutex
	at      map[peer.ID][]time.Time
	running int
	peak    int
	total   int
}

func (l *keeperLoad) connect(block time.Duration) func(ctx context.Context, ai peer.AddrInfo) error {
	return func(ctx context.Context, ai peer.AddrInfo) error {
		l.mu.Lock()
		l.at[ai.ID] = append(l.at[ai.ID], time.Now())
		l.total++
		l.running++
		l.peak = max(l.peak, l.running)
		l.mu.Unlock()
		defer func() { l.mu.Lock(); l.running--; l.mu.Unlock() }()
		if block > 0 { // a blackhole: the dial hangs for block, or until its timeout
			select {
			case <-time.After(block):
				return errors.New("i/o timeout")
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return errors.New("connection refused") // a fast refusal
	}
}

func newKeeperLoad(t *testing.T, ctx context.Context, n int, block time.Duration) (*MemberProtector, *keeperLoad) {
	t.Helper()
	p := keeperPeer(t, ctx, "/ip4/127.0.0.1/tcp/0", generateKeyPair(t), nil)
	t.Cleanup(func() { _ = p.Close() })
	l := &keeperLoad{at: map[peer.ID][]time.Time{}}
	m := p.NewMemberProtector("load")
	m.connect = l.connect(0)
	ids := make([]peer.ID, n)
	for i := range ids {
		ids[i] = generatePeerID(t)
	}
	m.Set(ctx, ids)
	if block > 0 {
		require.Eventually(t, func() bool { m.dialMu.Lock(); defer m.dialMu.Unlock(); return len(m.inflight) == 0 }, time.Second, time.Millisecond)
		m.dialMu.Lock()
		m.connect = l.connect(block)
		m.dialMu.Unlock()
		l.mu.Lock()
		l.total, l.at = 0, map[peer.ID][]time.Time{} // only Maintain's dials are measured
		l.mu.Unlock()
	}
	return m, l
}

func generatePeerID(t *testing.T) peer.ID {
	t.Helper()
	keys := generateKeyPair(t)
	priv, err := crypto.UnmarshalSecp256k1PrivateKey(keys.PrivateKey)
	require.NoError(t, err)
	id, err := peer.IDFromPrivateKey(priv)
	require.NoError(t, err)
	return id
}

// astra on #1088: 127 members that refuse at once must not be dialled at full rate forever. Inside the rapid window a member is retried
// every tick, but no tick starts more than PerTick dials; after it each member backs off (capped, jittered).
func TestTheKeeperBacksOffAndKeepsItsBudgetWith127FastRefusals(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m, l := newKeeperLoad(t, ctx, 127, 0)
	cfg := MaintainConfig{Interval: 20 * time.Millisecond, RapidWindow: 300 * time.Millisecond, BackoffMax: 400 * time.Millisecond, DialTimeout: time.Second, PerTick: 128}
	start := time.Now()
	go m.Maintain(ctx, cfg)
	time.Sleep(1500 * time.Millisecond)
	cancel()
	windowEnd := start.Add(cfg.RapidWindow)
	l.mu.Lock()
	defer l.mu.Unlock()
	for id, at := range l.at {
		after := 0
		for _, ts := range at {
			if ts.After(windowEnd.Add(cfg.Interval)) {
				after++
			}
		}
		// after the window a failing member waits at least BackoffMax/2 (the jitter's floor) between attempts: <= 1.2 s / 200 ms + 1
		require.LessOrEqual(t, after, 7, "member %s: %d attempts after the rapid window", id, after)
	}
	t.Logf("127 refusing members, 1.5 s: %d dials in all", l.total)
}

func TestTheKeeperBoundsDialsPerTickAndInFlightWithBlackholedMembers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m, l := newKeeperLoad(t, ctx, 127, time.Hour)
	cfg := MaintainConfig{Interval: 20 * time.Millisecond, RapidWindow: time.Minute, DialTimeout: 100 * time.Millisecond, PerTick: 8}
	go m.Maintain(ctx, cfg)
	time.Sleep(time.Second)
	cancel()
	l.mu.Lock()
	peak, total := l.peak, l.total
	l.mu.Unlock()
	require.LessOrEqual(t, peak, MaxMemberDials, "never more than the host's budget in flight")
	// each 100 ms dial holds its slot: at most MaxMemberDials per 100 ms, plus the warm-up's
	require.LessOrEqual(t, total, MaxMemberDials*12, "dials in a second")
	t.Logf("127 blackholed members, 1 s: %d dials, %d at most in flight", total, peak)

	time.Sleep(200 * time.Millisecond)
	l.mu.Lock()
	after := l.total
	l.mu.Unlock()
	time.Sleep(300 * time.Millisecond)
	l.mu.Lock()
	require.Equal(t, after, l.total, "a cancelled keeper starts no dial")
	l.mu.Unlock()
}

func TestASuccessfulDialAndANewSetResetTheRetryState(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m, l := newKeeperLoad(t, ctx, 3, 0)
	cfg := MaintainConfig{Interval: 10 * time.Millisecond, RapidWindow: 0, BackoffMax: time.Hour, DialTimeout: time.Second}
	go m.Maintain(ctx, cfg)
	require.Eventually(t, func() bool { m.dialMu.Lock(); defer m.dialMu.Unlock(); return len(m.retry) == 3 }, 2*time.Second, 5*time.Millisecond)
	m.dialMu.Lock()
	for _, st := range m.retry {
		require.Greater(t, st.next, time.Now(), "backed off")
	}
	m.dialMu.Unlock()
	m.Set(ctx, m.Protected())
	m.dialMu.Lock()
	require.Empty(t, m.retry, "a new set restarts the schedule")
	m.dialMu.Unlock()
	m.dialMu.Lock()
	m.connect = func(context.Context, peer.AddrInfo) error { return nil }
	m.dialMu.Unlock()
	_ = l
	require.Eventually(t, func() bool { m.dialMu.Lock(); defer m.dialMu.Unlock(); return len(m.retry) == 0 }, 2*time.Second, 5*time.Millisecond)
}

// astra on #1088 r2: Set alone (the shard prewarm runs no Maintain) still warms EVERY member through the bounded budget: the members over
// the budget wait for a slot instead of being dropped.
func TestSetAloneWarmsEveryMemberWithinTheBudget(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := keeperPeer(t, ctx, "/ip4/127.0.0.1/tcp/0", generateKeyPair(t), nil)
	defer func() { _ = p.Close() }()
	l := &keeperLoad{at: map[peer.ID][]time.Time{}}
	m := p.NewMemberProtector("shard-members")
	m.connect = l.connect(150 * time.Millisecond)
	ids := make([]peer.ID, 40)
	for i := range ids {
		ids[i] = generatePeerID(t)
	}
	m.Set(ctx, ids)
	require.Eventually(t, func() bool { l.mu.Lock(); defer l.mu.Unlock(); return len(l.at) == len(ids) }, 3*time.Second, 10*time.Millisecond,
		"every member is dialled once a slot frees")
	l.mu.Lock()
	defer l.mu.Unlock()
	require.LessOrEqual(t, l.peak, MaxMemberDials)
}

// A superseding Set cancels the warm-up it replaces: its dials in flight end, its members still waiting are never dialled, and the new
// set's members are.
func TestASupersedingSetCancelsTheWarmupItReplaces(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := keeperPeer(t, ctx, "/ip4/127.0.0.1/tcp/0", generateKeyPair(t), nil)
	defer func() { _ = p.Close() }()
	l := &keeperLoad{at: map[peer.ID][]time.Time{}}
	m := p.NewMemberProtector("root-committee")
	m.connect = l.connect(time.Hour)
	old := make([]peer.ID, 32)
	for i := range old {
		old[i] = generatePeerID(t)
	}
	m.Set(ctx, old)
	require.Eventually(t, func() bool { l.mu.Lock(); defer l.mu.Unlock(); return l.running == MaxMemberDials }, 2*time.Second, 5*time.Millisecond)
	next := make([]peer.ID, 8)
	for i := range next {
		next[i] = generatePeerID(t)
	}
	m.Set(ctx, next)
	require.Eventually(t, func() bool {
		l.mu.Lock()
		defer l.mu.Unlock()
		for _, id := range next {
			if len(l.at[id]) == 0 {
				return false
			}
		}
		return true
	}, 2*time.Second, 5*time.Millisecond, "the new set's members are dialled once the old dials are cancelled")
	time.Sleep(200 * time.Millisecond)
	l.mu.Lock()
	defer l.mu.Unlock()
	dialled := 0
	for _, id := range old {
		dialled += len(l.at[id])
	}
	require.Equal(t, MaxMemberDials, dialled, "no member of the replaced set is dialled after the replacement")
}

// The budget is the host's: two protectors of one peer (a shard node's shard-members and root-committee) share it.
func TestTwoProtectorsOfOnePeerShareTheBudget(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := keeperPeer(t, ctx, "/ip4/127.0.0.1/tcp/0", generateKeyPair(t), nil)
	defer func() { _ = p.Close() }()
	l := &keeperLoad{at: map[peer.ID][]time.Time{}}
	for _, tag := range []string{"shard-members", "root-committee"} {
		m := p.NewMemberProtector(tag)
		m.connect = l.connect(time.Hour)
		ids := make([]peer.ID, 24)
		for i := range ids {
			ids[i] = generatePeerID(t)
		}
		m.Set(ctx, ids)
	}
	time.Sleep(300 * time.Millisecond)
	l.mu.Lock()
	defer l.mu.Unlock()
	require.Equal(t, MaxMemberDials, l.peak, "16 in flight for the whole host, not per protector")
}
