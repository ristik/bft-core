package shardnode

import (
	"context"
	"crypto"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	testcertificates "github.com/unicitynetwork/bft-core/internal/testutils/certificates"
	testpeer "github.com/unicitynetwork/bft-core/internal/testutils/peer"
	testtrustbase "github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/network/protocol/handshake"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

func (n *lateRootNet) handshakeCount() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.handshakes
}

// committee is a root committee of its own: a signer, its trust base, and the peer ids a handshake to it is sent to.
type committee struct {
	signer abcrypto.Signer
	tb     *types.RootTrustBaseV1
	ids    map[peer.ID]bool
}

func newCommittee(t *testing.T, signer abcrypto.Signer) committee {
	t.Helper()
	if signer == nil {
		var err error
		signer, err = abcrypto.NewInMemorySecp256K1Signer()
		require.NoError(t, err)
	}
	tb, ok := testtrustbase.NewTrustBase(t, signer).(*types.RootTrustBaseV1)
	require.True(t, ok)
	ids := map[peer.ID]bool{}
	for _, n := range tb.RootNodes {
		id, err := peer.Decode(n.NodeID)
		require.NoError(t, err)
		ids[id] = true
	}
	return committee{signer: signer, tb: tb, ids: ids}
}

// certificateOf is the fixture's certificate as committee k certifies it in root epoch epoch at root round round: what the new committee's
// recertification of the unchanged shard state looks like to this client.
func certificateOf(t *testing.T, f *confBindingFixture, k committee, epoch, round uint64) *types.UnicityCertificate {
	t.Helper()
	zero := make([]byte, 32)
	trHash, err := f.technical.Hash()
	require.NoError(t, err)
	ir := &types.InputRecord{Version: 1, RoundNumber: 4, PreviousHash: zero, Hash: zero, SummaryValue: []byte{}, Timestamp: 1}
	mine := &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: authPartitionID, T2Timeout: 2500000000}
	uc := testcertificates.CreateUnicityCertificate(t, k.signer, ir, mine, round, zero, trHash)
	uc.UnicitySeal.Epoch, uc.UnicitySeal.Signatures = epoch, nil
	require.NoError(t, uc.UnicitySeal.Sign(k.tb.RootNodes[0].NodeID, k.signer))
	require.NoError(t, uc.Verify(k.tb, crypto.SHA256, authPartitionID, types.ShardID{}, f.confMine))
	return uc
}

// epochStore serves each root epoch's own trust base, records the epochs asked for, and runs hook inside a lookup (a delayed preparation).
type epochStore struct {
	mu        sync.Mutex
	byEpoch   map[uint64]*types.RootTrustBaseV1
	asked     []uint64
	installed *atomic.Uint64
	hook      func(epoch uint64)
}

func (s *epochStore) GetByEpoch(_ context.Context, epoch uint64) (*types.RootTrustBaseV1, error) {
	s.mu.Lock()
	s.asked = append(s.asked, epoch)
	tb, hook := s.byEpoch[epoch], s.hook
	s.mu.Unlock()
	if hook != nil {
		hook(epoch)
	}
	if tb == nil {
		return s.byEpoch[1], nil
	}
	return tb, nil
}

func (s *epochStore) CurrentRootEpoch() (uint64, bool) { return s.installed.Load(), true }

func (s *epochStore) askedFor(epoch uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Contains(s.asked, epoch)
}

// routeNet records every handshake with its destinations and answers it as the committee it reached would.
type routeNet struct {
	mu       sync.Mutex
	sent     [][]peer.ID
	received chan any
	answer   func(to []peer.ID) *certification.CertificationResponse
}

func (n *routeNet) Send(_ context.Context, msg any, to ...peer.ID) error {
	switch msg.(type) {
	case *handshake.Handshake, handshake.Handshake:
	default:
		return nil
	}
	n.mu.Lock()
	n.sent = append(n.sent, slices.Clone(to))
	answer := n.answer
	n.mu.Unlock()
	if answer != nil {
		if r := answer(to); r != nil {
			select {
			case n.received <- r:
			default:
			}
		}
	}
	return nil
}

func (n *routeNet) ReceivedChannel() <-chan any { return n.received }

// to counts the handshakes sent only to members of k, and the ones sent to anyone else.
func (n *routeNet) to(k committee) (in, out int) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, dests := range n.sent {
		only := len(dests) > 0
		for _, d := range dests {
			only = only && k.ids[d]
		}
		if only {
			in++
		} else {
			out++
		}
	}
	return in, out
}

// activationClient runs a client of the fixture's shard over net and store, holding the fixture's certificate of root epoch 1.
func activationClient(t *testing.T, f *confBindingFixture, net RootNetwork, store TrustBaseStore, opts BFTClientOptions) *BFTClient {
	t.Helper()
	c, err := NewBFTClient(testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t)), net, f.signer, authPartitionID, types.ShardID{}, f.confMine,
		store, &firstUCDriver{got: make(chan struct{})}, nil, opts)
	require.NoError(t, err)
	return c
}

func runClient(t *testing.T, c *BFTClient) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = c.Run(ctx) }()
	require.Eventually(t, func() bool { e, ok := c.heldRootEpoch(); return ok && e == 1 }, 5*time.Second, 10*time.Millisecond,
		"premise: the client holds a certificate of root epoch 1")
}

// productionTimers are the client's timers as a shard node runs them: the inactivity re-handshake is 30 s away.
var productionTimers = BFTClientOptions{HandshakeNodes: 1, CertNodes: 1, HeartbeatInterval: 5 * time.Second, InactivityTimeout: 30 * time.Second,
	StartupHandshakeInterval: 2 * time.Second}

// #1074, with disjoint old and new committees: after the activation of root epoch 2, the client asks epoch 2's own committee (its trust base is
// looked up, its roots are the destinations), at once and well under the inactivity timeout. Once it adopts the new committee's
// recertification it stops asking.
func TestTheActivationCatchUpAsksTheInstalledEpochsCommitteeAndStopsOnItsCertificate(t *testing.T) {
	f := newConfBindingFixture(t)
	old, next := newCommittee(t, f.signer), newCommittee(t, nil)
	recert := certificateOf(t, f, next, 2, 60)
	var installed atomic.Uint64
	installed.Store(1)
	store := &epochStore{byEpoch: map[uint64]*types.RootTrustBaseV1{1: f.tb, 2: next.tb}, installed: &installed}
	net := &routeNet{received: make(chan any, 64), answer: func(to []peer.ID) *certification.CertificationResponse {
		if len(to) > 0 && next.ids[to[0]] {
			return f.respond(recert)
		}
		return f.respond(f.ucMine)
	}}
	c := activationClient(t, f, net, store, productionTimers)
	runClient(t, c)
	before, _ := net.to(next)
	require.Zero(t, before)

	activated := time.Now()
	installed.Store(2)
	require.Eventually(t, func() bool { in, _ := net.to(next); return in > 0 }, 5*time.Second, 5*time.Millisecond, "a handshake to epoch 2's committee")
	t.Logf("activation to the first catch-up handshake to the new committee: %v", time.Since(activated).Round(time.Millisecond))
	require.Less(t, time.Since(activated), time.Second, "at once, not after the %v inactivity timeout", productionTimers.InactivityTimeout)
	require.True(t, store.askedFor(2), "epoch 2's own trust base was looked up")
	_, toOld := net.to(next)
	oldIn, _ := net.to(old)
	require.Equal(t, toOld, oldIn, "every other handshake went to the old committee only (the initial one), none to a mixture")

	require.Eventually(t, func() bool { e, _ := c.heldRootEpoch(); return e == 2 }, 5*time.Second, 10*time.Millisecond,
		"the new committee's recertification is adopted")
	in, _ := net.to(next)
	time.Sleep(2*activationHandshakeMax/3 + 500*time.Millisecond)
	after, _ := net.to(next)
	require.Equal(t, in, after, "no catch-up handshakes once a certificate of the installed epoch is held")
}

// A role that ends, or is re-published under another token, while a catch-up handshake is being prepared (a delayed trust-base lookup) stops
// that handshake: it is admitted last, under the token captured when its preparation began. A re-published role asks again under its own.
func TestTheActivationCatchUpIsAdmittedLastUnderItsRoleToken(t *testing.T) {
	for name, change := range map[string]func(role *tokenRole){
		"retired":        func(role *tokenRole) { role.active.Store(false) },
		"token replaced": func(role *tokenRole) { role.token.Store(2) },
	} {
		t.Run(name, func(t *testing.T) {
			f := newConfBindingFixture(t)
			next := newCommittee(t, nil)
			var installed atomic.Uint64
			installed.Store(1)
			role := &tokenRole{}
			role.token.Store(1)
			role.active.Store(true)
			var fired atomic.Bool
			store := &epochStore{byEpoch: map[uint64]*types.RootTrustBaseV1{1: f.tb, 2: next.tb}, installed: &installed}
			store.hook = func(epoch uint64) {
				if epoch == 2 && fired.CompareAndSwap(false, true) {
					change(role)
				}
			}
			net := &routeNet{received: make(chan any, 64), answer: func([]peer.ID) *certification.CertificationResponse { return f.respond(f.ucMine) }}
			c := activationClient(t, f, net, store, productionTimers)
			c.SetRole(role)
			runClient(t, c)

			installed.Store(2)
			require.Eventually(t, fired.Load, 5*time.Second, 5*time.Millisecond, "premise: the catch-up's preparation ran")
			time.Sleep(300 * time.Millisecond)
			in, _ := net.to(next)
			require.Zero(t, in, "the handshake prepared under the ended token is not sent")
			if name == "token replaced" {
				require.Eventually(t, func() bool { in, _ := net.to(next); return in > 0 }, 5*time.Second, 10*time.Millisecond,
					"the re-published role asks under its own token")
			} else {
				time.Sleep(2 * activationHandshakeEvery)
				in, _ := net.to(next)
				require.Zero(t, in, "a retired node asks nothing")
			}
		})
	}
}

// A further activation during the preparation of a catch-up handshake: the handshake for the superseded epoch is not sent, and the next one
// asks the newer epoch's committee at once.
func TestAFurtherActivationDuringTheCatchUpRetargetsIt(t *testing.T) {
	f := newConfBindingFixture(t)
	second, third := newCommittee(t, nil), newCommittee(t, nil)
	var installed atomic.Uint64
	installed.Store(1)
	store := &epochStore{byEpoch: map[uint64]*types.RootTrustBaseV1{1: f.tb, 2: second.tb, 3: third.tb}, installed: &installed}
	var fired atomic.Bool
	store.hook = func(epoch uint64) {
		if epoch == 2 && fired.CompareAndSwap(false, true) {
			installed.Store(3)
		}
	}
	net := &routeNet{received: make(chan any, 64), answer: func([]peer.ID) *certification.CertificationResponse { return f.respond(f.ucMine) }}
	c := activationClient(t, f, net, store, productionTimers)
	runClient(t, c)

	installed.Store(2)
	require.Eventually(t, func() bool { in, _ := net.to(third); return in > 0 }, 5*time.Second, 5*time.Millisecond, "epoch 3's committee is asked")
	in, _ := net.to(second)
	require.Zero(t, in, "nothing is sent to the superseded epoch's committee")
	require.True(t, store.askedFor(3))
}

// The catch-up cadence after the first, immediate handshake: doubling from activationHandshakeEvery, capped at activationHandshakeMax, each
// with up to half of it of jitter.
func TestTheActivationCatchUpBacksOffWithJitterAndACap(t *testing.T) {
	for n, base := range map[int]time.Duration{1: time.Second, 2: 2 * time.Second, 3: 4 * time.Second, 4: 8 * time.Second, 9: 8 * time.Second} {
		for range 50 {
			d := activationBackoff(n)
			require.GreaterOrEqual(t, d, base, "handshake %d", n)
			require.LessOrEqual(t, d, base+base/2, "handshake %d", n)
		}
	}
}

// With the production timers (5 s heartbeat, 30 s inactivity) and one trust base for every epoch, the first catch-up handshake leaves at once
// after the activation, and further ones follow the backoff.
func TestARootActivationIsCaughtUpWithAtOnceNotAfterTheInactivityTimeout(t *testing.T) {
	f := newConfBindingFixture(t)
	net := &lateRootNet{received: make(chan any, 64), ready: true, response: f.respond(f.ucMine)}
	var installed atomic.Uint64
	installed.Store(1)
	store := epochTrustStore{TrustBaseStore: stubTrustBaseStore{tb: f.tb}, installed: &installed}
	c := activationClient(t, f, net, store, productionTimers)
	runClient(t, c)
	time.Sleep(600 * time.Millisecond)
	before := net.handshakeCount()

	activated := time.Now()
	installed.Store(2)
	require.Eventually(t, func() bool { return net.handshakeCount() > before }, 5*time.Second, 5*time.Millisecond)
	waited := time.Since(activated)
	t.Logf("activation to the first catch-up handshake: %v (inactivity timeout %v, heartbeat %v)", waited.Round(time.Millisecond),
		productionTimers.InactivityTimeout, productionTimers.HeartbeatInterval)
	require.Less(t, waited, time.Second, "asked at once, not after the inactivity timeout")
	time.Sleep(activationHandshakeEvery*3/2 + 400*time.Millisecond)
	require.GreaterOrEqual(t, net.handshakeCount()-before, 2, "asked again after the first backoff while not caught up")
}

// A follower (non-active) node asks no root anything after an activation: its certificates come from its follow source.
func TestAFollowerDoesNotHandshakeAfterARootActivation(t *testing.T) {
	f := newConfBindingFixture(t)
	net := &lateRootNet{received: make(chan any, 64), ready: true, response: f.respond(f.ucMine)}
	var installed atomic.Uint64
	installed.Store(1)
	store := epochTrustStore{TrustBaseStore: stubTrustBaseStore{tb: f.tb}, installed: &installed}
	c := activationClient(t, f, net, store, BFTClientOptions{HandshakeNodes: 1, CertNodes: 1, HeartbeatInterval: time.Hour, InactivityTimeout: time.Hour})
	role := &tokenRole{}
	role.active.Store(true)
	c.SetRole(role)
	runClient(t, c)
	role.active.Store(false)
	time.Sleep(300 * time.Millisecond)
	before := net.handshakeCount()
	installed.Store(2)
	time.Sleep(2*activationHandshakeEvery + 300*time.Millisecond)
	require.Equal(t, before, net.handshakeCount())
}

// astra on #1076, in #1054: the catch-up handshake is part of the client's one handshake account. While it runs, the inactivity re-handshake
// to the OLD committee does not double it, and answers of the old epoch (adopted nowhere: they are retired at admission) neither move the
// progress clock nor stop the catch-up; only a certificate of the installed epoch does.
func TestTheActivationCatchUpSharesTheHandshakePacingAndIgnoresOldEpochAnswers(t *testing.T) {
	f := newConfBindingFixture(t)
	old, next := newCommittee(t, f.signer), newCommittee(t, nil)
	var installed atomic.Uint64
	installed.Store(1)
	store := &epochStore{byEpoch: map[uint64]*types.RootTrustBaseV1{1: f.tb, 2: next.tb}, installed: &installed}
	net := &routeNet{received: make(chan any, 64), answer: func(to []peer.ID) *certification.CertificationResponse {
		if len(to) > 0 && next.ids[to[0]] {
			return nil // the new committee is still coming up: no answer
		}
		return f.respond(f.ucMine) // the old committee answers with the old epoch's certificate
	}}
	c := activationClient(t, f, net, store, BFTClientOptions{HandshakeNodes: 1, CertNodes: 1, HeartbeatInterval: 50 * time.Millisecond,
		InactivityTimeout: 2 * time.Second})
	runClient(t, c)
	installed.Store(2)
	require.Eventually(t, func() bool { in, _ := net.to(next); return in > 0 }, 5*time.Second, 5*time.Millisecond, "the catch-up starts")
	delivered := c.Progress().Delivered()
	oldBefore, _ := net.to(old)
	time.Sleep(2500 * time.Millisecond) // beyond the inactivity timeout, within the catch-up's backoff
	toNext, _ := net.to(next)
	require.GreaterOrEqual(t, toNext, 2, "old-epoch answers do not stop the catch-up")
	oldAfter, _ := net.to(old)
	require.Equal(t, oldBefore, oldAfter, "the inactivity re-handshake is paced from the catch-up's handshakes: no doubling")
	require.Equal(t, delivered, c.Progress().Delivered(), "an old epoch's certificate moves no progress clock")
	e, _ := c.heldRootEpoch()
	require.EqualValues(t, 1, e)
}
