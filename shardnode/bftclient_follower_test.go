package shardnode

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	testpeer "github.com/unicitynetwork/bft-core/internal/testutils/peer"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-go-base/types"
)

// A non-active follower's client sends nothing to the roots (no handshake at start, at the startup retry or at the inactivity timeout) and
// still delivers a certificate from its follow source through the same verification to the driver. A forged one is not delivered. After
// promotion the next heartbeat subscribes to the roots at once.
func TestFollowerClientSendsNothingToRootsAndDeliversFollowedCertificates(t *testing.T) {
	f := newConfBindingFixture(t)
	net := &lateRootNet{received: make(chan any, 4), response: f.respond(f.ucMine), ready: true}
	driver := &firstUCDriver{got: make(chan struct{})}
	client, err := NewBFTClient(testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t)), net, f.signer, authPartitionID, types.ShardID{}, f.confMine,
		stubTrustBaseStore{tb: f.tb}, driver, nil,
		BFTClientOptions{HandshakeNodes: 1, CertNodes: 1, HeartbeatInterval: time.Hour, InactivityTimeout: 10 * time.Millisecond, StartupHandshakeInterval: 10 * time.Millisecond})
	require.NoError(t, err)
	follower := make(chan bool, 1)
	follower <- true
	nonActive := true
	client.SetFollowerRole(func() bool {
		select {
		case nonActive = <-follower:
		default:
		}
		return nonActive
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })

	good := f.respond(f.ucMine)
	raw, err := types.Cbor.Marshal(&good.UC)
	require.NoError(t, err)
	var forged types.UnicityCertificate
	require.NoError(t, types.Cbor.Unmarshal(raw, &forged))
	forged.UnicitySeal.RootChainRoundNumber += 7 // the seal no longer verifies
	require.True(t, client.FollowCertificate(&forged, &good.Technical))
	time.Sleep(200 * time.Millisecond) // several heartbeats, startup retries and inactivity timeouts
	select {
	case <-driver.got:
		t.Fatal("a forged followed certificate reached the driver")
	default:
	}
	net.mu.Lock()
	require.Zero(t, net.handshakes, "a follower never handshakes with a root")
	net.mu.Unlock()

	require.False(t, client.Holds(&good.UC), "nothing admitted yet: the follow source must offer again")
	require.True(t, client.FollowCertificate(&good.UC, &good.Technical))
	select {
	case <-driver.got:
	case <-time.After(5 * time.Second):
		t.Fatal("a followed certificate was not delivered")
	}
	require.Eventually(t, func() bool { return client.Holds(&good.UC) }, 5*time.Second, 10*time.Millisecond, "held once admitted: the acknowledgement")

	follower <- false
	client.RoleChanged()
	require.Eventually(t, func() bool { net.mu.Lock(); defer net.mu.Unlock(); return net.handshakes > 0 }, 5*time.Second, 10*time.Millisecond,
		"promoted, it subscribes to the roots at once, not at the next heartbeat")
}

type tokenRole struct {
	token  atomic.Uint64
	active atomic.Bool
}

func (r *tokenRole) Lease() (uint64, bool) { return r.token.Load(), r.active.Load() }

type countingNet struct {
	lateRootNet
	sends atomic.Int32
}

func (n *countingNet) Send(ctx context.Context, msg any, ids ...peer.ID) error {
	if _, ok := msg.(*certification.BlockCertificationRequest); ok {
		n.sends.Add(1)
	}
	return n.lateRootNet.Send(ctx, msg, ids...)
}

// A request leaves only under the role token it was produced under: after a revocation and re-publication (active again, a new token)
// neither the send nor a re-send of the old bytes goes out.
func TestClientSendIsBoundToTheOriginatingRoleToken(t *testing.T) {
	f := newConfBindingFixture(t)
	net := &countingNet{lateRootNet: lateRootNet{received: make(chan any, 4), ready: true}}
	client, err := NewBFTClient(testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t)), net, f.signer, authPartitionID, types.ShardID{}, f.confMine,
		stubTrustBaseStore{tb: f.tb}, &firstUCDriver{got: make(chan struct{})}, nil, BFTClientOptions{HandshakeNodes: 1, CertNodes: 1})
	require.NoError(t, err)
	role := &tokenRole{}
	role.active.Store(true)
	role.token.Store(7)
	client.SetRole(role)
	req := &certification.BlockCertificationRequest{PartitionID: authPartitionID}
	ctx := context.Background()

	require.NoError(t, client.sendRequest(withRoleToken(ctx, 7), req, f.ucMine, f.ucMine.GetRootEpoch()))
	require.EqualValues(t, 1, net.sends.Load())
	role.token.Store(9) // revoked and re-published: active again under another token
	require.ErrorIs(t, client.sendRequest(withRoleToken(ctx, 7), req, f.ucMine, f.ucMine.GetRootEpoch()), ErrFollower)
	require.EqualValues(t, 1, net.sends.Load(), "the old request does not leave under the new role")
	require.NoError(t, client.sendRequest(withRoleToken(ctx, 9), req, f.ucMine, f.ucMine.GetRootEpoch()))
}

// Round to client: a request signed under token 7 and answered (the round's completed cache), re-delivered after the role was re-published
// under token 9, reaches neither the client's network nor is it rebuilt; the signed bytes stay cached. Under the original token the replay
// re-sends exactly them, through the real client.
func TestRoundReplayThroughTheClientKeepsTheOriginatingToken(t *testing.T) {
	f := newConfBindingFixture(t)
	net := &countingNet{lateRootNet: lateRootNet{received: make(chan any, 4), ready: true}}
	client, err := NewBFTClient(testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t)), net, f.signer, authPartitionID, types.ShardID{}, f.confMine,
		stubTrustBaseStore{tb: f.tb}, &firstUCDriver{got: make(chan struct{})}, nil, BFTClientOptions{HandshakeNodes: 1, CertNodes: 1})
	require.NoError(t, err)
	require.NoError(t, client.SeedLUC(f.ucMine))
	role := &tokenRole{}
	role.active.Store(true)
	role.token.Store(7)
	client.SetRole(role)
	r := NewRound("leader", authPartitionID, types.ShardID{}, &stubExecutor{}, NewLoopbackDisseminator(), f.signer, client, nil)
	r.SetRole(role)
	uc := &types.UnicityCertificate{Version: 1, InputRecord: &types.InputRecord{Version: 1}, UnicitySeal: &types.UnicitySeal{Version: 1, RootChainRoundNumber: 1, Timestamp: 1000}}
	tr := &certification.TechnicalRecord{Round: 1, Leader: "leader", StatHash: []byte{1}, FeeHash: []byte{1}}
	signed := &certification.BlockCertificationRequest{PartitionID: authPartitionID, InputRecord: &types.InputRecord{Version: 1, RoundNumber: 1}}
	r.completed = &completedRound{round: 1, partitionRound: uc.GetRoundNumber(), rootRound: uc.GetRootRoundNumber(), req: signed, token: 7}
	ctx := context.Background()

	require.NoError(t, r.HandleCertificate(ctx, uc, tr))
	require.EqualValues(t, 1, net.sends.Load(), "replayed under its own token")

	role.token.Store(9) // re-published, active again
	require.NoError(t, r.HandleCertificate(ctx, uc, tr))
	require.EqualValues(t, 1, net.sends.Load(), "not sent under the new token")
	require.Same(t, signed, r.completed.req, "the signed bytes are kept, never rebuilt or re-signed")
}
