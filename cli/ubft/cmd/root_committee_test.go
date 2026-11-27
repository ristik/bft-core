package cmd

import (
	"context"
	"crypto/rand"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/internal/testutils/logger"
	"github.com/unicitynetwork/bft-core/network"
)

func committeeTestPeer(t *testing.T, announce []string) *network.Peer {
	t.Helper()
	priv, pub, err := crypto.GenerateSecp256k1Key(rand.Reader)
	require.NoError(t, err)
	privRaw, err := priv.Raw()
	require.NoError(t, err)
	pubRaw, err := pub.Raw()
	require.NoError(t, err)
	conf, err := network.NewPeerConfiguration("/ip4/127.0.0.1/tcp/0", announce, &network.PeerKeyPair{PublicKey: pubRaw, PrivateKey: privRaw}, nil, nil)
	require.NoError(t, err)
	p, err := network.NewPeer(context.Background(), conf, logger.New(t), nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close() })
	return p
}

func committeeTrust(epoch uint64, ids ...peer.ID) *types.RootTrustBaseV1 {
	tb := &types.RootTrustBaseV1{Epoch: epoch}
	for _, id := range ids {
		tb.RootNodes = append(tb.RootNodes, &types.NodeInfo{NodeID: id.String(), Stake: 1})
	}
	return tb
}

// #1082: the host members cannot dial the joiner (its only announced address is unreachable); the joiner's keeper dials them, and every
// member's warm-up ends with the whole committee connected before its first round, the host's included, over the joiner's connections.
func TestTheCommitteeIsConnectedBeforeTheFirstRoundEvenToAMemberThatCannotBeDialled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	log := logger.New(t)
	host := committeeTestPeer(t, nil)
	joiner := committeeTestPeer(t, []string{"/ip4/192.0.2.1/tcp/8000"})
	joiner.Network().Peerstore().AddAddrs(host.ID(), host.MultiAddresses(), peerstore.PermanentAddrTTL) // its bootnode
	tb := committeeTrust(9, host.ID(), joiner.ID())

	hostDone := make(chan *rootCommittee, 1)
	go func() { hostDone <- keepRootCommittee(ctx, log, host, tb, 10*time.Second) }()
	time.Sleep(200 * time.Millisecond) // the host is waiting for the joiner, which it cannot dial
	start := time.Now()
	j := keepRootCommittee(ctx, log, joiner, tb, 10*time.Second)
	require.True(t, j.member)
	require.Empty(t, j.status().Missing, "the joiner reaches the host itself")
	var h *rootCommittee
	select {
	case h = <-hostDone:
	case <-time.After(5 * time.Second):
		t.Fatal("the host's warm-up did not end over the joiner's connection")
	}
	require.Empty(t, h.status().Missing)
	require.Equal(t, []string{joiner.ID().String()}, h.status().Connected)
	t.Logf("both members connected %s after the joiner started its keeper", time.Since(start))
}

func TestANonMemberKeepsNoCommitteeAndAWarmupIsBounded(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	log := logger.New(t)
	follower := committeeTestPeer(t, nil)
	member := committeeTestPeer(t, nil)
	down := committeeTestPeer(t, nil)
	downID := down.ID()
	require.NoError(t, down.Close())

	c := keepRootCommittee(ctx, log, follower, committeeTrust(3, member.ID()), time.Minute)
	require.False(t, c.member)
	require.Nil(t, c.keeper, "a root outside the committee dials none of it")
	require.Empty(t, follower.Network().ConnsToPeer(member.ID()))

	start := time.Now()
	c = keepRootCommittee(ctx, log, member, committeeTrust(3, member.ID(), downID), 300*time.Millisecond)
	require.Less(t, time.Since(start), 2*time.Second, "a member that is down costs at most the warm-up")
	require.Equal(t, []string{downID.String()}, c.status().Missing)
}

// stagedCommittee is a manager's staged successor committee as the keeper polls it.
type stagedCommittee struct {
	epoch uint64
	ids   []string
}

func (s stagedCommittee) StagedCommittee() (uint64, []string) { return s.epoch, s.ids }

// #1086 PR 2 (#1082): a joiner is a follower of the installed epoch and keeps no committee of it, but once its staged candidate names it
// in the successor it keeps that committee connected, before the commit: the host member, which cannot dial it, is reached over the
// joiner's own connection, and the joiner's status reports the staged view. A staged successor that does not name it keeps nothing; once it
// switched into the successor in process, that committee is its installed one.
func TestAJoinerKeepsItsStagedSuccessorsCommitteeConnectedBeforeTheCommit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	log := logger.New(t)
	host := committeeTestPeer(t, nil)
	joiner := committeeTestPeer(t, []string{"/ip4/192.0.2.1/tcp/8000"})
	joiner.Network().Peerstore().AddAddrs(host.ID(), host.MultiAddresses(), peerstore.PermanentAddrTTL)
	installed := committeeTrust(8, host.ID())

	c := keepRootCommittee(ctx, log, joiner, installed, time.Second)
	require.False(t, c.member)
	require.Nil(t, c.status().Staged)

	other := committeeTestPeer(t, nil).ID()
	c.stage(ctx, log, 9, []string{host.ID().String(), other.String()})
	require.Nil(t, c.status().Staged, "a successor that does not name this root is not kept")
	require.Empty(t, joiner.Network().ConnsToPeer(host.ID()))

	go c.keepStaged(ctx, log, stagedCommittee{epoch: 9, ids: []string{host.ID().String(), joiner.ID().String()}})
	require.Eventually(t, func() bool {
		st := c.status().Staged
		return st != nil && st.Epoch == 9 && len(st.Missing) == 0
	}, 5*time.Second, 20*time.Millisecond, "the joiner dials the staged committee itself")
	require.Equal(t, []string{host.ID().String()}, c.status().Staged.Connected)
	require.NotEmpty(t, host.Network().ConnsToPeer(joiner.ID()), "the host reaches the joiner over the joiner's connection")
	require.False(t, c.status().Member, "still a follower of epoch 8")

	c.follow(ctx, log, committeeTrust(9, host.ID(), joiner.ID()))
	st := c.status()
	require.True(t, st.Member)
	require.EqualValues(t, 9, st.Epoch)
	require.Nil(t, st.Staged, "after the switch the staged committee is the installed one")
	require.Empty(t, st.Missing)
}
