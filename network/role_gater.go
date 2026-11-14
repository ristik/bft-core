package network

import (
	"errors"

	"github.com/libp2p/go-libp2p/core/control"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
)

// RoleGater is a libp2p connection gater that refuses every connection, outbound and inbound, to a peer Deny names. A non-active shard
// node (a joiner before its activation, a syncing replica, an external follower) uses it to keep root connections closed at the transport
// boundary: it takes certificates and activation evidence from blocks, archives and mirrors only, never from roots. Deny is consulted on
// every connection, so a promotion that makes the node active opens the roots without a restart. A nil Deny refuses nothing.
// ErrGated refuses a stream to a peer the role gater denies.
var ErrGated = errors.New("network: peer refused by the role gater")

type RoleGater struct {
	Deny func(peer.ID) bool
}

func (g *RoleGater) denied(id peer.ID) bool { return g != nil && g.Deny != nil && g.Deny(id) }

func (g *RoleGater) InterceptPeerDial(id peer.ID) bool                 { return !g.denied(id) }
func (g *RoleGater) InterceptAddrDial(id peer.ID, _ ma.Multiaddr) bool { return !g.denied(id) }
func (g *RoleGater) InterceptAccept(network.ConnMultiaddrs) bool       { return true }
func (g *RoleGater) InterceptSecured(_ network.Direction, id peer.ID, _ network.ConnMultiaddrs) bool {
	return !g.denied(id)
}
func (g *RoleGater) InterceptUpgraded(c network.Conn) (bool, control.DisconnectReason) {
	return !g.denied(c.RemotePeer()), 0
}
