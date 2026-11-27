package network

import (
	"fmt"
	"time"

	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/network/protocol/handshake"
)

// DefaultShardNetworkOptions are sane defaults for a shard node talking to
// root nodes on a local or well-connected network. Raise the timeouts for
// wide-area deployments.
var DefaultShardNetworkOptions = ShardNetworkOptions{
	ReceivedChannelCapacity:   1000,
	BlockCertificationTimeout: 300 * time.Millisecond,
	HandshakeTimeout:          300 * time.Millisecond,
}

type ShardNetworkOptions struct {
	ReceivedChannelCapacity   uint
	BlockCertificationTimeout time.Duration
	HandshakeTimeout          time.Duration
}

// ShardNetwork is the shard-side counterpart of NewLibP2PRootChainNetwork: it
// sends BlockCertificationRequest and Handshake messages to root nodes and
// receives CertificationResponse messages back.
//
// Ported from aggregator-go/internal/bft/network.go — that file registered
// the same three protocols by hand for the aggregator's own client. This
// makes the registration reusable by any shard node.
type ShardNetwork struct {
	*LibP2PNetwork
}

func NewShardNetwork(peer *Peer, obs Observability, opts ShardNetworkOptions) (*ShardNetwork, error) {
	base, err := NewLibP2PNetwork(peer, opts.ReceivedChannelCapacity, obs)
	if err != nil {
		return nil, fmt.Errorf("creating libp2p network: %w", err)
	}

	n := &ShardNetwork{LibP2PNetwork: base}

	sendProtocols := []SendProtocolDescription{
		{
			ProtocolID: ProtocolBlockCertification,
			Timeout:    opts.BlockCertificationTimeout,
			MsgType:    certification.BlockCertificationRequest{},
		},
		{
			ProtocolID: ProtocolHandshake,
			Timeout:    opts.HandshakeTimeout,
			MsgType:    handshake.Handshake{},
		},
	}
	if err := n.RegisterSendProtocols(sendProtocols); err != nil {
		return nil, fmt.Errorf("registering send protocols: %w", err)
	}

	receiveProtocols := shardReceiveProtocols()
	if err := n.RegisterReceiveProtocols(receiveProtocols); err != nil {
		return nil, fmt.Errorf("registering receive protocols: %w", err)
	}

	return n, nil
}

// shardReceiveProtocols are the certification response protocols a shard receives. V1, V2 and V3 frames are bounded by their declared payload limits, checked
// against the announced length before anything is allocated (V1 is derived from V2's, see MaxCertificationResponseV1Frame).
func shardReceiveProtocols() []ReceiveProtocolDescription {
	return []ReceiveProtocolDescription{
		{
			ProtocolID:   ProtocolUnicityCertificates,
			TypeFn:       func() any { return &certification.CertificationResponse{} },
			MaxFrameSize: certification.MaxCertificationResponseV1Frame,
		},
		{
			ProtocolID:   ProtocolUnicityCertificatesV2,
			TypeFn:       func() any { return &certification.CertificationResponseV2{} },
			MaxFrameSize: certification.MaxCertificationResponseV2Frame,
		},
		{
			ProtocolID:   ProtocolUnicityCertificatesV3,
			TypeFn:       func() any { return &certification.CertificationResponseV3{} },
			MaxFrameSize: certification.MaxCertificationResponseV3Frame,
		},
	}
}
