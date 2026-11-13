package network

import (
	"fmt"
	"time"

	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/network/protocol/handshake"
)

const (
	ProtocolHandshake           = "/ab/handshake/0.0.1"
	ProtocolBlockCertification  = "/ab/block-certification/0.0.1"
	ProtocolUnicityCertificates = "/ab/certificates/0.0.1"
	// ProtocolUnicityCertificatesV2 carries certification.CertificationResponseV2.
	ProtocolUnicityCertificatesV2 = "/ab/certificates/0.0.2"
	// ProtocolUnicityCertificatesV3 carries certification.CertificationResponseV3: the response, the optional partition view and the signed trust-base
	// entries a deployment publishes. It is a separate protocol and an explicit version, so no consumer ever infers the format from an array length. A
	// deployment that publishes entries sends only this one to its UTB peers (no silent fallback to a format that would lose the entries or the status).
	ProtocolUnicityCertificatesV3 = "/ab/certificates/0.0.3"
)

/*
Logger (log) is assumed to already have node_id attribute added, won't be added by NW component!
*/
// The ingress budget of block certification requests (#1032): bytes in flight and queued, over all peers and for one. One peer may have
// one frame of the maximum size and some ordinary ones outstanding; the whole budget fits four maximum frames. A peer whose frames do
// not fit is refused before its payload is read.
const (
	BlockCertificationIngressBytes   = 4 * certification.MaxBlockCertificationRequestFrame
	BlockCertificationIngressPerPeer = certification.MaxBlockCertificationRequestFrame + 8<<20
)

func NewLibP2PRootChainNetwork(self *Peer, capacity uint, sendCertificateTimeout time.Duration, obs Observability) (*LibP2PNetwork, error) {
	n, err := NewLibP2PNetwork(self, capacity, obs)
	if err != nil {
		return nil, err
	}

	sendProtocolDescriptions := []SendProtocolDescription{
		{ProtocolID: ProtocolUnicityCertificates, Timeout: sendCertificateTimeout, MsgType: certification.CertificationResponse{}},
		{ProtocolID: ProtocolUnicityCertificatesV3, Timeout: sendCertificateTimeout, MsgType: certification.CertificationResponseV3{}},
	}
	if err = n.RegisterSendProtocols(sendProtocolDescriptions); err != nil {
		return nil, fmt.Errorf("registering send protocols: %w", err)
	}

	receiveProtocolDescriptions := []ReceiveProtocolDescription{
		{
			ProtocolID:   ProtocolBlockCertification,
			TypeFn:       func() any { return &certification.BlockCertificationRequest{} },
			MaxFrameSize: certification.MaxBlockCertificationRequestFrame,
			Ingress:      NewIngressBudget(BlockCertificationIngressBytes, BlockCertificationIngressPerPeer),
		},
		{
			ProtocolID: ProtocolHandshake,
			TypeFn:     func() any { return &handshake.Handshake{} },
		},
	}
	if err = n.RegisterReceiveProtocols(receiveProtocolDescriptions); err != nil {
		return nil, fmt.Errorf("registering receive protocols: %w", err)
	}

	return n, nil
}
