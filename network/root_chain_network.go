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
	// ProtocolUnicityCertificatesV2 carries certification.CertificationResponseV2: the response plus the signed trust-base entries a deployment publishes.
	// It is a separate protocol, so the presence of the entries is announced by the protocol and the explicit version, never by an array length.
	ProtocolUnicityCertificatesV2 = "/ab/certificates/0.0.2"
)

/*
Logger (log) is assumed to already have node_id attribute added, won't be added by NW component!
*/
func NewLibP2PRootChainNetwork(self *Peer, capacity uint, sendCertificateTimeout time.Duration, obs Observability) (*LibP2PNetwork, error) {
	n, err := NewLibP2PNetwork(self, capacity, obs)
	if err != nil {
		return nil, err
	}

	sendProtocolDescriptions := []SendProtocolDescription{
		{ProtocolID: ProtocolUnicityCertificates, Timeout: sendCertificateTimeout, MsgType: certification.CertificationResponse{}},
		{ProtocolID: ProtocolUnicityCertificatesV2, Timeout: sendCertificateTimeout, MsgType: certification.CertificationResponseV2{}},
	}
	if err = n.RegisterSendProtocols(sendProtocolDescriptions); err != nil {
		return nil, fmt.Errorf("registering send protocols: %w", err)
	}

	receiveProtocolDescriptions := []ReceiveProtocolDescription{
		{
			ProtocolID: ProtocolBlockCertification,
			TypeFn:     func() any { return &certification.BlockCertificationRequest{} },
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
