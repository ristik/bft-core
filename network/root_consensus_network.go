package network

import (
	"time"

	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
)

const (
	ProtocolRootIrChangeReq     = "/ab/root-change-req/0.0.1"
	ProtocolRootProposal        = "/ab/root-proposal/0.0.1"
	ProtocolRootVote            = "/ab/root-vote/0.0.1"
	ProtocolRootTimeout         = "/ab/root-timeout/0.0.1"
	ProtocolRootStateReq        = "/ab/root-state-req/0.0.1"
	ProtocolRootStateResp       = "/ab/root-state-resp/0.0.1"
	ProtocolRootHandoffApproval = "/ab/root-handoff-approval/1.0.0"
	ProtocolRootHandoffAbort    = "/ab/root-handoff-abort/1.0.0"
	ProtocolRootPosControl      = "/ab/root-pos-control/1.0.0"
)

// consensusSendRetries is the number of repeats of an undelivered proposal, vote or timeout vote to a connected root (#982).
const consensusSendRetries = 2

func NewLibP2RootConsensusNetwork(self *Peer, capacity uint, sendTimeout time.Duration, obs Observability) (*LibP2PNetwork, error) {
	n, err := NewLibP2PNetwork(self, capacity, obs)
	if err != nil {
		return nil, err
	}
	approvalTimeout := sendTimeout
	if approvalTimeout < 5*time.Second {
		approvalTimeout = 5 * time.Second
	}
	sendProtocolDescriptions := []SendProtocolDescription{
		{ProtocolID: ProtocolRootIrChangeReq, Timeout: sendTimeout, MsgType: abdrc.IrChangeReqMsg{}},
		// a lost proposal or vote has no other repair and stalls a round with exactly a quorum live; a lost timeout vote waits a local timeout
		{ProtocolID: ProtocolRootProposal, Timeout: sendTimeout, MsgType: abdrc.ProposalMsg{}, Retries: consensusSendRetries},
		{ProtocolID: ProtocolRootVote, Timeout: sendTimeout, MsgType: abdrc.VoteMsg{}, Retries: consensusSendRetries},
		{ProtocolID: ProtocolRootTimeout, Timeout: sendTimeout, MsgType: abdrc.TimeoutMsg{}, Retries: consensusSendRetries},
		{ProtocolID: ProtocolRootStateReq, Timeout: sendTimeout, MsgType: abdrc.StateRequestMsg{}},
		{ProtocolID: ProtocolRootStateResp, Timeout: sendTimeout, MsgType: abdrc.StateMsg{}},
		{ProtocolID: ProtocolRootHandoffApproval, Timeout: approvalTimeout, MsgType: abdrc.HandoffApprovalMsg{}},
		{ProtocolID: ProtocolRootHandoffAbort, Timeout: approvalTimeout, MsgType: abdrc.HandoffAbortApprovalMsg{}},
		{ProtocolID: ProtocolRootPosControl, Timeout: approvalTimeout, MsgType: abdrc.PosControlSubmissionMsg{}},
	}
	if err = n.RegisterSendProtocols(sendProtocolDescriptions); err != nil {
		return nil, err
	}
	receiveProtocolDescriptions := []ReceiveProtocolDescription{
		{
			ProtocolID: ProtocolRootIrChangeReq,
			TypeFn:     func() any { return &abdrc.IrChangeReqMsg{} },
		},
		{
			ProtocolID: ProtocolRootProposal,
			TypeFn:     func() any { return &abdrc.ProposalMsg{} },
		},
		{
			ProtocolID: ProtocolRootVote,
			TypeFn:     func() any { return &abdrc.VoteMsg{} },
		},
		{
			ProtocolID: ProtocolRootTimeout,
			TypeFn:     func() any { return &abdrc.TimeoutMsg{} },
		},
		{
			ProtocolID: ProtocolRootStateReq,
			TypeFn:     func() any { return &abdrc.StateRequestMsg{} },
		},
		{
			ProtocolID: ProtocolRootStateResp,
			TypeFn:     func() any { return &abdrc.StateMsg{} },
		},
		{
			ProtocolID: ProtocolRootHandoffApproval,
			TypeFn:     func() any { return &abdrc.HandoffApprovalMsg{} },
		},
		{
			ProtocolID: ProtocolRootHandoffAbort,
			TypeFn:     func() any { return &abdrc.HandoffAbortApprovalMsg{} },
		},
		{
			ProtocolID: ProtocolRootPosControl,
			TypeFn:     func() any { return &abdrc.PosControlSubmissionMsg{} },
		},
	}
	if err = n.RegisterReceiveProtocols(receiveProtocolDescriptions); err != nil {
		return nil, err
	}
	return n, nil
}
