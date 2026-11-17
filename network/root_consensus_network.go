package network

import (
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

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

// MaxRootVoteFrame and MaxRootTimeoutFrame bound the wire frame of a received vote and timeout vote before anything is decoded (#1086 review):
// a vote or timeout carries a high QC (and a timeout the last TC) of at most q3format.MaxMembers signers, well below this.
const (
	MaxRootVoteFrame    = 4 << 20
	MaxRootTimeoutFrame = 4 << 20
)

// The ingress of root proposals (#1113). A proposal frame is bounded by abdrc.MaxProposalFrame, a validity rule the leader keeps when it
// builds the proposal, and refused before its payload is read when larger. Its bytes in flight and queued are reserved before they are read
// (IngressBudget): one peer at most one maximal frame, every peer together at most RootProposalIngressBytes, of which
// RootProposalIngressProtected is kept for the leaders of the current and the next round (RootConsensusGate.EligibleProposer), so the
// other admitted roots cannot fill it against them. Only roots of the installed committee and of its staged successor are admitted.
const (
	RootProposalIngressPerPeer   = abdrc.MaxProposalFrame
	RootProposalIngressProtected = 2 * abdrc.MaxProposalFrame
	RootProposalIngressBytes     = RootProposalIngressProtected + abdrc.MaxProposalFrame
)

// RootConsensusGate is what the root consensus network asks the consensus manager about the authenticated sender of a frame, before
// reading it: KnownRoot, a root of the installed committee or of the staged successor; EligibleProposer, the leader of the current or the
// next round. Both must be cheap and safe for concurrent use. Until a gate is set, no proposal is admitted.
type RootConsensusGate interface {
	KnownRoot(id peer.ID) bool
	EligibleProposer(id peer.ID) bool
}

type rootGate struct {
	gate atomic.Pointer[RootConsensusGate]
}

func (g *rootGate) knownRoot(id peer.ID) bool {
	p := g.gate.Load()
	return p != nil && (*p).KnownRoot(id)
}

func (g *rootGate) eligibleProposer(id peer.ID) bool {
	p := g.gate.Load()
	return p != nil && (*p).EligibleProposer(id)
}

// SetRootConsensusGate sets the admission and priority of received proposals of a root consensus network (NewLibP2RootConsensusNetwork);
// it is a no-op on any other network.
func (n *LibP2PNetwork) SetRootConsensusGate(g RootConsensusGate) {
	if n.rootGate != nil && g != nil {
		n.rootGate.gate.Store(&g)
	}
}

// consensusSendRetries is the number of repeats of an undelivered proposal, vote or timeout vote to a connected root (#982).
const consensusSendRetries = 2

func NewLibP2RootConsensusNetwork(self *Peer, capacity uint, sendTimeout time.Duration, obs Observability) (*LibP2PNetwork, error) {
	n, err := NewLibP2PNetwork(self, capacity, obs)
	if err != nil {
		return nil, err
	}
	n.rootGate = &rootGate{}
	proposalIngress := NewProtectedIngressBudget(RootProposalIngressBytes, RootProposalIngressProtected, RootProposalIngressPerPeer)
	proposalIngress.SetPriority(n.rootGate.eligibleProposer)
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
			ProtocolID:     ProtocolRootProposal,
			TypeFn:         func() any { return &abdrc.ProposalMsg{} },
			AdmitPeer:      n.rootGate.knownRoot,
			RevalidatePeer: n.rootGate.knownRoot,
			MaxFrameSize:   abdrc.MaxProposalFrame,
			Ingress:        proposalIngress,
		},
		{
			ProtocolID:   ProtocolRootVote,
			TypeFn:       func() any { return &abdrc.VoteMsg{} },
			MaxFrameSize: MaxRootVoteFrame,
		},
		{
			ProtocolID:   ProtocolRootTimeout,
			TypeFn:       func() any { return &abdrc.TimeoutMsg{} },
			MaxFrameSize: MaxRootTimeoutFrame,
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
