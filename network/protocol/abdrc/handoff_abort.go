package abdrc

import "github.com/unicitynetwork/bft-go-base/types/hex"

// HandoffAbortTarget is an explicit operator target. The signature domain does
// not contain NextBodyID, so every recipient must match it to authenticated
// control state before accepting an approval.
type HandoffAbortTarget struct {
	Network           uint64 `json:"network"`
	OldEpoch          uint64 `json:"oldEpoch"`
	PredecessorBodyID []byte `json:"predecessorBodyId"`
	Attempt           uint64 `json:"attempt"`
	NextBodyID        []byte `json:"nextBodyId"`
}

// HandoffAbortApprovalMsg carries one explicitly operator-authorized old-set
// abort signature. It carries no candidate body or successor authorization.
type HandoffAbortApprovalMsg struct {
	_                 struct{} `cbor:",toarray"`
	Network           uint64
	OldEpoch          uint64
	PredecessorBodyID []byte
	Attempt           uint64
	NextBodyID        []byte
	Signer            string
	Signature         hex.Bytes
}

// HandoffAbortStatus is local read-only evidence. “pending” means only that
// the requested operator approval was accepted, not that consensus aborted.
type HandoffAbortStatus struct {
	State              string             `json:"state"`
	Target             HandoffAbortTarget `json:"target"`
	RecordID           string             `json:"recordId,omitempty"`
	OrderedRound       uint64             `json:"orderedRound,omitempty"`
	CommittedRootID    string             `json:"committedRootId,omitempty"`
	CommittedRootRound uint64             `json:"committedRootRound,omitempty"`
}
