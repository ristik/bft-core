package abdrc

import "github.com/unicitynetwork/bft-go-base/types/hex"

// HandoffApprovalMsg carries one old validator's D4 freeze endorsement over
// root messaging. The body and context are included so every recipient can
// verify the signature without trusting the sender's claimed body identity.
type HandoffApprovalMsg struct {
	_               struct{} `cbor:",toarray"`
	Body            []byte
	FrozenParent    []byte
	Candidate       []byte
	PreFreezeRound  uint64
	PreFreezeRoot   []byte
	ActivationRound uint64
	Attempt         uint64
	Signer          string
	Signature       hex.Bytes
	AbortSignature  hex.Bytes
}
