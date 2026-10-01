package abdrc

import "github.com/unicitynetwork/bft-go-base/types/hex"

// HandoffApprovalMsg carries one old validator's D4 freeze endorsement over
// root messaging. The body and context are included so every recipient can
// verify the signature without trusting the sender's claimed body identity.
//
// The same message is the operator's unsigned intent before the root has
// ordered a Prepare: it then has no Signer or signatures, and FrozenParent is
// empty because the ROOT binds the frozen parent at the Prepare record. An
// endorser fills FrozenParent and ActivationRound from the Prepare-bound
// control state before it signs.
type HandoffApprovalMsg struct {
	_               struct{} `cbor:",toarray"`
	Body            []byte
	FrozenParent    []byte
	Candidate       []byte
	ActivationRound uint64
	Attempt         uint64
	Signer          string
	Signature       hex.Bytes
	AbortSignature  hex.Bytes
	// CandidatePreimage is the canonical H3 EVM assignment candidate whose
	// digest is Candidate. It is empty for a root-only plan, and then Candidate
	// is the legacy operator candidate hash.
	CandidatePreimage []byte
}
