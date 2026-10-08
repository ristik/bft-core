package abdrc

import (
	"fmt"

	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"

	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
)

// PosControlSubmissionTag separates the signed submission of a control from every other root signature.
const PosControlSubmissionTag = "UNICITY_P85_CONTROL_SUBMISSION"

// PosControlSubmissionMsg is a Retirement or RejectResult control a root validator offers the leader to order. The control carries no
// ordering position (the block that orders it stamps its own epoch and round) and its witness is not in the message: it commits to the
// witness by hash and the leader pulls the bytes from the submitter (rootchain/poswitness), which holds them.
type PosControlSubmissionMsg struct {
	_       struct{}           `cbor:",toarray"`
	Control rctypes.PosControl `json:"control"`
	// Epoch is the root epoch whose trust base the submission is signed under: a signature of another epoch is no submission of this
	// one, so an old submission cannot be replayed to occupy a validator's queue slots.
	Epoch     uint64    `json:"epoch"`
	Signer    string    `json:"signer"`
	Signature hex.Bytes `json:"signature"`
}

// SigningBytes are the bytes the submitter signs: the tag and the control's canonical item.
func (m PosControlSubmissionMsg) SigningBytes() ([]byte, error) {
	return PosControlSigningBytes(m.Control, m.Epoch)
}

// PosControlSigningBytes are the bytes a submission of c in the given root epoch is signed over.
func PosControlSigningBytes(c rctypes.PosControl, epoch uint64) ([]byte, error) {
	item, err := c.MarshalCBOR()
	if err != nil {
		return nil, fmt.Errorf("control: %w", err)
	}
	return types.Cbor.Marshal([]any{PosControlSubmissionTag, epoch, item})
}
