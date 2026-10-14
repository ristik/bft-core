package utb

import (
	"fmt"

	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"

	"github.com/unicitynetwork/bft-core/utbentry"
)

// ErrUnsigned is returned for bytes that are not the canonical unsigned (SigBytes) form of a version-2 entry.
var ErrUnsigned = utbentry.ErrUnsigned

// DecodeUnsigned strictly decodes the SigBytes of a version-2 entry (see utbentry.Decode).
func DecodeUnsigned(b []byte) (*types.RootTrustBaseV2, error) { return utbentry.Decode(b) }

// Signed is the canonical bytes of the finalized entry: the unsigned entry b with the endorsers' signatures. It decodes b strictly first, so only an
// entry that is a valid unsigned entry can be given a witness; verifying the witness is the store's and the verifiers' job.
func Signed(b []byte, signatures map[string]hex.Bytes) ([]byte, error) {
	e, err := DecodeUnsigned(b)
	if err != nil {
		return nil, err
	}
	if len(signatures) == 0 {
		return nil, fmt.Errorf("%w: no signatures", ErrUnsigned)
	}
	e.Signatures = signatures
	return e.MarshalCBOR()
}
