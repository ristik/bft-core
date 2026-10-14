package utb

import (
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/utbentry"
)

// ErrUnsigned is returned for bytes that are not the canonical unsigned (SigBytes) form of a version-2 entry.
var ErrUnsigned = utbentry.ErrUnsigned

// DecodeUnsigned strictly decodes the SigBytes of a version-2 entry (see utbentry.Decode).
func DecodeUnsigned(b []byte) (*types.RootTrustBaseV2, error) { return utbentry.Decode(b) }
