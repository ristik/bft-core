package bridgeprofile

import (
	"fmt"

	"github.com/unicitynetwork/bft-core/b1ref"
)

// SDKSignatureLength is the only seal signature width the SDK 3.0.1 certificate codec accepts. Native B1 also admits 64 bytes.
const SDKSignatureLength = 65

// scanCertificate is the bounded certificate scan every embedded or token-carried certificate passes before any allocation
// proportional to its contents or any cryptography: the native shape and sublimit scan (b1ref.ScanUC) intersected with the SDK
// codec subset. steps is the cumulative path-step account of the enclosing object and is checked against MaxPathSteps.
func scanCertificate(raw []byte, steps *uint64) error {
	shape, err := b1ref.ScanUC(raw)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrCertScan, err)
	}
	for _, n := range shape.SigLens {
		if n != SDKSignatureLength {
			return fmt.Errorf("%w: %d bytes", ErrCertSigLength, n)
		}
	}
	if *steps += shape.PathSteps; *steps > MaxPathSteps {
		return ErrTooManyPaths
	}
	return nil
}
