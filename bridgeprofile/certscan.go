package bridgeprofile

import (
	"fmt"

	"github.com/unicitynetwork/bft-core/b1ref"
	"github.com/unicitynetwork/bft-go-base/types"
)

// SDKSignatureLength is the only seal signature width the SDK 3.0.1 certificate codec accepts. Native B1 also admits 64 bytes.
const SDKSignatureLength = 65

// scanCertificate is the bounded certificate scan every embedded or token-carried certificate passes before any allocation
// proportional to its contents or any cryptography: the native shape and sublimit scan (b1ref.ScanUC) intersected with the SDK
// codec subset. steps is the cumulative path-step account of the enclosing object and is checked against MaxPathSteps.
func scanCertificate(raw []byte, steps *uint64) error {
	// The bridge restrictions run before the generic native decoder in ScanUC.
	// Native B1 deliberately accepts null containers; the JS SDK cannot decode
	// those encodings. Do not normalize them or change B1's acceptance rules.
	if len(raw) > b1ref.MaxUCBytes {
		return fmt.Errorf("%w: %w", ErrCertScan, b1ref.ErrUCTooLarge)
	}
	root, err := scanOneNative(raw)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCertScan, err)
	}
	uc, err := root.tagContent(types.UnicityCertificateTag)
	if err != nil || !uc.isArray(7) {
		return ErrCertScan
	}
	for _, field := range []struct {
		index         int
		tag           uint64
		arity         int
		requiredIndex int
		major         byte
	}{
		{1, types.InputRecordTag, 10, 5, majBytes},
		{4, types.ShardTreeCertificateTag, 3, 2, majArray},
		{5, types.UnicityTreeCertificateTag, 3, 2, majArray},
		{6, types.UnicitySealTag, 8, 7, majMap},
	} {
		body, err := uc.kids[field.index].tagContent(field.tag)
		if err != nil || !body.isArray(field.arity) || body.kids[field.requiredIndex].major != field.major {
			return fmt.Errorf("%w: SDK field %d requires CBOR major %d", ErrCertScan, field.index, field.major)
		}
	}
	seal := uc.kids[6].kids[0].kids
	if !seal[1].isUint() || seal[1].arg == 0 || seal[1].arg > 65535 {
		return fmt.Errorf("%w: SDK seal network outside 1..65535", ErrCertScan)
	}
	for i := 1; i < len(seal[7].kids); i += 2 {
		sig := seal[7].kids[i]
		if !sig.isBytes() {
			return ErrCertScan
		}
		if len(sig.data) != SDKSignatureLength {
			return fmt.Errorf("%w: %d bytes", ErrCertSigLength, len(sig.data))
		}
	}
	shape, err := b1ref.ScanUC(raw)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrCertScan, err)
	}
	return addPathSteps(steps, shape.PathSteps)
}

// All UC and RSMT paths in an enclosing object share this overflow-safe budget.
func addPathSteps(steps *uint64, n uint64) error {
	if *steps > MaxPathSteps || n > MaxPathSteps-*steps {
		return ErrTooManyPaths
	}
	*steps += n
	return nil
}
