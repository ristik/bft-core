package votesig

import "errors"

// EnvelopeUTB is the version of the vote and certificate envelope that carries the signed trust-base endorsement: [3, inner, utb], where inner is the
// unchanged scheme 1 or scheme 2 encoding of the same message. The envelope version is separate from the signing scheme and is chosen by the epoch's
// authenticated Config.UTB, never by arity or signature length.
const EnvelopeUTB uint64 = 3

var (
	// ErrEnvelope is returned for a vote or certificate whose envelope is not the one its epoch requires.
	ErrEnvelope = errors.New("message envelope does not match the epoch's configuration")
	// ErrUTB is returned for an invalid trust-base endorsement of a vote or certificate.
	ErrUTB = errors.New("invalid trust-base endorsement")
)

// PeekEnvelopeUTB reports whether data starts the version 3 envelope: a three-item array whose first item is the integer 3.
func PeekEnvelopeUTB(data []byte) bool {
	return len(data) >= 2 && data[0] == 0x83 && data[1] == byte(EnvelopeUTB)
}
