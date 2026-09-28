package service

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/unicitynetwork/bft-core/signingauthority"
	"github.com/unicitynetwork/bft-go-base/types"
)

// protocolVersion is the version of this message set. A frame naming any other version is refused
// as signing-unsupported-version: nothing is coerced to fit, and there is no negotiation, because a
// profile that changed what a request means would change what the authority signs.
const protocolVersion uint64 = 1

/*
MaxFrameBytes bounds one message on the wire, and is refused BEFORE the body is read.

It is derived rather than chosen: a reserve message carries the complete proposed request, which the
authority bounds at MaxUnsignedRequestBytes, plus the certificate and the technical record that
authorize it. Those are small in every profile this serves, and the allowance below is generous
rather than tight, because the bound that decides what is signed is the authority's own. This one
decides what a listening process is willing to read.
*/
const MaxFrameBytes = 2*signingauthority.MaxUnsignedRequestBytes + 64*1024

// CredentialBytes is the length of a client or operator credential. They are bearer secrets drawn
// from the system random source, compared in constant time, and never derived from anything an
// operator names.
const CredentialBytes = 32

// errFrameTooLarge is the transport's own refusal, distinct from the authority's ErrRequestTooLarge:
// this one is decided on a length that has been read and a body that has not.
var errFrameTooLarge = errors.New("signing-frame-too-large")

// errWrongEndpoint is an operation asked of the endpoint that does not serve it: a client asking to
// replace a session, or an operator asking to sign. Endpoints do not fall back to each other.
var errWrongEndpoint = errors.New("signing-operation-not-served-here")

// errOperatorUnauthenticated is an operator-endpoint call without the operator credential.
var errOperatorUnauthenticated = errors.New("signing-operator-unauthenticated")

// errMalformed is a frame that decodes into nothing this protocol defines.
var errMalformed = errors.New("signing-malformed-message")

type op uint64

const (
	opReserve        op = 1
	opSign           op = 2
	opRetainResponse op = 3
	opRelease        op = 4
	opRestoreStatus  op = 5

	opReplaceSession op = 101
	opStatus         op = 102
	opEnrollment     op = 103
	// opCompleteEnrollment states a pending authority's shard configuration. It carries the whole
	// configuration, never a hash, because the authority checks the configuration names its own key.
	opCompleteEnrollment op = 104
)

func (o op) servedToClient() bool {
	switch o {
	case opReserve, opSign, opRetainResponse, opRelease, opRestoreStatus:
		return true
	}
	return false
}

func (o op) servedToOperator() bool {
	switch o {
	case opReplaceSession, opStatus, opEnrollment, opCompleteEnrollment:
		return true
	}
	return false
}

func (o op) String() string {
	switch o {
	case opReserve:
		return "reserve"
	case opSign:
		return "sign"
	case opRetainResponse:
		return "retain-response"
	case opRelease:
		return "release"
	case opRestoreStatus:
		return "restore-status"
	case opReplaceSession:
		return "replace-session"
	case opStatus:
		return "status"
	case opEnrollment:
		return "enrollment"
	case opCompleteEnrollment:
		return "complete-enrollment"
	}
	return fmt.Sprintf("unknown(%d)", uint64(o))
}

type wireRequest struct {
	_          struct{} `cbor:",toarray"`
	Version    uint64
	Op         uint64
	Credential []byte
	Payload    []byte
}

type wireResponse struct {
	_       struct{} `cbor:",toarray"`
	Version uint64
	// Refusal is the contract's name for the outcome, empty on success. It is a name rather than a
	// sentence so the client can map it back to the same error values an in-process caller sees, and
	// so a round's non-voting reason says the same thing either way.
	Refusal string
	Payload []byte
}

type reservePayload struct {
	_         struct{} `cbor:",toarray"`
	UC        []byte
	Technical []byte
	Proposed  []byte
}

type authorizationPayload struct {
	_              struct{} `cbor:",toarray"`
	AssignedRound  uint64
	AssignedEpoch  uint64
	ID             []byte
	Unsigned       []byte
	UnsignedDigest []byte
}

type releasePayload struct {
	_      struct{} `cbor:",toarray"`
	Round  uint64
	Digest []byte
}

type statusPayload struct {
	_                struct{} `cbor:",toarray"`
	Generation       uint64
	ReservedRound    uint64
	HasReservation   bool
	ResponseRetained bool
	Faulted          bool
	KeyLost          bool
}

type enrollmentPayload struct {
	_          struct{} `cbor:",toarray"`
	Enrollment []byte
	PublicKey  []byte
}

// writeFrame writes one length-prefixed CBOR message.
func writeFrame(w io.Writer, msg any) error {
	body, err := types.Cbor.Marshal(msg)
	if err != nil {
		return fmt.Errorf("encoding message: %w", err)
	}
	if len(body) > MaxFrameBytes {
		return fmt.Errorf("%w: %d bytes", errFrameTooLarge, len(body))
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(body)))
	if _, err := w.Write(header[:]); err != nil {
		return fmt.Errorf("writing frame header: %w", err)
	}
	if _, err := w.Write(body); err != nil {
		return fmt.Errorf("writing frame: %w", err)
	}
	return nil
}

/*
readFrame reads one length-prefixed CBOR message.

An oversize frame is refused on its header, before its body is read: the reader neither allocates the
body nor decodes it. The connection is not usable afterwards, because the unread body would be taken
for the next frame, so every caller of this closes the connection on errFrameTooLarge. That is why
the error is distinguishable rather than folded into a decode failure.
*/
func readFrame(r io.Reader, msg any) error {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 {
		return fmt.Errorf("%w: empty frame", errMalformed)
	}
	if uint64(size) > MaxFrameBytes {
		return fmt.Errorf("%w: %d bytes announced", errFrameTooLarge, size)
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(r, body); err != nil {
		return err
	}
	if err := types.Cbor.Unmarshal(body, msg); err != nil {
		return fmt.Errorf("%w: %v", errMalformed, err)
	}
	return nil
}
