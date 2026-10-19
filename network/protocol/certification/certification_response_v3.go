package certification

import (
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"

	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"
)

const (
	// CertificationResponseV3Version is the only version accepted in the V3 envelope. It is the first element of the array and the only signal of the
	// format: no form is ever inferred from an array length.
	CertificationResponseV3Version uint32 = 3

	// MaxTrustBaseUpdates bounds the signed trust-base entries attached to one response: the current UC signer epoch's successor, or the two entries a
	// folded transition needs. Several missed epochs are fetched (GetTrustBase), never attached; the whole chain is never sent.
	MaxTrustBaseUpdates = 2
	// MaxTrustBaseUpdateBytes bounds one attached entry (the 16-member profile fits with room to spare).
	MaxTrustBaseUpdateBytes = 64 << 10

	// MaxCertificationResponseV3Frame is the limit for the CBOR payload (excluding the varint length prefix) of a V3 frame: the V2 limit plus the entries.
	// Entries and signatures are never truncated to fit; the partition view is the only optional part and is omitted on its own size.
	MaxCertificationResponseV3Frame = MaxCertificationResponseV2Frame + MaxTrustBaseUpdates*MaxTrustBaseUpdateBytes
)

// ErrResponseV3 is returned for a response that is not a well-formed version 3 message.
var ErrResponseV3 = errors.New("invalid certification response v3")

/*
CertificationResponseV3 is the certification response of a deployment whose roots publish signed trust-base entries (UTB) and consolidated partition
views. It travels on /ab/certificates/0.0.3:

	[3, [partition, shard, technical, uc, status, message], bstr(partitionView) | null, [bstr(entry), ...]]

The wrapped response is the legacy response: the UC, the technical record, Status and Message mean exactly what they mean there (the UC is the last-good
certificate whatever the status, and a rejection is never turned into an acceptance by a valid update or view). The partition view is opaque canonical
bytes at this layer, null when omitted (never an empty string). The entries are an authority update, not part of the certificate: each the canonical bytes
of a types.RootTrustBaseV2 (tag 39000, version 2), ascending by epoch, at most MaxTrustBaseUpdates of at most MaxTrustBaseUpdateBytes. The receiver
authenticates them from the predecessor it already holds and only then verifies the UC under its own epoch.
*/
type CertificationResponseV3 struct {
	_                struct{} `cbor:",toarray"`
	Version          uint32
	Response         CertificationResponse
	PartitionView    []byte
	TrustBaseUpdates []hex.Bytes
}

// NewCertificationResponseV3 wraps a response with the entries to attach. The partition view is the response's in-process carrier, shared not copied
// (it is immutable once encoded), and omitted when it exceeds the view limit; the entries are referenced, they are immutable stored bytes.
func NewCertificationResponseV3(cr *CertificationResponse, updates [][]byte) *CertificationResponseV3 {
	v3 := &CertificationResponseV3{Version: CertificationResponseV3Version, Response: *cr}
	v3.Response.PartitionView = nil
	if n := len(cr.PartitionView); n > 0 && n <= MaxPartitionViewSize {
		v3.PartitionView = cr.PartitionView
	}
	for _, u := range updates {
		v3.TrustBaseUpdates = append(v3.TrustBaseUpdates, u)
	}
	return v3
}

// Legacy returns the operational response with the partition view copied into the in-process carrier field.
func (v3 *CertificationResponseV3) Legacy() *CertificationResponse {
	cr := v3.Response
	cr.PartitionView = nil
	if len(v3.PartitionView) > 0 {
		cr.PartitionView = append([]byte(nil), v3.PartitionView...)
	}
	return &cr
}

// IsValid checks the envelope: the version, an explicit null or non-empty view and the bounds on the entries. The operational response is validated
// with CertificationResponse.IsValid and the view bytes by their owner.
func (v3 *CertificationResponseV3) IsValid() error {
	if err := v3.checkEnvelope(); err != nil {
		return err
	}
	return v3.Response.IsValid()
}

func (v3 *CertificationResponseV3) checkEnvelope() error {
	if v3 == nil {
		return fmt.Errorf("%w: nil", ErrResponseV3)
	}
	if v3.Version != CertificationResponseV3Version {
		return fmt.Errorf("%w: version %d", ErrResponseV3, v3.Version)
	}
	if v3.PartitionView != nil && len(v3.PartitionView) == 0 {
		return fmt.Errorf("%w: partition view must be null or non-empty", ErrResponseV3)
	}
	if len(v3.PartitionView) > MaxPartitionViewSize {
		return fmt.Errorf("%w: partition view of %d bytes (at most %d)", ErrResponseV3, len(v3.PartitionView), MaxPartitionViewSize)
	}
	if len(v3.TrustBaseUpdates) > MaxTrustBaseUpdates {
		return fmt.Errorf("%w: %d trust-base updates (at most %d)", ErrResponseV3, len(v3.TrustBaseUpdates), MaxTrustBaseUpdates)
	}
	for i, u := range v3.TrustBaseUpdates {
		if len(u) == 0 || len(u) > MaxTrustBaseUpdateBytes {
			return fmt.Errorf("%w: update %d is %d bytes", ErrResponseV3, i, len(u))
		}
	}
	return nil
}

// MarshalCBOR refuses a message that is not version 3 or exceeds the bounds, so a sender cannot produce what no receiver accepts.
func (v3 CertificationResponseV3) MarshalCBOR() ([]byte, error) {
	if err := v3.checkEnvelope(); err != nil {
		return nil, err
	}
	type wire CertificationResponseV3
	return types.Cbor.Marshal(wire(v3))
}

// UnmarshalCBOR is strict: exactly the four-element array, version 3, a view that is a definite-length byte string or null (an integer array or
// undefined is refused), entries within the bounds.
func (v3 *CertificationResponseV3) UnmarshalCBOR(data []byte) error {
	type rawEnvelope struct {
		_                struct{} `cbor:",toarray"`
		Version          uint32
		Response         CertificationResponse
		PartitionView    cbor.RawMessage
		TrustBaseUpdates []hex.Bytes
	}
	var r rawEnvelope
	if err := types.Cbor.Unmarshal(data, &r); err != nil {
		return fmt.Errorf("%w: %w", ErrResponseV3, err)
	}
	if len(r.PartitionView) == 0 {
		return fmt.Errorf("%w: partition view is missing", ErrResponseV3)
	}
	var view []byte
	switch major := r.PartitionView[0] >> 5; {
	case r.PartitionView[0] == 0xf6: // null
	case major == 2 && r.PartitionView[0] != 0x5f: // definite-length byte string
		if err := cbor.Unmarshal(r.PartitionView, &view); err != nil {
			return fmt.Errorf("%w: decoding partition view: %w", ErrResponseV3, err)
		}
	default:
		return fmt.Errorf("%w: partition view must be a byte string or null, got CBOR major type %d", ErrResponseV3, major)
	}
	out := CertificationResponseV3{Version: r.Version, Response: r.Response, PartitionView: view, TrustBaseUpdates: r.TrustBaseUpdates}
	if err := out.checkEnvelope(); err != nil {
		return err
	}
	*v3 = out
	return nil
}
