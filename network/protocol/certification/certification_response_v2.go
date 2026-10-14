package certification

import (
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"
)

const (
	// CertificationResponseVersion2 is the explicit version of the response that carries trust-base updates. It is the first field of the array and is
	// the only signal that a peer supports them: the arity of the legacy forms (4 or 6 elements) says nothing about it.
	CertificationResponseVersion2 uint64 = 2

	// MaxTrustBaseUpdates bounds the signed trust-base entries attached to one response: the current UC signer epoch's successor, or the two entries a
	// folded transition needs. Several missed epochs are fetched (GetTrustBase), never attached; the whole chain is never sent.
	MaxTrustBaseUpdates = 2
	// MaxTrustBaseUpdateBytes bounds one attached entry (the 16-member profile fits with room to spare).
	MaxTrustBaseUpdateBytes = 64 << 10
)

// ErrResponseV2 is returned for a response that is not a well-formed version 2 message.
var ErrResponseV2 = errors.New("invalid certification response v2")

/*
CertificationResponseV2 is the certification response of a deployment whose roots publish signed trust-base entries (UTB). It is the legacy response plus
the explicit version and a bounded list of finalized entries, each the canonical bytes of a types.RootTrustBaseV2 (tag 39000, version 2), ascending by
epoch. It travels on /ab/certificates/0.0.2, beside /ab/certificates/0.0.1, which keeps carrying CertificationResponse.

The entries are an authority update, not part of the certificate: the UC, the technical record, Status and Message mean exactly what they mean in the
legacy response (the wrapped UC is the last-good certificate whatever the status, and a rejection is not turned into an acceptance by a valid update). The
receiver authenticates the entries from the predecessor it already holds and only then verifies the UC under its own epoch.
*/
type CertificationResponseV2 struct {
	_                struct{} `cbor:",toarray"`
	Version          uint64
	Partition        types.PartitionID
	Shard            types.ShardID
	Technical        TechnicalRecord
	UC               types.UnicityCertificate
	Status           uint32
	Message          string
	TrustBaseUpdates []hex.Bytes
}

// NewCertificationResponseV2 wraps a legacy response with the entries to attach. The entries are referenced, not copied: they are immutable stored bytes.
func NewCertificationResponseV2(cr *CertificationResponse, updates [][]byte) *CertificationResponseV2 {
	out := &CertificationResponseV2{Version: CertificationResponseVersion2, Partition: cr.Partition, Shard: cr.Shard, Technical: cr.Technical, UC: cr.UC,
		Status: cr.Status, Message: cr.Message}
	for _, u := range updates {
		out.TrustBaseUpdates = append(out.TrustBaseUpdates, u)
	}
	return out
}

// Response is the legacy view of the message: what every consumer of a certification response already handles.
func (cr *CertificationResponseV2) Response() *CertificationResponse {
	return &CertificationResponse{Partition: cr.Partition, Shard: cr.Shard, Technical: cr.Technical, UC: cr.UC, Status: cr.Status, Message: cr.Message}
}

// IsValid is the legacy response's validity plus the bounds on the attached entries.
func (cr *CertificationResponseV2) IsValid() error {
	if cr == nil {
		return fmt.Errorf("%w: nil", ErrResponseV2)
	}
	if err := cr.checkUpdates(); err != nil {
		return err
	}
	return cr.Response().IsValid()
}

func (cr *CertificationResponseV2) checkUpdates() error {
	if cr.Version != CertificationResponseVersion2 {
		return fmt.Errorf("%w: version %d", ErrResponseV2, cr.Version)
	}
	if len(cr.TrustBaseUpdates) > MaxTrustBaseUpdates {
		return fmt.Errorf("%w: %d trust-base updates (at most %d)", ErrResponseV2, len(cr.TrustBaseUpdates), MaxTrustBaseUpdates)
	}
	for i, u := range cr.TrustBaseUpdates {
		if len(u) == 0 || len(u) > MaxTrustBaseUpdateBytes {
			return fmt.Errorf("%w: update %d is %d bytes", ErrResponseV2, i, len(u))
		}
	}
	return nil
}

// MarshalCBOR refuses a message that is not version 2 or exceeds the bounds, so a sender cannot produce what no receiver accepts.
func (cr CertificationResponseV2) MarshalCBOR() ([]byte, error) {
	if err := cr.checkUpdates(); err != nil {
		return nil, err
	}
	type wire CertificationResponseV2
	return types.Cbor.Marshal(wire(cr))
}

// UnmarshalCBOR is strict: exactly the eight-element array, version 2, within the bounds. Neither legacy arity is accepted here.
func (cr *CertificationResponseV2) UnmarshalCBOR(data []byte) error {
	type wire CertificationResponseV2
	var w wire
	if err := types.Cbor.Unmarshal(data, &w); err != nil {
		return fmt.Errorf("%w: %w", ErrResponseV2, err)
	}
	out := CertificationResponseV2(w)
	if err := out.checkUpdates(); err != nil {
		return err
	}
	*cr = out
	return nil
}
