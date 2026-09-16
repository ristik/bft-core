/*
Package inputcarrier is the inert carrier for the evidence a proposer binds to a block: the unicity
certificate and technical record that authorize the round (D1 §5.1, docs/design/f2c-root-input-wiring-
contract.md §3.1). It has three parts: a bounded, versioned envelope; a shard-internal transport for
it; and Verify, which authenticates what arrives through rootinput.

WHAT "INERT" MEANS HERE. No production package imports this one (inert_test.go enforces it), so no
shard node sends, receives or verifies an envelope, and nothing here can change what a node signs,
executes or certifies. It does not touch ProtocolShardPayload, disseminatedBlock, the Disseminator
interface or round.go. It is the U1 unit of docs/design/f2-execution-prerequisites.md §4: a carrier and
a fixture-verified path, activated later together with the execution-side prerequisites.

WHY IT IS NOT IN shardnode. rootinput's internal wiring-contract test imports shardnode, so shardnode
importing rootinput would stop `go test ./rootinput` from building.

EVIDENCE, NEVER A VERDICT. The envelope carries the certificate and technical record as bytes, the
shard round and the block hash they are bound to, and nothing else: no root input, no commitment, no
parent, no cursor and no flag saying anything was verified. Those belong to the verifier (f2c §3.1).
*/
package inputcarrier

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-go-base/types"
)

// Version is the only envelope version this package accepts.
const Version uint64 = 1

// ErrMalformedEnvelope marks an envelope this package refuses to interpret: an unknown version, a
// field outside its bound, a non-canonical encoding or trailing bytes. It says nothing about whether
// the evidence inside would have authenticated.
var ErrMalformedEnvelope = errors.New("inputcarrier: malformed envelope")

// Envelope is the evidence bound to one block. Every field is a copy the caller owns.
type Envelope struct {
	Version         uint64
	ShardRound      uint64 // the shard round the technical record authorizes
	BlockHash       []byte // the 32-byte hash of the block this evidence is bound to
	Certificate     []byte // canonical CBOR of the bound types.UnicityCertificate
	TechnicalRecord []byte // canonical CBOR of the bound certification.TechnicalRecord
}

// envelopeWire is the CBOR toarray wire form, matching the repository's other protocols.
type envelopeWire struct {
	_               struct{} `cbor:",toarray"`
	Version         uint64
	ShardRound      uint64
	BlockHash       []byte
	Certificate     []byte
	TechnicalRecord []byte
}

/*
Limits bounds one envelope. The frame bound is not configured separately: FrameBytes derives it from
the field bounds, so the transport can never refuse an envelope the field bounds allow, or read a frame
the field bounds would refuse after decoding.
*/
type Limits struct {
	MaxCertificateBytes     int
	MaxTechnicalRecordBytes int
}

// DefaultLimits are starting values. A technical record is a round, an epoch, a leader identifier and
// two 32-byte hashes; a certificate grows with the root validator set's signatures and proof paths.
var DefaultLimits = Limits{
	MaxCertificateBytes:     64 << 10,
	MaxTechnicalRecordBytes: 1 << 10,
}

func (l Limits) validate() error {
	if l.MaxCertificateBytes <= 0 || l.MaxTechnicalRecordBytes <= 0 {
		return fmt.Errorf("inputcarrier: envelope bounds must be positive, got %+v", l)
	}
	return nil
}

// bstrHeader is the length of the CBOR header of a byte string of n bytes.
func bstrHeader(n int) int {
	switch {
	case n < 24:
		return 1
	case n < 1<<8:
		return 2
	case n < 1<<16:
		return 3
	case n < 1<<32:
		return 5
	default:
		return 9
	}
}

/*
FrameBytes is the largest encoding of a valid envelope under these limits: the array header, version
1, the largest shard round, the 32-byte block hash, and both byte strings at their bounds with their
headers. TestLimitsCompose encodes exactly that envelope and requires its length to equal this value.
*/
func (l Limits) FrameBytes() int {
	const (
		arrayHeader = 1
		version     = 1 // Version is 1, a one-byte unsigned integer
		shardRound  = 9 // the largest uint64
		blockHash   = 2 + 32
	)
	return arrayHeader + version + shardRound + blockHash +
		bstrHeader(l.MaxCertificateBytes) + l.MaxCertificateBytes +
		bstrHeader(l.MaxTechnicalRecordBytes) + l.MaxTechnicalRecordBytes
}

func (l Limits) check(e Envelope) error {
	return l.checkVersion(e, Version)
}

func (l Limits) checkVersion(e Envelope, version uint64) error {
	switch {
	case e.Version != version:
		return fmt.Errorf("%w: version %d, only %d is accepted", ErrMalformedEnvelope, e.Version, version)
	case len(e.BlockHash) != 32:
		return fmt.Errorf("%w: block hash must be 32 bytes, got %d", ErrMalformedEnvelope, len(e.BlockHash))
	case len(e.Certificate) == 0 || len(e.Certificate) > l.MaxCertificateBytes:
		return fmt.Errorf("%w: certificate is %d bytes, bound 1..%d", ErrMalformedEnvelope, len(e.Certificate), l.MaxCertificateBytes)
	case len(e.TechnicalRecord) == 0 || len(e.TechnicalRecord) > l.MaxTechnicalRecordBytes:
		return fmt.Errorf("%w: technical record is %d bytes, bound 1..%d", ErrMalformedEnvelope, len(e.TechnicalRecord), l.MaxTechnicalRecordBytes)
	}
	return nil
}

// Encode returns the canonical encoding of e, or refuses an envelope outside the limits. Nothing is
// truncated or padded to fit.
func Encode(e Envelope, l Limits) ([]byte, error) {
	if err := l.validate(); err != nil {
		return nil, err
	}
	if err := l.check(e); err != nil {
		return nil, err
	}
	b, err := types.Cbor.Marshal(envelopeWire{
		Version: e.Version, ShardRound: e.ShardRound, BlockHash: e.BlockHash,
		Certificate: e.Certificate, TechnicalRecord: e.TechnicalRecord,
	})
	if err != nil {
		return nil, fmt.Errorf("inputcarrier: encoding envelope: %w", err)
	}
	return b, nil
}

/*
Decode interprets exactly b, or refuses it.

The length is checked before decoding, the fields are checked against the limits, and the decoded
envelope must re-encode to exactly b. That last check refuses trailing bytes, extra array elements,
non-minimal integers, indefinite lengths and every other encoding that decodes to the same values but
is not the bytes a canonical encoder writes, so the bytes a receiver holds are the bytes that were
checked. The returned envelope owns its slices.
*/
func Decode(b []byte, l Limits) (Envelope, error) {
	if err := l.validate(); err != nil {
		return Envelope{}, err
	}
	if len(b) == 0 || len(b) > l.FrameBytes() {
		return Envelope{}, fmt.Errorf("%w: %d bytes, bound 1..%d", ErrMalformedEnvelope, len(b), l.FrameBytes())
	}
	var w envelopeWire
	if err := types.Cbor.Unmarshal(b, &w); err != nil {
		return Envelope{}, fmt.Errorf("%w: %w", ErrMalformedEnvelope, err)
	}
	e := Envelope{
		Version: w.Version, ShardRound: w.ShardRound, BlockHash: bytes.Clone(w.BlockHash),
		Certificate: bytes.Clone(w.Certificate), TechnicalRecord: bytes.Clone(w.TechnicalRecord),
	}
	if err := l.check(e); err != nil {
		return Envelope{}, err
	}
	again, err := Encode(e, l)
	if err != nil {
		return Envelope{}, err
	}
	if !bytes.Equal(again, b) {
		return Envelope{}, fmt.Errorf("%w: not the canonical encoding of its own contents", ErrMalformedEnvelope)
	}
	return e, nil
}

// clone returns a copy of e that shares no slice with it.
func (e Envelope) clone() Envelope {
	return Envelope{
		Version: e.Version, ShardRound: e.ShardRound, BlockHash: bytes.Clone(e.BlockHash),
		Certificate: bytes.Clone(e.Certificate), TechnicalRecord: bytes.Clone(e.TechnicalRecord),
	}
}
