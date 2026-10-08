package evmassign

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-go-base/types"
)

// A primary candidate's EVM proof travels in the Freeze companion beside the candidate preimage: the storage-proof witness of the election
// and custody state at the frozen parent P (rootchain/evmstate), and the EVM possession proofs whose set the election committed. It is
// retained with the companion, so a replay judges the same bytes.

const (
	// MaxPrimaryWitnessBytes bounds the witness; MaxPrimaryProofBytes the whole proof (the witness plus up to 32 signatures).
	MaxPrimaryWitnessBytes = 512 << 10
	MaxPrimaryProofBytes   = MaxPrimaryWitnessBytes + 32*(8+33+65+16) + 1024
	// MaxPrimaryPoPs is the committee ceiling.
	MaxPrimaryPoPs = 32
)

// ErrPrimaryProofEncoding reports a proof that is oversized, not canonical or malformed.
var ErrPrimaryProofEncoding = errors.New("evmassign: invalid primary proof encoding")

// PrimaryProof is the evidence a primary candidate carries for its Election result.
type PrimaryProof struct {
	_       struct{} `cbor:",toarray"`
	Witness []byte
	PoPs    []EVMPoP
}

// Encode is the one canonical encoding.
func (p PrimaryProof) Encode() ([]byte, error) {
	if len(p.Witness) == 0 || len(p.Witness) > MaxPrimaryWitnessBytes || len(p.PoPs) == 0 || len(p.PoPs) > MaxPrimaryPoPs {
		return nil, ErrPrimaryProofEncoding
	}
	b, err := types.Cbor.Marshal(p)
	if err != nil || len(b) > MaxPrimaryProofBytes {
		return nil, ErrPrimaryProofEncoding
	}
	return b, nil
}

// DecodePrimaryProof accepts exactly one canonical encoding.
func DecodePrimaryProof(raw []byte) (PrimaryProof, error) {
	var p PrimaryProof
	if len(raw) == 0 || len(raw) > MaxPrimaryProofBytes {
		return p, ErrPrimaryProofEncoding
	}
	if err := types.Cbor.Unmarshal(raw, &p); err != nil {
		return PrimaryProof{}, errors.Join(ErrPrimaryProofEncoding, err)
	}
	canonical, err := p.Encode()
	if err != nil || !bytes.Equal(canonical, raw) {
		return PrimaryProof{}, fmt.Errorf("%w: not canonical", ErrPrimaryProofEncoding)
	}
	return p, nil
}
