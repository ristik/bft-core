package certifiedstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-go-base/types"
)

var embeddedRecordDec = func() cbor.DecMode {
	m, err := cbor.DecOptions{MaxNestedLevels: 16, MaxArrayElements: 65536, MaxMapPairs: 65536, IndefLength: cbor.IndefLengthForbidden}.DecMode()
	if err != nil {
		panic(err)
	}
	return m
}()

// EncodeVerifiedRecord returns the exact canonical v1 record envelope after verifying it under c.
// It is a pure codec/verification boundary for versioned stores that embed the reviewed ordinary record.
func EncodeVerifiedRecord(ctx context.Context, c Context, r Record) ([]byte, Loaded, error) {
	raw, sr, err := encodeRecord(c, r)
	if err != nil {
		return nil, Loaded{}, err
	}
	l, err := verify(ctx, c, sr)
	if err != nil {
		return nil, Loaded{}, err
	}
	return bytes.Clone(raw), l, nil
}

// VerifyEncodedRecord verifies one exact canonical v1 record envelope under c. The byte bound is
// enforced before copying or decoding; alternate encodings of the same values are refused.
func VerifyEncodedRecord(ctx context.Context, c Context, raw []byte) (Loaded, error) {
	if len(raw) == 0 || len(raw) > MaxRecordBytes {
		return Loaded{}, fmt.Errorf("%w: record is %d bytes, bound 1..%d", ErrRecordUntrusted, len(raw), MaxRecordBytes)
	}
	raw = bytes.Clone(raw)
	sr, err := decodeRecord(raw)
	if err != nil {
		return Loaded{}, err
	}
	if err = embeddedRecordDec.Valid(sr.Certificate); err != nil {
		return Loaded{}, fmt.Errorf("%w: certificate bounds: %v", ErrRecordUntrusted, err)
	}
	if err = embeddedRecordDec.Valid(sr.Technical); err != nil {
		return Loaded{}, fmt.Errorf("%w: technical-record bounds: %v", ErrRecordUntrusted, err)
	}
	var uc types.UnicityCertificate
	if err = types.Cbor.Unmarshal(sr.Certificate, &uc); err != nil {
		return Loaded{}, fmt.Errorf("%w: certificate: %v", ErrRecordUntrusted, err)
	}
	var tr certification.TechnicalRecord
	if err = types.Cbor.Unmarshal(sr.Technical, &tr); err != nil {
		return Loaded{}, fmt.Errorf("%w: technical record: %v", ErrRecordUntrusted, err)
	}
	ucCanonical, _ := types.Cbor.Marshal(&uc)
	trCanonical, _ := types.Cbor.Marshal(&tr)
	if !bytes.Equal(ucCanonical, sr.Certificate) || !bytes.Equal(trCanonical, sr.Technical) {
		return Loaded{}, fmt.Errorf("%w: nested certificate or technical record is not canonical", ErrRecordUntrusted)
	}
	payload, err := types.Cbor.Marshal(sr)
	if err != nil {
		return Loaded{}, err
	}
	sum := sha256.Sum256(payload)
	canonical, err := types.Cbor.Marshal(envelope{Version: RecordVersion, Payload: payload, Digest: sum[:]})
	if err != nil {
		return Loaded{}, err
	}
	if !bytes.Equal(raw, canonical) {
		return Loaded{}, fmt.Errorf("%w: record envelope is not canonical", ErrRecordUntrusted)
	}
	return verify(ctx, c, sr)
}
