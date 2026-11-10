// Package gettrustbase is the peer protocol that serves finalized signed trust-base entries (types.RootTrustBaseV2) from the append-only entry store
// (utbstore), the client that catches a store up from it, and the tag-39014 request codec. The response format and the release bundle are bft-go-base's (types.TrustBaseResponse, types.EncodeTrustBaseBundle, ...).
//
// A request names (network, fromEpoch, toEpoch|null) and an optional snapshot (end epoch and its EntryID) that freezes pagination; a response is one
// bounded contiguous ascending page of stored canonical entry bytes. Servers add no authority: clients authenticate every unknown entry from their latest
// held entry (utbstore.Append) and the cursor is only a consistency hint.
package gettrustbase

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/unicitynetwork/bft-go-base/types"
)

const (
	// ProtocolID is the libp2p stream protocol of the request/response exchange.
	ProtocolID = "/unicity/get-trust-base/1.0.0"

	// RequestTag is the CBOR tag of the request. bft-go-base does not provide the request side; the response tag is types.TrustBaseResponseTag.
	RequestTag types.CborTag = 39014

	// Version is the request version (the response version is types.TrustBaseResponseVersion).
	Version uint32 = 1

	MaxRequestBytes = 1 << 10
	entryIDLen      = types.TrustBaseV2IDLen
	maxNesting      = 16
	maxArray        = 16
)

var ErrEncoding = errors.New("gettrustbase: invalid request encoding")

// Request is [version=1, network, fromEpoch, toEpoch|null, snapshotEnd|null, snapshotEntryID|null, maxEntries, maxBytes]. Zero is never an omission
// sentinel; null is.
type Request struct {
	_               struct{} `cbor:",toarray"`
	Version         uint32
	Network         types.NetworkID
	FromEpoch       uint64
	ToEpoch         *uint64
	SnapshotEnd     *uint64
	SnapshotEntryID []byte
	MaxEntries      uint32
	MaxBytes        uint32
}

func requestDecMode() cbor.DecMode {
	m, err := cbor.DecOptions{
		DupMapKey:        cbor.DupMapKeyEnforcedAPF,
		IndefLength:      cbor.IndefLengthForbidden,
		MaxNestedLevels:  maxNesting,
		MaxArrayElements: maxArray,
		MaxMapPairs:      maxArray,
		TagsMd:           cbor.TagsAllowed,
	}.DecMode()
	if err != nil {
		panic(err)
	}
	return m
}

// decodeRequest strictly decodes data as tag(content): exact tag, bounded arrays, no trailing bytes and the deterministic encoding only.
func decodeRequest(data []byte, out *Request) error {
	dm := requestDecMode()
	var raw cbor.RawTag
	if err := dm.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("%w: %v", ErrEncoding, err)
	}
	if raw.Number != RequestTag {
		return fmt.Errorf("%w: tag %d, expected %d", ErrEncoding, raw.Number, RequestTag)
	}
	if err := dm.Unmarshal(raw.Content, out); err != nil {
		return fmt.Errorf("%w: %v", ErrEncoding, err)
	}
	again, err := types.Cbor.MarshalTaggedValue(RequestTag, out)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrEncoding, err)
	}
	if !bytes.Equal(again, data) {
		return fmt.Errorf("%w: not the deterministic encoding", ErrEncoding)
	}
	return nil
}

// Encode is the tagged deterministic request.
func (r *Request) Encode() ([]byte, error) { return types.Cbor.MarshalTaggedValue(RequestTag, r) }

// DecodeRequest strictly decodes and structurally checks a request.
func DecodeRequest(data []byte) (*Request, error) {
	if len(data) > MaxRequestBytes {
		return nil, fmt.Errorf("%w: %d bytes", ErrEncoding, len(data))
	}
	var r Request
	if err := decodeRequest(data, &r); err != nil {
		return nil, err
	}
	if r.Version != Version {
		return nil, fmt.Errorf("%w: version %d", ErrEncoding, r.Version)
	}
	if (r.SnapshotEnd == nil) != (r.SnapshotEntryID == nil) {
		return nil, fmt.Errorf("%w: snapshot end and id go together", ErrEncoding)
	}
	if r.SnapshotEntryID != nil && len(r.SnapshotEntryID) != entryIDLen {
		return nil, fmt.Errorf("%w: snapshot id of %d bytes", ErrEncoding, len(r.SnapshotEntryID))
	}
	return &r, nil
}
