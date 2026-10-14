// Package gettrustbase is the peer protocol that serves finalized signed trust-base entries (types.RootTrustBaseV2) from the append-only entry store
// (utbstore), the client that catches a store up from it, and the one tagged response format that is also the release bundle of the complete history.
//
// A request names (network, fromEpoch, toEpoch|null) and an optional snapshot (end epoch and its EntryID) that freezes pagination; a response is one
// bounded contiguous ascending page of stored canonical entry bytes. A complete bundle is the same Response object with status OK, from = the genesis
// epoch, end = the release tip and no continuation (design §7). Servers add no authority: clients authenticate every unknown entry from their latest
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

	// RequestTag and ResponseTag are PROVISIONAL: the numbers proposed in unicity-ids-proposal.md, to be replaced by the registered ones (D11). They are
	// the only place the numbers appear.
	RequestTag  types.CborTag = 39014
	ResponseTag types.CborTag = 39015

	// Version is the request and response version.
	Version uint32 = 1

	// Transport caps (design §7). A client may lower the budgets, never raise the server's.
	DefaultMaxEntries   = 64
	DefaultMaxResponse  = 1 << 20
	MaxEntryBytes       = 64 << 10
	MaxRequestBytes     = 1 << 10
	envelopeBound       = 256 // network, status, epochs, end id, array heads: well above the real size
	maxNesting          = 16
	entryIDLen          = types.TrustBaseV2IDLen
	maxArrayElementsMin = 16
)

// Status is the response status.
type Status uint8

const (
	StatusOK Status = iota
	StatusInvalidRequest
	StatusWrongNetwork
	StatusNotYetAvailable
	StatusHistoryMismatch
	StatusLimitTooSmall
	StatusBusy
	StatusUnavailable
	statusEnd
)

func (s Status) String() string {
	names := [...]string{"OK", "InvalidRequest", "WrongNetwork", "NotYetAvailable", "HistoryMismatch", "LimitTooSmall", "Busy", "Unavailable"}
	if int(s) < len(names) {
		return names[s]
	}
	return fmt.Sprintf("Status(%d)", uint8(s))
}

var (
	ErrEncoding = errors.New("gettrustbase: invalid encoding")
	ErrResponse = errors.New("gettrustbase: invalid response")
)

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

// Response is [version=1, network, status, fromEpoch, effectiveEnd, endEntryID|null, entries[], nextEpoch|null]. Entries are the stored canonical
// tagged entries, embedded verbatim.
type Response struct {
	_            struct{} `cbor:",toarray"`
	Version      uint32
	Network      types.NetworkID
	Status       Status
	FromEpoch    uint64
	EffectiveEnd uint64
	EndEntryID   []byte
	Entries      []cbor.RawMessage
	NextEpoch    *uint64
}

func decMode(maxArray int) cbor.DecMode {
	if maxArray < maxArrayElementsMin {
		maxArray = maxArrayElementsMin
	}
	m, err := cbor.DecOptions{
		DupMapKey:        cbor.DupMapKeyEnforcedAPF,
		IndefLength:      cbor.IndefLengthForbidden,
		MaxNestedLevels:  maxNesting,
		MaxArrayElements: maxArray,
		MaxMapPairs:      types.MaxTrustBaseV2Members + 16,
		TagsMd:           cbor.TagsAllowed,
	}.DecMode()
	if err != nil {
		panic(err)
	}
	return m
}

// decodeTagged strictly decodes data as tag(content) into out: exact tag, bounded arrays, no trailing bytes and the deterministic encoding only.
func decodeTagged(data []byte, tag types.CborTag, maxArray int, out any) error {
	dm := decMode(maxArray)
	var raw cbor.RawTag
	if err := dm.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("%w: %v", ErrEncoding, err)
	}
	if raw.Number != tag {
		return fmt.Errorf("%w: tag %d, expected %d", ErrEncoding, raw.Number, tag)
	}
	if err := dm.Unmarshal(raw.Content, out); err != nil {
		return fmt.Errorf("%w: %v", ErrEncoding, err)
	}
	again, err := types.Cbor.MarshalTaggedValue(tag, out)
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
	if err := decodeTagged(data, RequestTag, maxArrayElementsMin, &r); err != nil {
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

// Encode is the tagged deterministic response; the entries are the caller's exact bytes.
func (r *Response) Encode() ([]byte, error) {
	cp := *r
	if cp.Entries == nil {
		cp.Entries = []cbor.RawMessage{}
	}
	return types.Cbor.MarshalTaggedValue(ResponseTag, &cp)
}

// Limits bound a response decode. MaxBytes is checked against the input before anything is allocated.
type Limits struct {
	MaxBytes   int
	MaxEntries int
}

// PageLimits are the peer-page caps.
var PageLimits = Limits{MaxBytes: DefaultMaxResponse, MaxEntries: DefaultMaxEntries}

// DecodeResponse strictly decodes a response and checks its internal consistency: status and cursor rules, and for an OK page a contiguous
// ascending run of structurally valid entries of the response's network, linked by predecessor EntryID, ending at effectiveEnd when no cursor remains.
// It does not verify signatures; the store does that when the entries are appended.
func DecodeResponse(data []byte, lim Limits) (*Response, []*types.RootTrustBaseV2, error) {
	if lim.MaxBytes <= 0 || len(data) > lim.MaxBytes {
		return nil, nil, fmt.Errorf("%w: %d bytes exceed %d", ErrEncoding, len(data), lim.MaxBytes)
	}
	var r Response
	if err := decodeTagged(data, ResponseTag, lim.MaxEntries, &r); err != nil {
		return nil, nil, err
	}
	if r.Version != Version {
		return nil, nil, fmt.Errorf("%w: version %d", ErrEncoding, r.Version)
	}
	if r.Status >= statusEnd {
		return nil, nil, fmt.Errorf("%w: status %d", ErrEncoding, r.Status)
	}
	if r.Entries == nil {
		return nil, nil, fmt.Errorf("%w: entries must be an array", ErrEncoding)
	}
	if len(r.Entries) > lim.MaxEntries {
		return nil, nil, fmt.Errorf("%w: %d entries exceed %d", ErrResponse, len(r.Entries), lim.MaxEntries)
	}
	if r.EndEntryID != nil && len(r.EndEntryID) != entryIDLen {
		return nil, nil, fmt.Errorf("%w: end id of %d bytes", ErrEncoding, len(r.EndEntryID))
	}
	if r.Status != StatusOK {
		if len(r.Entries) != 0 || r.NextEpoch != nil {
			return nil, nil, fmt.Errorf("%w: %s carries entries or a cursor", ErrResponse, r.Status)
		}
		return &r, nil, nil
	}
	decoded, err := checkPage(&r)
	if err != nil {
		return nil, nil, err
	}
	return &r, decoded, nil
}

func checkPage(r *Response) ([]*types.RootTrustBaseV2, error) {
	if len(r.Entries) == 0 {
		return nil, fmt.Errorf("%w: an OK response without entries", ErrResponse)
	}
	if r.EndEntryID == nil {
		return nil, fmt.Errorf("%w: no end entry id", ErrResponse)
	}
	out := make([]*types.RootTrustBaseV2, len(r.Entries))
	var prevID [entryIDLen]byte
	for i, raw := range r.Entries {
		if len(raw) > MaxEntryBytes {
			return nil, fmt.Errorf("%w: entry of %d bytes", ErrResponse, len(raw))
		}
		e, err := types.DecodeRootTrustBaseV2(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: entry %d: %v", ErrResponse, i, err)
		}
		if e.NetworkID != r.Network {
			return nil, fmt.Errorf("%w: entry %d of network %d in a response for %d", ErrResponse, i, e.NetworkID, r.Network)
		}
		if i == 0 && e.Epoch != r.FromEpoch {
			return nil, fmt.Errorf("%w: first entry is epoch %d, page starts at %d", ErrResponse, e.Epoch, r.FromEpoch)
		}
		if i > 0 {
			if out[i-1].Epoch == ^uint64(0) || e.Epoch != out[i-1].Epoch+1 {
				return nil, fmt.Errorf("%w: epoch %d does not follow %d", ErrResponse, e.Epoch, out[i-1].Epoch)
			}
			if !bytes.Equal(e.PreviousEntryID, prevID[:]) {
				return nil, fmt.Errorf("%w: epoch %d does not link to its predecessor", ErrResponse, e.Epoch)
			}
		}
		id, err := e.EntryID()
		if err != nil {
			return nil, err
		}
		prevID, out[i] = id, e
	}
	last := out[len(out)-1].Epoch
	switch {
	case r.NextEpoch == nil && last != r.EffectiveEnd:
		return nil, fmt.Errorf("%w: page ends at %d without a cursor before the effective end %d", ErrResponse, last, r.EffectiveEnd)
	case r.NextEpoch != nil && (*r.NextEpoch != last+1 || *r.NextEpoch > r.EffectiveEnd):
		return nil, fmt.Errorf("%w: cursor %d after epoch %d (end %d)", ErrResponse, *r.NextEpoch, last, r.EffectiveEnd)
	}
	if last == r.EffectiveEnd && !bytes.Equal(r.EndEntryID, prevID[:]) {
		return nil, fmt.Errorf("%w: end entry id differs from the last entry", ErrResponse)
	}
	return out, nil
}
