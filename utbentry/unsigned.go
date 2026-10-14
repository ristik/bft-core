// Package utbentry is the dependency-light part of the signed trust-base entry support: the strict decoder of the unsigned (SigBytes) form that vote and
// certificate verification use, with the deployment's member limit. It imports only go-base, so consensus types can use it without the builder's weight-set
// dependencies.
package utbentry

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"
)

// ErrUnsigned is returned for bytes that are not the canonical unsigned (SigBytes) form of a version-2 entry.
var ErrUnsigned = errors.New("utb: not a canonical unsigned entry")

var unsignedDecMode = func() cbor.DecMode {
	m, err := cbor.DecOptions{
		DupMapKey:        cbor.DupMapKeyEnforcedAPF,
		IndefLength:      cbor.IndefLengthForbidden,
		MaxNestedLevels:  8,
		MaxArrayElements: types.MaxTrustBaseV2Members + 16,
		MaxMapPairs:      types.MaxTrustBaseV2Members + 16,
		TagsMd:           cbor.TagsAllowed,
	}.DecMode()
	if err != nil {
		panic(err)
	}
	return m
}()

// wire mirrors types.RootTrustBaseV2's array form, so the unsigned bytes (signature field null) can be read without go-base's decoder, which
// requires the signatures of a non-genesis entry.
type wire struct {
	_                struct{} `cbor:",toarray"`
	Version          types.Version
	NetworkID        types.NetworkID
	Epoch            uint64
	EpochStart       uint64
	RootNodes        []*types.NodeInfo
	QuorumThreshold  uint64
	StateHash        hex.Bytes
	ChangeRecordHash hex.Bytes
	PreviousEntryID  hex.Bytes
	Signatures       map[string]hex.Bytes
}

// Decode strictly decodes the SigBytes of a version-2 entry: exact tag (39000), version, arity and sizes, a null signature field, no
// trailing bytes, the deterministic encoding only, the deployment's member limit, and the entry's structure (types.RootTrustBaseV2 rules without the
// signatures). The returned entry has nil Signatures; its EntryID is SHA-256 of b.
func Decode(b []byte) (*types.RootTrustBaseV2, error) {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: "+format, append([]any{ErrUnsigned}, a...)...)
	}
	var raw cbor.RawTag
	if err := unsignedDecMode.Unmarshal(b, &raw); err != nil {
		return nil, bad("%v", err)
	}
	if raw.Number != types.UnicityTrustBaseTag {
		return nil, bad("tag %d", raw.Number)
	}
	var w wire
	if err := unsignedDecMode.Unmarshal(raw.Content, &w); err != nil {
		return nil, bad("%v", err)
	}
	if w.Version != types.TrustBaseV2Version {
		return nil, bad("version %d", w.Version)
	}
	if w.Signatures != nil {
		return nil, bad("the signature field is not null")
	}
	e := &types.RootTrustBaseV2{Version: w.Version, NetworkID: w.NetworkID, Epoch: w.Epoch, EpochStart: w.EpochStart, RootNodes: w.RootNodes,
		QuorumThreshold: w.QuorumThreshold, StateHash: w.StateHash, ChangeRecordHash: w.ChangeRecordHash, PreviousEntryID: w.PreviousEntryID}
	again, err := e.SigBytes()
	if err != nil {
		return nil, bad("%v", err)
	}
	if !bytes.Equal(again, b) {
		return nil, bad("not the deterministic encoding")
	}
	if len(e.RootNodes) > MaxMembers {
		return nil, bad("%d members", len(e.RootNodes))
	}
	if err := ValidateShape(e); err != nil {
		return nil, bad("%v", err)
	}
	return e, nil
}

// MaxMembers is the deployment's committee ceiling (the admitted 16-member profile); a test in package utb pins it to evmassign.MaxValidators.
const MaxMembers = 16

// ValidateShape is types.RootTrustBaseV2.Validate for an entry that may still lack its signatures: Validate requires a non-genesis entry to carry a
// non-empty signature map, so an unsigned one is checked as a copy with a placeholder. Signatures are verified by VerifySuccessor, never here.
func ValidateShape(e *types.RootTrustBaseV2) error {
	probe := *e
	if !probe.IsGenesis() && len(probe.Signatures) == 0 {
		probe.Signatures = map[string]hex.Bytes{"-": nil}
	}
	return probe.Validate()
}
