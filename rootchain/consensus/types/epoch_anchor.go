package types

import (
	"bytes"
	"errors"
	"math"
)

// EpochAnchor is the certified-parent alternative installed after verifying
// the old handoff proof and the complete production checkpoint. Slot is a
// logical position only; it is not a block round or commit subject.
type EpochAnchor struct {
	_         struct{} `cbor:",toarray"`
	GenesisID []byte
	Epoch     uint64
	Slot      uint64
	StateRoot []byte
}

var ErrEpochAnchor = errors.New("invalid epoch anchor")

func (a *EpochAnchor) IsValid() error {
	if a == nil || len(a.GenesisID) != 32 || len(a.StateRoot) != 32 || a.Epoch < 2 || a.Slot == 0 || a.Slot == math.MaxUint64 ||
		bytes.Equal(a.GenesisID, make([]byte, 32)) {
		return ErrEpochAnchor
	}
	return nil
}
