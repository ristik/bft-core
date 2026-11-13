package recordsfeed

import (
	"encoding/binary"
	"fmt"

	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/keyvaluedb"
)

// KVCutStore keeps verified cuts in a key-value database, one record per cut key. A stored cut is evidence, not authority: whoever reads it
// (this node serving a follower, the follower itself) verifies it against its own origin again.
type KVCutStore struct{ DB keyvaluedb.KeyValueDB }

func cutDBKey(k CutKey) []byte {
	b := make([]byte, 0, 4+24+32)
	b = append(b, "cut/"...)
	b = binary.BigEndian.AppendUint64(b, k.Network)
	b = binary.BigEndian.AppendUint64(b, k.Epoch)
	b = binary.BigEndian.AppendUint64(b, k.Round)
	return append(b, k.TreeRoot[:]...)
}

// PutCut implements CutStore; a cut already stored is kept (its key names one committed block).
func (s KVCutStore) PutCut(k CutKey, cut Cut) error {
	if found, err := s.DB.Read(cutDBKey(k), new([]byte)); err != nil || found {
		return err
	}
	raw, err := types.Cbor.Marshal(cut)
	if err != nil {
		return err
	}
	if len(raw) > MaxCutBytes {
		return fmt.Errorf("%w: cut of %d bytes", ErrWire, len(raw))
	}
	return s.DB.Write(cutDBKey(k), raw)
}

// GetCut implements CutStore.
func (s KVCutStore) GetCut(k CutKey) (Cut, bool, error) {
	var raw []byte
	found, err := s.DB.Read(cutDBKey(k), &raw)
	if err != nil || !found {
		return Cut{}, false, err
	}
	var cut Cut
	if err := types.Cbor.Unmarshal(raw, &cut); err != nil {
		return Cut{}, false, fmt.Errorf("%w: stored cut: %v", ErrWire, err)
	}
	return cut, true, nil
}
