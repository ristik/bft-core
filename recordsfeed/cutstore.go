package recordsfeed

import (
	"encoding/binary"
	"fmt"

	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/keyvaluedb"
	"github.com/unicitynetwork/bft-core/rootrecords"
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

func recordDBKey(index uint64) []byte {
	return binary.BigEndian.AppendUint64([]byte("rec/"), index)
}

// AppendRecords implements CutStore.
func (s KVCutStore) AppendRecords(records []rootrecords.Record) error {
	for _, r := range records {
		raw, err := types.Cbor.Marshal(toWire(r))
		if err != nil {
			return err
		}
		if err := s.DB.Write(recordDBKey(r.Index), raw); err != nil {
			return err
		}
	}
	return nil
}

// LoadRecords implements CutStore: the stored records from index 0 up to the first missing index.
func (s KVCutStore) LoadRecords() ([]rootrecords.Record, error) {
	var out []rootrecords.Record
	for i := uint64(0); ; i++ {
		var raw []byte
		found, err := s.DB.Read(recordDBKey(i), &raw)
		if err != nil {
			return nil, err
		}
		if !found {
			return out, nil
		}
		var w wireRecord
		if err := types.Cbor.Unmarshal(raw, &w); err != nil {
			return nil, fmt.Errorf("%w: stored record %d: %v", ErrWire, i, err)
		}
		r, err := fromWire(w)
		if err != nil || r.Index != i {
			return nil, fmt.Errorf("%w: stored record %d", ErrWire, i)
		}
		out = append(out, r)
	}
}
