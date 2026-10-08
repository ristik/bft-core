package storage

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"errors"
	"fmt"

	"go.etcd.io/bbolt"

	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/handoff"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootrecords"
	basetypes "github.com/unicitynetwork/bft-go-base/types"
)

// CutKey names the committed block a control cut belongs to by what the shards hold of it: the network, the root epoch and round of the
// block, and the root of its unicity tree (the one a certificate of that block authenticates). Rounds overlap across epochs, and a round
// alone names nothing a shard can verify, so the epoch and the tree root are part of every request and every stored entry.
type CutKey struct {
	Network, Epoch, Round uint64
	TreeRoot              [32]byte
}

func (k CutKey) bytes() []byte {
	b := append([]byte(nil), keyCut...)
	b = binary.BigEndian.AppendUint64(b, k.Network)
	b = binary.BigEndian.AppendUint64(b, k.Epoch)
	b = binary.BigEndian.AppendUint64(b, k.Round)
	return append(b, k.TreeRoot[:]...)
}

// DurableCut is one retained cut: the control state of a committed root block, the path of its leaf in that block's unicity tree and
// the block's certificates (its quorum certificate and the commit certificate that committed it), so an imported or restored cut can be
// authenticated independently against the historical authority of its epoch.
type DurableCut struct {
	_        struct{} `cbor:",toarray"`
	Control  *evmroot.ControlState
	Path     *basetypes.UnicityTreeCertificate
	Qc       *rctypes.QuorumCert
	CommitQc *rctypes.QuorumCert
}

// CutEntry is a cut with its key.
type CutEntry struct {
	Key CutKey
	Cut DurableCut
}

var (
	keyCut = []byte("p85/cut/")

	// ErrCutConflict reports a cut that differs from the one already retained under the same key.
	ErrCutConflict = errors.New("P85 control cut: conflicts with the retained cut")
	// ErrNoCutStore reports a commit of a source-state-bearing block on a store that cannot retain its cut.
	ErrNoCutStore = errors.New("P85 control cut: the block store cannot retain cuts")
	// ErrCutCorrupt reports a retained or imported cut whose control leaf does not lead to the tree root of its key.
	ErrCutCorrupt = errors.New("P85 control cut: the control leaf does not lead to the tree root of its key")
)

// CutStore retains the control cuts of committed blocks durably. A cut is immutable once stored: the same cut again is a no-op, a
// different one is a conflict. The store is kept beside the record log, in metadata that block pruning and epoch-anchor installation
// do not touch.
type CutStore interface {
	PutCut(entry CutEntry) error
	GetCut(key CutKey) (DurableCut, error)
}

// BlockCommitter is a store that makes the commit of a block atomic with its records and its cut: either all three are retained or none.
type BlockCommitter interface {
	CommitBlock(block *ExecutedBlock, recs []rootrecords.Record, cut *CutEntry) error
}

// cutEntryOf is the cut of a committed block that carries a source state, nil for one that does not. The key's coordinates come from the
// committed block itself (its epoch and round) and from the tree its control leaf belongs to, never from the possibly inherited epoch of
// the control state.
func cutEntryOf(b *ExecutedBlock) (*CutEntry, error) {
	if b == nil || b.ShardState.Control == nil || len(b.ShardState.Control.Pos) == 0 {
		return nil, nil
	}
	tree, _, err := b.ShardState.UnicityTree(crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("building the unicity tree of block %d: %w", b.GetRound(), err)
	}
	path, err := tree.Certificate(evmroot.D4ControlPartition)
	if err != nil {
		return nil, fmt.Errorf("control leaf path of block %d: %w", b.GetRound(), err)
	}
	root, err := handoff.ControlRoot(b.ShardState.Control, path)
	if err != nil || len(root) != 32 {
		return nil, fmt.Errorf("control leaf of block %d does not lead to its tree root: %w", b.GetRound(), errors.Join(ErrCutCorrupt, err))
	}
	key := CutKey{Network: b.ShardState.Control.Network, Epoch: b.BlockData.Epoch, Round: b.GetRound()}
	copy(key.TreeRoot[:], root)
	return &CutEntry{Key: key, Cut: DurableCut{Control: b.ShardState.Control, Path: path, Qc: b.Qc, CommitQc: b.CommitQc}}, nil
}

// VerifyDurableCut checks that the cut's control leaf leads to the tree root of its key: the integrity of a stored cut, and the first
// check of an imported one (the certificates it carries are then checked against the epoch's historical authority).
func VerifyDurableCut(key CutKey, cut DurableCut) error {
	root, err := handoff.ControlRoot(cut.Control, cut.Path)
	if err != nil || !bytes.Equal(root, key.TreeRoot[:]) {
		return ErrCutCorrupt
	}
	if cut.Control.Network != key.Network {
		return ErrCutCorrupt
	}
	return nil
}

func sameCut(a, b DurableCut) (bool, error) {
	x, err := basetypes.Cbor.Marshal([]any{a.Control, a.Path})
	if err != nil {
		return false, err
	}
	y, err := basetypes.Cbor.Marshal([]any{b.Control, b.Path})
	if err != nil {
		return false, err
	}
	return bytes.Equal(x, y), nil
}

// putCutTx stores a cut inside an open transaction; a stored cut equal in control and path is idempotent (a replayed commit may carry
// another valid signature subset of the same certificate), any other is a conflict.
func putCutTx(meta *bbolt.Bucket, e CutEntry) error {
	if err := VerifyDurableCut(e.Key, e.Cut); err != nil {
		return err
	}
	enc, err := basetypes.Cbor.Marshal(e.Cut)
	if err != nil {
		return fmt.Errorf("serializing the cut of round %d: %w", e.Key.Round, err)
	}
	if old := meta.Get(e.Key.bytes()); old != nil {
		var prior DurableCut
		if err := basetypes.Cbor.Unmarshal(old, &prior); err != nil {
			return fmt.Errorf("reading the retained cut of round %d: %w", e.Key.Round, err)
		}
		same, err := sameCut(prior, e.Cut)
		if err != nil {
			return err
		}
		if !same {
			return fmt.Errorf("%w: round %d of epoch %d", ErrCutConflict, e.Key.Round, e.Key.Epoch)
		}
		return nil
	}
	return meta.Put(e.Key.bytes(), enc)
}

// PutCut retains a cut.
func (db BoltDB) PutCut(e CutEntry) error {
	return db.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketMetadata)
		if b == nil {
			return errors.New("metadata bucket not found")
		}
		return putCutTx(b, e)
	})
}

// GetCut returns a retained cut after checking its integrity.
func (db BoltDB) GetCut(key CutKey) (cut DurableCut, err error) {
	err = db.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketMetadata)
		if b == nil {
			return errors.New("metadata bucket not found")
		}
		raw := b.Get(key.bytes())
		if raw == nil {
			return ErrCutUnavailable
		}
		if err := basetypes.Cbor.Unmarshal(raw, &cut); err != nil {
			return fmt.Errorf("reading the retained cut of round %d: %w", key.Round, err)
		}
		return VerifyDurableCut(key, cut)
	})
	return cut, err
}

// CommitBlock persists a committed block together with the records it projected and its cut in one transaction. A crash leaves the prior
// state or the complete new one; a repeat after a crash is idempotent.
func (db BoltDB) CommitBlock(block *ExecutedBlock, recs []rootrecords.Record, cut *CutEntry) error {
	data, err := basetypes.Cbor.Marshal(block)
	if err != nil {
		return fmt.Errorf("serializing block: %w", err)
	}
	return db.db.Update(func(tx *bbolt.Tx) error {
		meta := tx.Bucket(bucketMetadata)
		if meta == nil {
			return errors.New("metadata bucket not found")
		}
		if err := appendRecordsTx(meta, recs); err != nil {
			return err
		}
		if cut != nil {
			if err := putCutTx(meta, *cut); err != nil {
				return err
			}
		}
		return writeBlockTx(tx, block, data, true)
	})
}

var (
	_ CutStore       = BoltDB{}
	_ BlockCommitter = BoltDB{}
)

// MaxCutPage bounds a page of exported cuts.
const MaxCutPage = 64

// CutPage returns up to max (at most MaxCutPage) retained cuts in key order, strictly after the given key (from the first when nil):
// the bounded export of the immutable cut history for backup, recovery and archive publication.
func (db BoltDB) CutPage(after *CutKey, max int) (out []CutEntry, err error) {
	max = min(max, MaxCutPage)
	err = db.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketMetadata)
		if b == nil {
			return errors.New("metadata bucket not found")
		}
		c := b.Cursor()
		k, v := c.Seek(keyCut)
		if after != nil {
			k, v = c.Seek(after.bytes())
			if k != nil && bytes.Equal(k, after.bytes()) {
				k, v = c.Next()
			}
		}
		for ; k != nil && bytes.HasPrefix(k, keyCut) && len(out) < max; k, v = c.Next() {
			key, err := parseCutKey(k)
			if err != nil {
				return err
			}
			var cut DurableCut
			if err := basetypes.Cbor.Unmarshal(v, &cut); err != nil {
				return fmt.Errorf("reading the retained cut of round %d: %w", key.Round, err)
			}
			out = append(out, CutEntry{Key: key, Cut: cut})
		}
		return nil
	})
	return out, err
}

func parseCutKey(k []byte) (CutKey, error) {
	if len(k) != len(keyCut)+24+32 {
		return CutKey{}, errors.New("malformed cut key")
	}
	k = k[len(keyCut):]
	key := CutKey{Network: binary.BigEndian.Uint64(k), Epoch: binary.BigEndian.Uint64(k[8:]), Round: binary.BigEndian.Uint64(k[16:])}
	copy(key.TreeRoot[:], k[24:])
	return key, nil
}

// RestoreCuts stores a page of imported cuts. Every cut is first checked to lead to the tree root of its key and, when an authority is
// given, to be certified by the original committee of its epoch (the certificates it carries against the historical trust base); a cut
// that fails either, or conflicts with a retained one, fails the whole page and nothing of it is kept.
func RestoreCuts(store CutStore, page []CutEntry, authority func(CutEntry) error) error {
	if len(page) > MaxCutPage {
		return fmt.Errorf("%w: a page of %d cuts exceeds %d", ErrCutCorrupt, len(page), MaxCutPage)
	}
	for _, e := range page {
		if err := VerifyDurableCut(e.Key, e.Cut); err != nil {
			return err
		}
		if authority != nil {
			if err := authority(e); err != nil {
				return fmt.Errorf("cut of round %d, epoch %d: %w", e.Key.Round, e.Key.Epoch, err)
			}
		}
	}
	if committer, ok := store.(interface{ putCuts([]CutEntry) error }); ok {
		return committer.putCuts(page)
	}
	for _, e := range page {
		if err := store.PutCut(e); err != nil {
			return err
		}
	}
	return nil
}

// putCuts stores a page in one transaction.
func (db BoltDB) putCuts(page []CutEntry) error {
	return db.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketMetadata)
		if b == nil {
			return errors.New("metadata bucket not found")
		}
		for _, e := range page {
			if err := putCutTx(b, e); err != nil {
				return err
			}
		}
		return nil
	})
}
