package storage

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"go.etcd.io/bbolt"

	basetypes "github.com/unicitynetwork/bft-go-base/types"
)

// The durable observation queue (VT-07a, astra r11). The validator-registry source observer must see EVERY committed block's certified
// EVM block, in commit order, whatever the execution client or the process does meanwhile: a publication is recognised from the output
// state at the block that first shows it, and that block is pruned from the tree by the next commit. So the inputs of the observation are
// written in the SAME transaction that makes the committing block the new root (BoltDB.CommitBlock), oldest first, and the worker consumes
// them in order, acknowledging an entry only after its outcome (a recorded source, or an awaiting item) is durable. The result id and the
// output commitment are not known here (they come from the output read the worker makes); the in-memory commit notification is a wakeup only.

// ObservationID identifies a committed observation across root epoch changes, when old root rounds may be reused.
type ObservationID struct {
	Epoch, Round uint64
	BlockHash    [32]byte
}

// ObservationInput is what the observer needs of one committed block's certified EVM block.
type ObservationInput struct {
	RootEpoch, RootRound, ParentRound, RootUCTime uint64
	BlockHash, StateRoot                          [32]byte
	// ShardRound is the certified block's shard round (IR.RoundNumber): a label, never a block height.
	ShardRound uint64
}

func (o ObservationInput) ID() ObservationID {
	return ObservationID{Epoch: o.RootEpoch, Round: o.RootRound, BlockHash: o.BlockHash}
}

// ObservationCursor holds the last acknowledged observation and its open Published result (zero when none).
type ObservationCursor struct {
	Set  bool
	ID   ObservationID
	Prev [32]byte
}

// ObservationQueue is the durable queue a store may offer.
type ObservationQueue interface {
	// PendingObservations returns up to max unacknowledged entries, oldest first, and the cursor of the last acknowledged one.
	PendingObservations(max int) ([]ObservationInput, ObservationCursor, error)
	// AckObservation deletes the exact entry at the front of the queue and advances the cursor in one transaction.
	AckObservation(id ObservationID, prev [32]byte) error
}

var (
	keyObsPrefix                 = []byte("vr/obs/")
	keyObsCursor                 = []byte("vr/obs-cursor-v2")
	ErrNoAtomicObservationCommit = errors.New("the persistent store cannot commit the observation queue atomically")
)

func obsKey(id ObservationID) []byte {
	k := make([]byte, 0, len(keyObsPrefix)+16+len(id.BlockHash))
	k = append(k, keyObsPrefix...)
	k = binary.BigEndian.AppendUint64(k, id.Epoch)
	k = binary.BigEndian.AppendUint64(k, id.Round)
	return append(k, id.BlockHash[:]...)
}

func readObservationCursor(meta *bbolt.Bucket) (cur ObservationCursor, err error) {
	if raw := meta.Get(keyObsCursor); raw != nil {
		if err := basetypes.Cbor.Unmarshal(raw, &cur); err != nil {
			return cur, fmt.Errorf("reading the observation cursor: %w", err)
		}
	}
	return cur, nil
}

// appendObservationsTx retains every pending input until acknowledgement. The worker bounds its reads, and a slow
// execution client may grow the on-disk backlog without losing an unobserved publication boundary.
func appendObservationsTx(meta *bbolt.Bucket, obs []ObservationInput) error {
	if len(obs) == 0 {
		return nil
	}
	cur, err := readObservationCursor(meta)
	if err != nil {
		return err
	}
	for _, o := range obs {
		// Recovery can reinstall a head already observed. Keep the cursor monotonic within each epoch.
		if cur.Set && (o.RootEpoch < cur.ID.Epoch || (o.RootEpoch == cur.ID.Epoch && o.RootRound <= cur.ID.Round)) {
			continue
		}
		raw, err := basetypes.Cbor.Marshal(o)
		if err != nil {
			return fmt.Errorf("serializing an observation: %w", err)
		}
		if err := meta.Put(obsKey(o.ID()), raw); err != nil {
			return err
		}
	}
	return nil
}

// PendingObservations implements ObservationQueue.
func (db BoltDB) PendingObservations(max int) (out []ObservationInput, cur ObservationCursor, err error) {
	err = db.db.View(func(tx *bbolt.Tx) error {
		meta := tx.Bucket(bucketMetadata)
		if meta == nil {
			return errors.New("metadata bucket not found")
		}
		var err error
		if cur, err = readObservationCursor(meta); err != nil {
			return err
		}
		c := meta.Cursor()
		for k, v := c.Seek(keyObsPrefix); bytes.HasPrefix(k, keyObsPrefix) && len(out) < max; k, v = c.Next() {
			if len(k) == len(keyObsPrefix)+8 {
				return errors.New("the observation queue predates epoch-aware observations; regenerate this development generation")
			}
			var o ObservationInput
			if err := basetypes.Cbor.Unmarshal(v, &o); err != nil {
				return fmt.Errorf("reading an observation: %w", err)
			}
			if !bytes.Equal(k, obsKey(o.ID())) {
				return errors.New("observation queue key does not match its entry")
			}
			out = append(out, o)
		}
		return nil
	})
	return out, cur, err
}

// AckObservation implements ObservationQueue.
func (db BoltDB) AckObservation(id ObservationID, prev [32]byte) error {
	raw, err := basetypes.Cbor.Marshal(ObservationCursor{Set: true, ID: id, Prev: prev})
	if err != nil {
		return err
	}
	return db.db.Update(func(tx *bbolt.Tx) error {
		meta := tx.Bucket(bucketMetadata)
		if meta == nil {
			return errors.New("metadata bucket not found")
		}
		key := obsKey(id)
		first, _ := meta.Cursor().Seek(keyObsPrefix)
		if !bytes.Equal(first, key) {
			return errors.New("the acknowledged observation is no longer at the front of the queue")
		}
		if err := meta.Delete(key); err != nil {
			return err
		}
		return meta.Put(keyObsCursor, raw)
	})
}

var _ ObservationQueue = BoltDB{}

// SetObservedShard names the designated EVM shard whose certified blocks are queued at every commit (VR mode). Unset (the default) queues
// nothing, so a chain without the validator registry writes nothing extra.
func (x *BlockStore) SetObservedShard(key basetypes.PartitionShardID) { x.observed.Store(&key) }

// PendingObservations and AckObservation expose the durable queue of the store, when its persistent store keeps one.
func (x *BlockStore) PendingObservations(max int) ([]ObservationInput, ObservationCursor, error) {
	q, ok := x.storage.(ObservationQueue)
	if !ok {
		return nil, ObservationCursor{}, errors.New("the persistent store keeps no observation queue")
	}
	return q.PendingObservations(max)
}

func (x *BlockStore) AckObservation(id ObservationID, prev [32]byte) error {
	q, ok := x.storage.(ObservationQueue)
	if !ok {
		return errors.New("the persistent store keeps no observation queue")
	}
	return q.AckObservation(id, prev)
}

// observationsOf are the certified EVM observations of a commit path (newest block first), oldest first, of the observed shard; a block
// whose shard state carries no complete certified block contributes nothing (as the in-memory notification skipped it).
func observationsOf(path []*ExecutedBlock, key *basetypes.PartitionShardID) []ObservationInput {
	if key == nil {
		return nil
	}
	var out []ObservationInput
	for i := len(path) - 1; i >= 0; i-- {
		b := path[i]
		if b == nil || b.BlockData == nil {
			continue
		}
		si := b.ShardState.States[*key]
		if si == nil || si.IR == nil || len(si.IR.BlockHash) != 32 || len(si.IR.Hash) != 32 {
			continue
		}
		out = append(out, ObservationInput{RootEpoch: b.BlockData.Epoch, RootRound: b.GetRound(), ParentRound: b.BlockData.GetParentRound(), RootUCTime: b.BlockData.Timestamp,
			BlockHash: [32]byte(si.IR.BlockHash), StateRoot: [32]byte(si.IR.Hash), ShardRound: si.IR.RoundNumber})
	}
	return out
}
