package storage

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync/atomic"

	"go.etcd.io/bbolt"

	basetypes "github.com/unicitynetwork/bft-go-base/types"
)

// The durable observation queue (VT-07a, astra r11). The validator-registry source observer must see EVERY committed block's certified
// EVM block, in commit order, whatever the execution client or the process does meanwhile: a publication is recognised from the output
// state at the block that first shows it, and that block is pruned from the tree by the next commit. So the inputs of the observation are
// written in the SAME transaction that makes the committing block the new root (BoltDB.CommitBlock), oldest first, and the worker consumes
// them in order, acknowledging an entry only after its outcome (a recorded source, or an awaiting item) is durable. The result id and the
// output commitment are not known here (they come from the output read the worker makes); the in-memory commit notification is a wakeup only.

// ObservationInput is what the observer needs of one committed block's certified EVM block.
type ObservationInput struct {
	RootRound, ParentRound, RootUCTime uint64
	BlockHash, StateRoot               [32]byte
	// ShardRound is the certified block's shard round (IR.RoundNumber): a label, never a block height.
	ShardRound uint64
}

// ObservationCursor is the observer's continuity state after its last acknowledged entry: the round it last observed and the result that was
// the open Published output there (zero when none), so a restart resumes exactly where the acknowledged work ended.
type ObservationCursor struct {
	Set   bool
	Round uint64
	Prev  [32]byte
}

// ObservationQueue is the durable queue a store may offer.
type ObservationQueue interface {
	// PendingObservations are up to max unacknowledged entries, oldest first, and the cursor of the last acknowledged one.
	PendingObservations(max int) ([]ObservationInput, ObservationCursor, error)
	// AckObservation deletes every entry up to and including round and stores the cursor, in one transaction.
	AckObservation(round uint64, cursor ObservationCursor) error
}

// MaxObservationQueue bounds the unacknowledged entries: beyond it the OLDEST are dropped at commit (a worker that was away for this many
// commits has lost the boundary of anything older; the incumbents' sources are then fetched). The queue is otherwise bounded by consumption.
const MaxObservationQueue = 4096

var (
	keyObsPrefix = []byte("vr/obs/")
	keyObsCursor = []byte("vr/obscursor")
)

func obsKey(round uint64) []byte {
	k := make([]byte, len(keyObsPrefix)+8)
	copy(k, keyObsPrefix)
	binary.BigEndian.PutUint64(k[len(keyObsPrefix):], round)
	return k
}

// appendObservationsTx writes the entries (oldest first) and enforces the bound.
func appendObservationsTx(meta *bbolt.Bucket, obs []ObservationInput) error {
	if len(obs) == 0 {
		return nil
	}
	for _, o := range obs {
		raw, err := basetypes.Cbor.Marshal(o)
		if err != nil {
			return fmt.Errorf("serializing an observation: %w", err)
		}
		if err := meta.Put(obsKey(o.RootRound), raw); err != nil {
			return err
		}
	}
	n := 0
	c := meta.Cursor()
	for k, _ := c.Seek(keyObsPrefix); k != nil && len(k) == len(keyObsPrefix)+8 && string(k[:len(keyObsPrefix)]) == string(keyObsPrefix); k, _ = c.Next() {
		n++
	}
	for ; n > MaxObservationQueue; n-- {
		k, _ := c.Seek(keyObsPrefix)
		if k == nil {
			break
		}
		if err := c.Delete(); err != nil {
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
		if raw := meta.Get(keyObsCursor); raw != nil {
			if err := basetypes.Cbor.Unmarshal(raw, &cur); err != nil {
				return fmt.Errorf("reading the observation cursor: %w", err)
			}
		}
		c := meta.Cursor()
		for k, v := c.Seek(keyObsPrefix); k != nil && len(out) < max && len(k) == len(keyObsPrefix)+8 && string(k[:len(keyObsPrefix)]) == string(keyObsPrefix); k, v = c.Next() {
			var o ObservationInput
			if err := basetypes.Cbor.Unmarshal(v, &o); err != nil {
				return fmt.Errorf("reading an observation: %w", err)
			}
			out = append(out, o)
		}
		return nil
	})
	return out, cur, err
}

// AckObservation implements ObservationQueue.
func (db BoltDB) AckObservation(round uint64, cursor ObservationCursor) error {
	raw, err := basetypes.Cbor.Marshal(cursor)
	if err != nil {
		return err
	}
	return db.db.Update(func(tx *bbolt.Tx) error {
		meta := tx.Bucket(bucketMetadata)
		if meta == nil {
			return errors.New("metadata bucket not found")
		}
		c := meta.Cursor()
		for k, _ := c.Seek(keyObsPrefix); k != nil && len(k) == len(keyObsPrefix)+8 && string(k[:len(keyObsPrefix)]) == string(keyObsPrefix); k, _ = c.Next() {
			if binary.BigEndian.Uint64(k[len(keyObsPrefix):]) > round {
				break
			}
			if err := c.Delete(); err != nil {
				return err
			}
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

func (x *BlockStore) AckObservation(round uint64, cursor ObservationCursor) error {
	q, ok := x.storage.(ObservationQueue)
	if !ok {
		return errors.New("the persistent store keeps no observation queue")
	}
	return q.AckObservation(round, cursor)
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
		out = append(out, ObservationInput{RootRound: b.GetRound(), ParentRound: b.BlockData.GetParentRound(), RootUCTime: b.BlockData.Timestamp,
			BlockHash: [32]byte(si.IR.BlockHash), StateRoot: [32]byte(si.IR.Hash), ShardRound: si.IR.RoundNumber})
	}
	return out
}

var _ = atomic.Pointer[BlockTree]{}
