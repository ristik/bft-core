package partitions

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"time"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/logger"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/zkverifier"
	"github.com/unicitynetwork/bft-go-base/types"
	bolt "go.etcd.io/bbolt"
)

var rootBucketName = []byte("root")

// derivedBucketName records the provenance of configurations derived from
// committed root handoff history. It is a sibling of rootBucketName, because
// every child bucket of the latter is read as a partition.
var derivedBucketName = []byte("derived")

var (
	// ErrDerivedOnly refuses an external write of a designated EVM shard
	// configuration after genesis: only verified committed history may change it.
	ErrDerivedOnly = errors.New("orchestration: EVM shard configuration changes only through a committed root handoff")
	// ErrDerivedConflict reports an existing entry that differs from the one
	// derived from committed history. It is corruption and refuses startup.
	ErrDerivedConflict = errors.New("orchestration: conflicting derived shard configuration")
)

type (
	Orchestration struct {
		networkID      types.NetworkID
		db             *bolt.DB
		log            *slog.Logger
		reserveControl bool
	}
)

func (o *Orchestration) EnableHandoffProfile() { o.reserveControl = true }

/*
NewOrchestration creates new boltDB implementation of shard validator orchestration.
  - dbFile is filename (full path) to the Bolt DB file to use for storage,
    if the file does not exist it will be created;
*/
// StoreOption configures the database opened by NewOrchestration.
type StoreOption func(*bolt.DB)

// WithNoSync opens the orchestration database without syncing each commit to disk (bbolt's NoSync).
// For throwaway test stores only; see storage.WithNoSync in rootchain/consensus/storage for why it
// exists (#127). Production callers never pass it, and TestNewOrchestration_Sync pins that the default syncs.
func WithNoSync() StoreOption { return func(db *bolt.DB) { db.NoSync = true } }

func NewOrchestration(networkID types.NetworkID, dbFile string, log *slog.Logger, opts ...StoreOption) (*Orchestration, error) {
	db, err := bolt.Open(dbFile, 0600, &bolt.Options{Timeout: 3 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("opening bolt DB: %w", err)
	}
	for _, opt := range opts {
		opt(db)
	}

	// ensure root bucket exists
	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(rootBucketName)
		if err != nil {
			return fmt.Errorf("creating %q bucket: %w", rootBucketName, err)
		}
		if _, err = tx.CreateBucketIfNotExists(derivedBucketName); err != nil {
			return fmt.Errorf("creating %q bucket: %w", derivedBucketName, err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return &Orchestration{
		networkID: networkID,
		db:        db,
		log:       log,
	}, nil
}

func (o *Orchestration) NetworkID() types.NetworkID {
	return o.networkID
}

// ShardConfig returns ShardConf for the given root round.
func (o *Orchestration) ShardConfig(partitionID types.PartitionID, shardID types.ShardID, rootRound uint64) (*types.PartitionDescriptionRecord, error) {
	var shardConf *types.PartitionDescriptionRecord
	err := o.db.View(func(tx *bolt.Tx) error {
		var err error
		shardConf, err = getShardConf(tx, partitionID, shardID, rootRound)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to load shard conf for shard %s_%s: %w", partitionID, shardID.String(), err)
	}
	if shardConf == nil {
		return nil, fmt.Errorf("shard conf missing for shard %s_%s", partitionID, shardID.String())
	}
	if shardConf.NetworkID != o.networkID {
		return nil, fmt.Errorf("shard conf loaded from database has wrong networkID %d, expected %d", shardConf.NetworkID, o.networkID)
	}
	return shardConf, nil
}

/*
ShardConfigs returns shard confs active in the given root round.
*/
func (o *Orchestration) ShardConfigs(rootRound uint64) (map[types.PartitionShardID]*types.PartitionDescriptionRecord, error) {
	shardConfs := make(map[types.PartitionShardID]*types.PartitionDescriptionRecord)

	err := o.db.View(func(tx *bolt.Tx) error {
		rootBucket := tx.Bucket(rootBucketName)
		if rootBucket == nil {
			return fmt.Errorf("bucket %q does not exist", rootBucketName)
		}

		// check all partitions
		return rootBucket.ForEachBucket(func(partitionID []byte) error {
			partitionBucket := rootBucket.Bucket(partitionID)

			// check all shards
			return partitionBucket.ForEachBucket(func(shardID []byte) error {
				shardBucket := partitionBucket.Bucket(shardID)

				// check if there is an active shard conf for the given root round
				c := shardBucket.Cursor()
				for k, v := c.Last(); k != nil; k, v = c.Prev() {
					epochStartRound := keyToUint64(k)
					if epochStartRound > rootRound {
						continue
					}

					var shardConf *types.PartitionDescriptionRecord
					if err := json.Unmarshal(v, &shardConf); err != nil {
						return fmt.Errorf("failed to unmarshal shard conf: %w", err)
					}
					ps := types.PartitionShardID{
						PartitionID: shardConf.PartitionID,
						ShardID:     shardConf.ShardID.Key(),
					}
					shardConfs[ps] = shardConf

					// active shard conf found, look no further for this shard
					break
				}
				return nil
			})
		})
	})
	if err != nil {
		return nil, fmt.Errorf("failed to read shard confs: %w", err)
	}

	return shardConfs, nil
}

// AddShardConfig verifies and stores the given shard conf.
//
// Validation rules:
//   - The network ID must match
//   - The partition ID must match one of the existing partitions
//   - The shard ID must be 0x80 (CBOR encoding of the empty bitstring)
//   - The new epoch number must be one greater than the current epoch of the only shard in the specified partition
//   - The activation round number must be strictly greater than the current round of the only shard in the specified partition
//   - The node identifiers must match their authentication keys
func (o *Orchestration) AddShardConfig(shardConf *types.PartitionDescriptionRecord) error {
	if shardConf == nil {
		return fmt.Errorf("missing shard configuration")
	}
	if o.reserveControl && shardConf.PartitionID == rctypes.ControlPartition {
		return rctypes.ErrControlPartition
	}
	if shardConf.NetworkID != o.networkID {
		return fmt.Errorf("invalid networkID %d, expected %d", shardConf.NetworkID, o.networkID)
	}
	designatedEVM := o.reserveControl && shardConf.PartitionTypeID == evmassign.EVMPartitionTypeID
	if designatedEVM && shardConf.Epoch != 0 {
		return ErrDerivedOnly
	}
	err := o.db.Update(func(tx *bolt.Tx) error {
		if err := verifyShardConf(tx, shardConf); err != nil {
			return fmt.Errorf("verify shard conf: %w", err)
		}
		if designatedEVM {
			// Genesis initialization is idempotent; a different genesis entry
			// would silently rewrite the history every derived entry extends.
			if err := sameStoredShardConf(tx, shardConf); err != nil {
				return err
			}
		}
		if err := storeShardConf(tx, shardConf); err != nil {
			return fmt.Errorf("store shard conf: %w", err)
		}
		return nil
	})
	if err != nil {
		o.log.Error(fmt.Sprintf("Failed to add shard config for partition %d, epoch %d",
			shardConf.PartitionID, shardConf.Epoch), logger.Error(err))
		return err
	}
	o.log.Info(fmt.Sprintf("Added shard config for partition %d, epoch %d, epoch start %d",
		shardConf.PartitionID, shardConf.Epoch, shardConf.EpochStart), logger.Error(err))
	return err
}

func confHash(conf *types.PartitionDescriptionRecord) ([]byte, error) {
	return conf.Hash(crypto.SHA256)
}

// sameStoredShardConf fails when an entry already stored at the configuration's
// activation key differs from it.
func sameStoredShardConf(tx *bolt.Tx, conf *types.PartitionDescriptionRecord) error {
	bucket := getShardBucket(tx, conf.PartitionID, conf.ShardID)
	if bucket == nil {
		return nil
	}
	raw := bucket.Get(uint64ToKey(conf.EpochStart))
	if raw == nil {
		return nil
	}
	var existing *types.PartitionDescriptionRecord
	if err := json.Unmarshal(raw, &existing); err != nil {
		return fmt.Errorf("failed to unmarshal shard conf: %w", err)
	}
	a, err := confHash(existing)
	if err != nil {
		return err
	}
	b, err := confHash(conf)
	if err != nil {
		return err
	}
	if !bytes.Equal(a, b) {
		return ErrDerivedConflict
	}
	return nil
}

func derivedKey(conf *types.PartitionDescriptionRecord) []byte {
	key := append([]byte(nil), conf.PartitionID.Bytes()...)
	key = append(key, conf.ShardID.Bytes()...)
	return append(key, uint64ToKey(conf.Epoch)...)
}

// InstallDerivedShardConfig installs a configuration derived from verified,
// committed root handoff history at its activation round. It is idempotent: the
// identical entry with the identical provenance is a no-op, and any other entry
// at the same activation key, or a gap in the epoch chain, is corruption.
// Provenance (the committed record and candidate digests) is never an authority
// by itself; the caller derived the configuration from committed data.
func (o *Orchestration) InstallDerivedShardConfig(conf *types.PartitionDescriptionRecord, provenance []byte) error {
	if conf == nil || conf.Epoch == 0 || conf.EpochStart == 0 {
		return ErrDerivedConflict
	}
	if _, err := evmassign.DecodeProvenance(provenance); err != nil {
		return ErrDerivedConflict
	}
	if conf.NetworkID != o.networkID {
		return fmt.Errorf("invalid networkID %d, expected %d", conf.NetworkID, o.networkID)
	}
	if err := conf.IsValid(); err != nil {
		return err
	}
	return o.db.Update(func(tx *bolt.Tx) error {
		derived := tx.Bucket(derivedBucketName)
		if derived == nil {
			return fmt.Errorf("bucket %q does not exist", derivedBucketName)
		}
		key := derivedKey(conf)
		if bucket := getShardBucket(tx, conf.PartitionID, conf.ShardID); bucket != nil && bucket.Get(uint64ToKey(conf.EpochStart)) != nil {
			if err := sameStoredShardConf(tx, conf); err != nil {
				return err
			}
			if prior := derived.Get(key); prior != nil && !bytes.Equal(prior, provenance) {
				return ErrDerivedConflict
			}
			return derived.Put(key, provenance)
		}
		last, err := getShardConf(tx, conf.PartitionID, conf.ShardID, math.MaxUint64)
		if err != nil {
			return err
		}
		if last == nil || conf.Verify(last) != nil || derived.Get(key) != nil {
			return ErrDerivedConflict
		}
		if err := storeShardConf(tx, conf); err != nil {
			return err
		}
		return derived.Put(key, provenance)
	})
}

// ShardConfigByEpoch returns the stored configuration with the given shard
// epoch, or nil.
func (o *Orchestration) ShardConfigByEpoch(partitionID types.PartitionID, shardID types.ShardID, epoch uint64) (*types.PartitionDescriptionRecord, error) {
	var found *types.PartitionDescriptionRecord
	err := o.db.View(func(tx *bolt.Tx) error {
		bucket := getShardBucket(tx, partitionID, shardID)
		if bucket == nil {
			return nil
		}
		return bucket.ForEach(func(_, v []byte) error {
			var conf *types.PartitionDescriptionRecord
			if err := json.Unmarshal(v, &conf); err != nil {
				return fmt.Errorf("failed to unmarshal shard conf: %w", err)
			}
			if conf.Epoch == epoch {
				found = conf
			}
			return nil
		})
	})
	return found, err
}

// DerivedChain returns the configurations derived from committed handoffs for
// the shard with a shard epoch above afterEpoch, oldest first, with their
// provenance. Together with the acknowledged base it is the committed
// supersession chain.
func (o *Orchestration) DerivedChain(partitionID types.PartitionID, shardID types.ShardID, afterEpoch uint64) ([]evmassign.ChainStep, error) {
	var steps []evmassign.ChainStep
	err := o.db.View(func(tx *bolt.Tx) error {
		derived := tx.Bucket(derivedBucketName)
		if derived == nil {
			return nil
		}
		prefix := append(append([]byte(nil), partitionID.Bytes()...), shardID.Bytes()...)
		c := derived.Cursor()
		for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
			if len(k) != len(prefix)+8 {
				continue
			}
			epoch := binary.BigEndian.Uint64(k[len(prefix):])
			if epoch <= afterEpoch {
				continue
			}
			p, err := evmassign.DecodeProvenance(v)
			if err != nil {
				return ErrDerivedConflict
			}
			conf, err := o.confAtEpochTx(tx, partitionID, shardID, epoch)
			if err != nil {
				return err
			}
			if conf == nil {
				return ErrDerivedConflict
			}
			h, err := confHash(conf)
			if err != nil {
				return err
			}
			steps = append(steps, evmassign.ChainStep{ShardEpoch: epoch, ConfHash: h, RecordID: p.RecordID,
				CandidateDigest: p.CandidateDigest, RootEpoch: p.RootEpoch})
		}
		return nil
	})
	return steps, err
}

func (o *Orchestration) confAtEpochTx(tx *bolt.Tx, partitionID types.PartitionID, shardID types.ShardID, epoch uint64) (*types.PartitionDescriptionRecord, error) {
	bucket := getShardBucket(tx, partitionID, shardID)
	if bucket == nil {
		return nil, nil
	}
	var found *types.PartitionDescriptionRecord
	err := bucket.ForEach(func(_, v []byte) error {
		var conf *types.PartitionDescriptionRecord
		if err := json.Unmarshal(v, &conf); err != nil {
			return err
		}
		if conf.Epoch == epoch {
			found = conf
		}
		return nil
	})
	return found, err
}

// DerivedProvenance returns the provenance recorded for a derived entry, or nil.
func (o *Orchestration) DerivedProvenance(conf *types.PartitionDescriptionRecord) ([]byte, error) {
	var out []byte
	err := o.db.View(func(tx *bolt.Tx) error {
		if b := tx.Bucket(derivedBucketName); b != nil {
			out = bytes.Clone(b.Get(derivedKey(conf)))
		}
		return nil
	})
	return out, err
}

func (o *Orchestration) Close() error {
	return o.db.Close()
}

func getShardConf(tx *bolt.Tx, partitionID types.PartitionID, shardID types.ShardID, rootRound uint64) (*types.PartitionDescriptionRecord, error) {
	shardBucket := getShardBucket(tx, partitionID, shardID)
	if shardBucket == nil {
		return nil, nil
	}

	c := shardBucket.Cursor()
	for k, v := c.Last(); k != nil; k, v = c.Prev() {
		epochStartRound := keyToUint64(k)
		if epochStartRound > rootRound {
			continue
		}

		var shardConf *types.PartitionDescriptionRecord
		if err := json.Unmarshal(v, &shardConf); err != nil {
			return nil, fmt.Errorf("failed to unmarshal shard conf: %w", err)
		}
		return shardConf, nil
	}

	return nil, nil
}

func storeShardConf(tx *bolt.Tx, shardConf *types.PartitionDescriptionRecord) error {
	shardConfBytes, err := json.Marshal(shardConf)
	if err != nil {
		return fmt.Errorf("failed to marshal shard conf to json: %w", err)
	}

	roundToShardConfBucket, err := createShardBuckets(tx, shardConf.PartitionID, shardConf.ShardID)
	if err != nil {
		return err
	}

	if err = roundToShardConfBucket.Put(uint64ToKey(shardConf.EpochStart), shardConfBytes); err != nil {
		return fmt.Errorf("storing shard conf: %w", err)
	}
	return nil
}

func verifyShardConf(tx *bolt.Tx, shardConf *types.PartitionDescriptionRecord) error {
	if shardConf.Epoch == 0 {
		if err := shardConf.IsValid(); err != nil {
			return err
		}
		return verifyProofConfig(shardConf)
	}

	lastShardConf, err := getShardConf(tx, shardConf.PartitionID, shardConf.ShardID, math.MaxUint64)
	if err != nil {
		return fmt.Errorf("failed to get previous shard conf: %w", err)
	}
	if lastShardConf == nil {
		return fmt.Errorf("previous shard conf not found")
	}
	if err = shardConf.Verify(lastShardConf); err != nil {
		return fmt.Errorf("shard conf does not extend previous shard conf: %w", err)
	}
	return verifyProofConfig(shardConf)
}

// verifyProofConfig validates the ZK proof configuration in partition params.
// Returns error if:
// - proof_type is specified but not available (FFI not built)
// - SP1 proof_type is specified but vkey_path is missing
func verifyProofConfig(shardConf *types.PartitionDescriptionRecord) error {
	proofType := zkverifier.ParseProofTypeFromParams(shardConf.PartitionParams)

	// Empty/none proof type is always valid (m-of-n mode)
	if proofType == zkverifier.ProofTypeNone || proofType == "" {
		return nil
	}

	// Check if proof type is available in current build
	if !zkverifier.IsProofTypeAvailable(proofType) {
		return fmt.Errorf("proof type %q not available (build with -tags zkverifier_ffi to enable)", proofType)
	}

	// SP1 requires verification key path and chain_id
	if proofType == zkverifier.ProofTypeSP1 {
		vkeyPath := zkverifier.ParseVKeyPathFromParams(shardConf.PartitionParams)
		if vkeyPath == "" {
			return fmt.Errorf("vkey_path required for SP1 proof type")
		}
		if _, ok := zkverifier.ParseChainIDFromParams(shardConf.PartitionParams); !ok {
			return fmt.Errorf("chain_id required for SP1 proof type")
		}
	}

	// LightClient requires chain_id
	if proofType == zkverifier.ProofTypeLightClient {
		if _, ok := zkverifier.ParseChainIDFromParams(shardConf.PartitionParams); !ok {
			return fmt.Errorf("chain_id required for light_client proof type")
		}
	}

	return nil
}

// schema:
// root bucket (root bucket)
//
//	multiple partition buckets (partition id to partition bucket)
//	  multiple shard buckets (shard id to shard bucket)
func createShardBuckets(tx *bolt.Tx, partitionID types.PartitionID, shardID types.ShardID) (*bolt.Bucket, error) {
	rootBucket := tx.Bucket(rootBucketName)
	if rootBucket == nil {
		return nil, fmt.Errorf("bucket %q does not exist", rootBucketName)
	}
	partitionBucket, err := rootBucket.CreateBucketIfNotExists(partitionID.Bytes())
	if err != nil {
		return nil, fmt.Errorf("creating partition 0x%x bucket: %w", partitionID.Bytes(), err)
	}
	shardBucket, err := partitionBucket.CreateBucketIfNotExists(shardID.Bytes())
	if err != nil {
		return nil, fmt.Errorf("creating shard 0x%x bucket: %w", shardID.Bytes(), err)
	}
	return shardBucket, nil
}

func getShardBucket(tx *bolt.Tx, partitionID types.PartitionID, shardID types.ShardID) *bolt.Bucket {
	rootBucket := tx.Bucket(rootBucketName)
	if rootBucket == nil {
		return nil
	}
	partitionBucket := rootBucket.Bucket(partitionID.Bytes())
	if partitionBucket == nil {
		return nil
	}
	return partitionBucket.Bucket(shardID.Bytes())
}

func uint64ToKey(n uint64) []byte {
	key := make([]byte, 8)
	binary.BigEndian.PutUint64(key, n)
	return key
}

func keyToUint64(key []byte) uint64 {
	return binary.BigEndian.Uint64(key)
}
