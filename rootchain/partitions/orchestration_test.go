package partitions

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/internal/testutils/logger"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/testutils"
	"github.com/unicitynetwork/bft-go-base/types"
)

func TestHandoffProfileReservesControlPartition(t *testing.T) {
	o, err := NewOrchestration(5, filepath.Join(t.TempDir(), "orchestration.db"), logger.New(t))
	require.NoError(t, err)
	t.Cleanup(func() { _ = o.db.Close() })
	conf := &types.PartitionDescriptionRecord{PartitionID: rctypes.ControlPartition}
	require.False(t, errors.Is(o.AddShardConfig(conf), rctypes.ErrControlPartition))
	o.EnableHandoffProfile()
	require.ErrorIs(t, o.AddShardConfig(conf), rctypes.ErrControlPartition)
}

func TestNewOrchestration(t *testing.T) {
	t.Run("directory not exist", func(t *testing.T) {
		dbPath := filepath.Join(t.TempDir(), "notExist", "orchestration.db")
		o, err := NewOrchestration(5, dbPath, logger.New(t))
		require.ErrorIs(t, err, fs.ErrNotExist)
		require.Nil(t, o)
	})

	t.Run("ok", func(t *testing.T) {
		// create new orchestration, verify first VAR is created and stored
		dbPath := filepath.Join(t.TempDir(), "orchestration.db")
		o, err := NewOrchestration(5, dbPath, logger.New(t))
		require.NoError(t, err)
		require.NotNil(t, o)
		t.Cleanup(func() { _ = o.db.Close() })

		shardConf := createShardConf(t, 1, types.ShardID{}, 10)
		require.NoError(t, o.AddShardConfig(shardConf))

		shardConfA, err := o.ShardConfig(1, types.ShardID{}, 10)
		require.NoError(t, err)

		require.EqualValues(t, shardConf.NetworkID, shardConfA.NetworkID)
		require.EqualValues(t, shardConf.PartitionID, shardConfA.PartitionID)
		require.EqualValues(t, shardConf.ShardID, shardConfA.ShardID)
		require.EqualValues(t, shardConf.Epoch, shardConfA.Epoch)
		require.EqualValues(t, shardConf.EpochStart, shardConfA.EpochStart)
		validators := shardConfA.Validators
		require.Len(t, validators, 1)
		require.EqualValues(t, shardConf.Validators[0].NodeID, validators[0].NodeID)
		require.EqualValues(t, shardConf.Validators[0].SigKey, validators[0].SigKey)

		// if we now reopen the DB with different genesis file the original
		// data must be preserved and new seed ignored
		require.NoError(t, o.db.Close())
		o, err = NewOrchestration(5, dbPath, logger.New(t))
		require.NoError(t, err)
		require.NotNil(t, o)
		t.Cleanup(func() { _ = o.db.Close() })

		shardConfB, err := o.ShardConfig(1, types.ShardID{}, 10)
		require.NoError(t, err)
		require.Equal(t, shardConfA, shardConfB)
	})
}

func TestShardConfig(t *testing.T) {
	partitionA := types.PartitionID(1)
	partitionB := types.PartitionID(2)
	shardID := types.ShardID{}
	invalidShardID := types.ShardID{}
	err := invalidShardID.UnmarshalText([]byte("0x81"))
	require.NoError(t, err)

	shardConf1 := createShardConf(t, partitionA, shardID, 1)
	shardConf2 := createShardConf(t, partitionB, shardID, 1)

	dbPath := filepath.Join(t.TempDir(), "orchestration.db")
	o, err := NewOrchestration(5, dbPath, logger.New(t))
	require.NoError(t, err)
	require.NotNil(t, o)
	t.Cleanup(func() { _ = o.db.Close() })
	require.NoError(t, o.AddShardConfig(shardConf1))
	require.NoError(t, o.AddShardConfig(shardConf2))

	var testCases = []struct {
		partitionID types.PartitionID                 // partition id to query
		shardID     types.ShardID                     // shard id to query
		rootRound   uint64                            // root round to query
		errMsg      string                            // expected err message
		shardConf   *types.PartitionDescriptionRecord // expected shardConf
	}{
		{partitionID: 0, shardID: shardID, rootRound: 1, errMsg: "shard conf missing for shard 00000000_"},
		{partitionID: 3, shardID: shardID, rootRound: 1, errMsg: "shard conf missing for shard 00000003_"},

		{partitionID: 1, shardID: invalidShardID, rootRound: 1, errMsg: "shard conf missing for shard 00000001_1000000"},
		{partitionID: 1, shardID: shardID, rootRound: 0, errMsg: "shard conf missing for shard 00000001_"},
		{partitionID: 1, shardID: shardID, rootRound: 1, shardConf: shardConf1},
		{partitionID: 1, shardID: shardID, rootRound: 999, shardConf: shardConf1},

		{partitionID: 2, shardID: invalidShardID, rootRound: 1, errMsg: "shard conf missing for shard 00000002_1000000"},
		{partitionID: 2, shardID: shardID, rootRound: 0, errMsg: "shard conf missing for shard 00000002_"},
		{partitionID: 2, shardID: shardID, rootRound: 1, shardConf: shardConf2},
		{partitionID: 2, shardID: shardID, rootRound: 888, shardConf: shardConf2},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("query shard conf for partition %q shard %q epoch %q", tc.partitionID, tc.shardID, tc.rootRound), func(t *testing.T) {
			shardConf, err := o.ShardConfig(tc.partitionID, tc.shardID, tc.rootRound)
			if tc.errMsg != "" {
				require.ErrorContains(t, err, tc.errMsg)
				require.Nil(t, shardConf)
			} else {
				require.NoError(t, err)
				require.NotNil(t, shardConf)
				require.Equal(t, tc.shardConf, shardConf)
			}
		})
	}
}

func TestAddShardConfig(t *testing.T) {
	// test adding new config
	// networkID := types.NetworkID(5)
	partitionID := types.PartitionID(1)
	shardID := types.ShardID{}
	invalidShardID := types.ShardID{}
	err := invalidShardID.UnmarshalText([]byte("0x81"))
	require.NoError(t, err)

	dbPath := filepath.Join(t.TempDir(), "orchestration.db")
	o, err := NewOrchestration(5, dbPath, logger.New(t))
	require.NoError(t, err)
	require.NotNil(t, o)
	t.Cleanup(func() { _ = o.db.Close() })

	existingShardConf := createShardConf(t, partitionID, shardID, 100)
	require.NoError(t, o.AddShardConfig(existingShardConf))

	var testCases = []struct {
		shardConf *types.PartitionDescriptionRecord // shard conf to add
		errMsg    string                            // expected err message
	}{
		{
			shardConf: func() *types.PartitionDescriptionRecord {
				shardConf := createShardConf(t, partitionID, shardID, 100)
				shardConf.NetworkID = 6
				return shardConf
			}(),
			errMsg: "invalid networkID 6, expected 5",
		},
		{
			shardConf: func() *types.PartitionDescriptionRecord {
				shardConf := createShardConf(t, partitionID, shardID, 200)
				shardConf.Epoch = 2
				return shardConf
			}(),
			errMsg: "verify shard conf: shard conf does not extend previous shard conf: invalid epoch, provided 2 previous 0",
		},
		{
			shardConf: func() *types.PartitionDescriptionRecord {
				// first configuration of a shard should have epoch 0
				shardConf := createShardConf(t, 2, shardID, 200)
				shardConf.Epoch = 1
				return shardConf
			}(),
			errMsg: "verify shard conf: previous shard conf not found",
		},
		{
			shardConf: func() *types.PartitionDescriptionRecord {
				// updating an already added shard conf succeeds, should it not?
				shardConf := createShardConf(t, partitionID, shardID, 100)
				shardConf.T2Timeout = 10 * time.Second
				return shardConf
			}(),
			errMsg: "",
		},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("add shard config for partition %q shard %q epoch %q", tc.shardConf.PartitionID, tc.shardConf.ShardID, tc.shardConf.Epoch), func(t *testing.T) {
			err := o.AddShardConfig(tc.shardConf)
			if tc.errMsg != "" {
				require.ErrorContains(t, err, tc.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestAddShardConfig_TestAddingShardConfForPreviousEpoch(t *testing.T) {
	// create orchestration
	networkID := types.NetworkID(5)
	partitionID := types.PartitionID(1)
	shardID := types.ShardID{}
	shardConf := createShardConf(t, partitionID, shardID, 1)
	dbPath := filepath.Join(t.TempDir(), "orchestration.db")
	o, err := NewOrchestration(5, dbPath, logger.New(t))
	require.NoError(t, err)
	err = o.AddShardConfig(shardConf)
	require.NoError(t, err)
	require.NotNil(t, o)
	t.Cleanup(func() { _ = o.db.Close() })

	// add second shardConf
	shardConf2 := &types.PartitionDescriptionRecord{
		NetworkID:       networkID,
		PartitionID:     partitionID,
		PartitionTypeID: shardConf.PartitionTypeID,
		ShardID:         shardID,
		Epoch:           1,
		EpochStart:      100,
	}
	require.NoError(t, o.AddShardConfig(shardConf2))

	// try to add third shardConf with epoch number same as in the previous shardConf
	shardConf3 := &types.PartitionDescriptionRecord{
		NetworkID:       networkID,
		PartitionID:     partitionID,
		PartitionTypeID: shardConf.PartitionTypeID,
		ShardID:         shardID,
		Epoch:           1,
		EpochStart:      200,
	}
	require.ErrorContains(t, o.AddShardConfig(shardConf3), "invalid epoch, provided 1 previous 1")
}

func createShardConf(t *testing.T, partitionID types.PartitionID, shardID types.ShardID, epochStart uint64) *types.PartitionDescriptionRecord {
	validator := testutils.NewTestNode(t)
	return &types.PartitionDescriptionRecord{
		Version:         1,
		NetworkID:       5,
		PartitionID:     partitionID,
		PartitionTypeID: 99,
		ShardID:         shardID,
		UnitIDLen:       256,
		TypeIDLen:       32,
		T2Timeout:       2500 * time.Millisecond,
		Epoch:           0,
		EpochStart:      epochStart,
		Validators:      []*types.NodeInfo{validator.NodeInfo(t)},
	}
}

// TestNewOrchestration_Sync pins the durability default: the orchestration database syncs every
// commit unless WithNoSync — meant for throwaway test fixtures (#127) — is passed.
func TestNewOrchestration_Sync(t *testing.T) {
	durable, err := NewOrchestration(5, filepath.Join(t.TempDir(), "durable.db"), logger.New(t))
	require.NoError(t, err)
	t.Cleanup(func() { _ = durable.Close() })
	require.False(t, durable.db.NoSync, "the orchestration database must sync every commit by default")

	throwaway, err := NewOrchestration(5, filepath.Join(t.TempDir(), "throwaway.db"), logger.New(t), WithNoSync())
	require.NoError(t, err)
	t.Cleanup(func() { _ = throwaway.Close() })
	require.True(t, throwaway.db.NoSync, "WithNoSync must disable syncing")
}

// Under the handoff profile a local entry for the designated EVM shard that differs from the stored genesis one (a
// wrong-key file, say) is refused: the profile guards are the only thing standing between it and the history every
// derived assignment extends. Re-supplying the identical genesis entry stays idempotent.
func TestHandoffProfileRefusesAWrongKeyEVMGenesisEntry(t *testing.T) {
	o, err := NewOrchestration(5, filepath.Join(t.TempDir(), "orchestration.db"), logger.New(t))
	require.NoError(t, err)
	t.Cleanup(func() { _ = o.Close() })
	o.EnableHandoffProfile()
	genesis := createShardConf(t, 8, types.ShardID{}, 1)
	genesis.PartitionTypeID = evmassign.EVMPartitionTypeID
	require.NoError(t, o.AddShardConfig(genesis))
	require.NoError(t, o.AddShardConfig(genesis), "the identical genesis entry is idempotent")

	wrongKey := createShardConf(t, 8, types.ShardID{}, 1) // same activation key, different validator
	wrongKey.PartitionTypeID = evmassign.EVMPartitionTypeID
	require.ErrorIs(t, o.AddShardConfig(wrongKey), ErrDerivedConflict)
	stored, err := o.ShardConfig(8, types.ShardID{}, 1)
	require.NoError(t, err)
	require.Equal(t, genesis.Validators[0].SigKey, stored.Validators[0].SigKey, "the stored genesis entry is untouched")
}

// Under the handoff profile the genesis set is fixed once: an empty orchestration takes it in one transaction, afterwards only a
// byte-equal reload of an existing shard's genesis entry passes. Another epoch, other keys (at the same or another activation
// round), a new partition and a new shard are all refused, so no local file or call can add or edit a configuration.
func TestHandoffProfileFixesTheGenesisShardConfigurations(t *testing.T) {
	open := func(t *testing.T, profile bool) *Orchestration {
		o, err := NewOrchestration(5, filepath.Join(t.TempDir(), "orchestration.db"), logger.New(t))
		require.NoError(t, err)
		t.Cleanup(func() { _ = o.Close() })
		if profile {
			o.EnableHandoffProfile()
		}
		return o
	}
	evm := createShardConf(t, 8, types.ShardID{}, 1)
	evm.PartitionTypeID = evmassign.EVMPartitionTypeID
	aggregator := createShardConf(t, 9, types.ShardID{}, 1)
	seeded := func(t *testing.T) *Orchestration {
		o := open(t, true)
		require.NoError(t, o.InitGenesisShardConfigs(evm, aggregator))
		return o
	}

	t.Run("the genesis set is stored atomically and reloads identically", func(t *testing.T) {
		o := seeded(t)
		require.NoError(t, o.InitGenesisShardConfigs(evm, aggregator))
		require.NoError(t, o.InitGenesisShardConfigs(aggregator), "a subset reload is idempotent too")
		require.NoError(t, o.AddShardConfig(aggregator), "AddShardConfig is the same rule")
		stored, err := o.ShardConfigs(100)
		require.NoError(t, err)
		require.Len(t, stored, 2)
	})
	t.Run("an epoch>0 entry is refused", func(t *testing.T) {
		o := seeded(t)
		next := *aggregator
		next.Epoch, next.EpochStart = 1, 50
		require.ErrorIs(t, o.AddShardConfig(&next), ErrDerivedOnly)
	})
	t.Run("other keys at another activation round are refused (B2 probe)", func(t *testing.T) {
		o := seeded(t)
		later := createShardConf(t, 9, types.ShardID{}, 100) // epoch 0, other validator, epoch_start 100
		err := o.AddShardConfig(later)
		require.ErrorIs(t, err, ErrDerivedConflict)
		stored, err := o.ShardConfigs(100)
		require.NoError(t, err)
		require.Equal(t, aggregator.Validators[0].SigKey, stored[types.PartitionShardID{PartitionID: 9, ShardID: types.ShardID{}.Key()}].Validators[0].SigKey,
			"the new keys are not in effect at round 100")
	})
	t.Run("other keys at the same activation round are refused", func(t *testing.T) {
		o := seeded(t)
		require.ErrorIs(t, o.AddShardConfig(createShardConf(t, 9, types.ShardID{}, 1)), ErrDerivedConflict)
	})
	t.Run("a new partition or shard after genesis is refused (B2 probe)", func(t *testing.T) {
		o := seeded(t)
		require.ErrorIs(t, o.AddShardConfig(createShardConf(t, 11, types.ShardID{}, 1)), ErrDerivedOnly)
		require.ErrorIs(t, o.InitGenesisShardConfigs(evm, createShardConf(t, 12, types.ShardID{}, 1)), ErrDerivedOnly, "one bad entry refuses the whole batch")
		split, _ := (types.ShardID{}).Split()
		sibling := createShardConf(t, 9, split, 1)
		require.ErrorIs(t, o.AddShardConfig(sibling), ErrDerivedOnly, "a new shard of an existing partition")
		stored, err := o.ShardConfigs(100)
		require.NoError(t, err)
		require.Len(t, stored, 2, "nothing was written")
	})
	t.Run("a first single write is the genesis, a second partition is not", func(t *testing.T) {
		o := open(t, true)
		require.NoError(t, o.AddShardConfig(aggregator))
		require.ErrorIs(t, o.AddShardConfig(evm), ErrDerivedOnly)
	})
	t.Run("without the profile the legacy path is unchanged", func(t *testing.T) {
		o := open(t, false)
		require.NoError(t, o.AddShardConfig(aggregator))
		require.NoError(t, o.AddShardConfig(evm))
		next := *aggregator
		next.Epoch, next.EpochStart = 1, 50
		next.Validators = createShardConf(t, 9, types.ShardID{}, 50).Validators
		require.NoError(t, o.AddShardConfig(&next))
	})
}

// One handoff's derived configurations install atomically: a conflicting member leaves none of the batch behind.
func TestInstallDerivedShardConfigsIsAtomic(t *testing.T) {
	o, err := NewOrchestration(5, filepath.Join(t.TempDir(), "orchestration.db"), logger.New(t))
	require.NoError(t, err)
	t.Cleanup(func() { _ = o.Close() })
	o.EnableHandoffProfile()
	evm := createShardConf(t, 8, types.ShardID{}, 1)
	evm.PartitionTypeID = evmassign.EVMPartitionTypeID
	agg := createShardConf(t, 9, types.ShardID{}, 1)
	require.NoError(t, o.InitGenesisShardConfigs(evm, agg))
	provenance, err := evmassign.Provenance{RecordID: bytes.Repeat([]byte{1}, 32), CandidateDigest: bytes.Repeat([]byte{2}, 32), RootEpoch: 2}.Bytes()
	require.NoError(t, err)
	next := func(c *types.PartitionDescriptionRecord, start uint64) *types.PartitionDescriptionRecord {
		n := *c
		n.Epoch, n.EpochStart = 1, start
		n.Validators = createShardConf(t, c.PartitionID, types.ShardID{}, start).Validators
		return &n
	}
	evmNext, aggNext := next(evm, 7), next(agg, 7)
	aggBroken := *aggNext
	aggBroken.Epoch = 5 // a gap in the epoch chain: refused
	require.ErrorIs(t, o.InstallDerivedShardConfigs([]*types.PartitionDescriptionRecord{evmNext, &aggBroken}, provenance), ErrDerivedConflict)
	confs, err := o.ShardConfigs(7)
	require.NoError(t, err)
	require.EqualValues(t, 0, confs[types.PartitionShardID{PartitionID: 8, ShardID: types.ShardID{}.Key()}].Epoch, "the EVM entry of the failed batch was rolled back")
	require.NoError(t, o.InstallDerivedShardConfigs([]*types.PartitionDescriptionRecord{evmNext, aggNext}, provenance))
	confs, err = o.ShardConfigs(7)
	require.NoError(t, err)
	require.EqualValues(t, 1, confs[types.PartitionShardID{PartitionID: 8, ShardID: types.ShardID{}.Key()}].Epoch)
	require.EqualValues(t, 1, confs[types.PartitionShardID{PartitionID: 9, ShardID: types.ShardID{}.Key()}].Epoch)
	require.NoError(t, o.InstallDerivedShardConfigs([]*types.PartitionDescriptionRecord{evmNext, aggNext}, provenance), "idempotent")
}
