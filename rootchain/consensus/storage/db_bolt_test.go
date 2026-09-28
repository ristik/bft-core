package storage

import (
	"bytes"
	"crypto"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.etcd.io/bbolt"

	"github.com/unicitynetwork/bft-go-base/types"

	test "github.com/unicitynetwork/bft-core/internal/testutils"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
)

func TestEpochAnchorSafetyInstallPreservesNewLocks(t *testing.T) {
	db, err := NewBoltStorage(filepath.Join(t.TempDir(), "anchor.db"), WithNoSync())
	require.NoError(t, err)
	defer db.Close()
	require.NoError(t, db.SetHighestQcRound(100, 101))
	a := &rctypes.EpochAnchor{GenesisID: bytes.Repeat([]byte{1}, 32), Epoch: 2, Slot: 12, StateRoot: bytes.Repeat([]byte{2}, 32)}
	require.NoError(t, db.InstallEpochAnchorSafety(a))
	require.EqualValues(t, 12, db.GetHighestQcRound())
	require.EqualValues(t, 12, db.GetHighestVotedRound())
	require.NoError(t, db.SetHighestQcRound(20, 21))
	require.NoError(t, db.InstallEpochAnchorSafety(a))
	require.EqualValues(t, 20, db.GetHighestQcRound())
	require.EqualValues(t, 21, db.GetHighestVotedRound())
	installed, err := db.ReadEpochAnchorSafety()
	require.NoError(t, err)
	require.Equal(t, a, installed)
	other := *a
	other.GenesisID = bytes.Repeat([]byte{3}, 32)
	require.ErrorIs(t, db.InstallEpochAnchorSafety(&other), rctypes.ErrEpochAnchor)
}

func TestHandoffArchiveSizeBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name  string
		check func(int) bool
		limit int
	}{
		{"body", validHandoffBodySize, 1 << 20},
		{"bundle", validHandoffBundleSize, 64 << 20},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.False(t, tc.check(0))
			require.True(t, tc.check(tc.limit-1))
			require.True(t, tc.check(tc.limit))
			require.False(t, tc.check(tc.limit+1))
		})
	}
}

func TestEpochAnchorSafetySequentialGuards(t *testing.T) {
	db, err := NewBoltStorage(filepath.Join(t.TempDir(), "sequential.db"), WithNoSync())
	require.NoError(t, err)
	defer db.Close()
	makeAnchor := func(epoch, slot uint64) *rctypes.EpochAnchor {
		return &rctypes.EpochAnchor{GenesisID: bytes.Repeat([]byte{byte(epoch)}, 32), Epoch: epoch, Slot: slot,
			StateRoot: bytes.Repeat([]byte{byte(epoch + 10)}, 32)}
	}
	require.NoError(t, db.InstallEpochAnchorSafety(makeAnchor(2, 12)))
	for _, tc := range []struct {
		name        string
		epoch, slot uint64
	}{
		{"old epoch", 1, 13}, {"same epoch changed", 2, 13}, {"skipped epoch", 4, 13},
		{"equal slot", 3, 12}, {"lower slot", 3, 11},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.ErrorIs(t, db.InstallEpochAnchorSafety(makeAnchor(tc.epoch, tc.slot)), rctypes.ErrEpochAnchor)
			installed, err := db.ReadEpochAnchorSafety()
			require.NoError(t, err)
			require.EqualValues(t, 2, installed.Epoch)
		})
	}
	require.NoError(t, db.InstallEpochAnchorSafety(makeAnchor(3, 13)))
}

func TestEpochAnchorRootAdvancesOneEpochAndPersistsNewLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "two-anchors.db")
	db, err := NewBoltStorage(path, WithNoSync())
	require.NoError(t, err)
	anchor := func(epoch, slot uint64) *rctypes.EpochAnchor {
		return &rctypes.EpochAnchor{GenesisID: bytes.Repeat([]byte{byte(epoch)}, 32), Epoch: epoch, Slot: slot, StateRoot: bytes.Repeat([]byte{byte(epoch + 10)}, 32)}
	}
	root := func(a *rctypes.EpochAnchor) *ExecutedBlock {
		return &ExecutedBlock{BlockData: &rctypes.BlockData{Version: 2, Epoch: a.Epoch, Round: a.Slot, Payload: &rctypes.Payload{Version: 2}, Anchor: a}}
	}
	a2, a3 := anchor(2, 12), anchor(3, 22)
	require.NoError(t, db.InstallEpochAnchorRoot(root(a2), a2))
	require.NoError(t, db.SetHighestQcRound(19, 20))
	bad := anchor(4, 32)
	require.ErrorIs(t, db.InstallEpochAnchorRoot(root(bad), bad), rctypes.ErrEpochAnchor)
	require.ErrorIs(t, db.InstallEpochAnchorRoot(root(anchor(3, 12)), anchor(3, 12)), rctypes.ErrEpochAnchor)
	require.NoError(t, db.InstallEpochAnchorRoot(root(a3), a3))
	require.NoError(t, db.InstallEpochAnchorRoot(root(a3), a3))
	require.ErrorIs(t, db.InstallEpochAnchorRoot(root(a2), a2), rctypes.ErrEpochAnchor)
	require.EqualValues(t, 22, db.GetHighestQcRound())
	require.EqualValues(t, 22, db.GetHighestVotedRound())
	require.NoError(t, db.Close())
	db, err = NewBoltStorage(path, WithNoSync())
	require.NoError(t, err)
	defer db.Close()
	installed, err := db.ReadEpochAnchorSafety()
	require.NoError(t, err)
	require.Equal(t, a3, installed)
	blocks, err := db.LoadBlocks()
	require.NoError(t, err)
	require.Len(t, blocks, 1)
	require.EqualValues(t, 3, blocks[0].BlockData.Epoch)
}

func TestHandoffBundleArchiveSurvivesRestartAndRefusesReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "handoff-archive.db")
	db, err := NewBoltStorage(path, WithNoSync())
	require.NoError(t, err)
	id := bytes.Repeat([]byte{7}, 32)
	require.NoError(t, db.StoreHandoffBody(id, []byte("body")))
	require.NoError(t, db.StoreHandoffBundle(2, []byte("bundle")))
	require.ErrorIs(t, db.StoreHandoffBody(id, []byte("other")), ErrHandoffRecord)
	require.ErrorIs(t, db.StoreHandoffBundle(2, []byte("other")), ErrHandoffRecord)
	require.NoError(t, db.Close())
	db, err = NewBoltStorage(path, WithNoSync())
	require.NoError(t, err)
	defer db.Close()
	body, err := db.HandoffBody(id)
	require.NoError(t, err)
	require.Equal(t, []byte("body"), body)
	bundle, err := db.HandoffBundle(2)
	require.NoError(t, err)
	require.Equal(t, []byte("bundle"), bundle)
}

func TestEpochAnchorRootInstallRollsBackAtEveryWriteAndRestarts(t *testing.T) {
	steps := []string{"root-put", "old-block-delete-0", "old-block-delete-1", "safety-anchor", "highest-voted", "highest-qc", "vote-delete", "timeout-delete"}
	for _, failAt := range steps {
		t.Run(failAt, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "anchor-crash.db")
			db, err := NewBoltStorage(path)
			require.NoError(t, err)
			oldRoot := &ExecutedBlock{BlockData: &rctypes.BlockData{Version: 2, Epoch: 1, Round: 4, Payload: &rctypes.Payload{Version: 2}}, CommitQc: &rctypes.QuorumCert{}}
			require.NoError(t, db.WriteBlock(oldRoot, true))
			require.NoError(t, db.WriteBlock(&ExecutedBlock{BlockData: &rctypes.BlockData{Version: 2, Epoch: 1, Round: 5, Payload: &rctypes.Payload{Version: 2}}}, false))
			require.NoError(t, db.SetHighestQcRound(20, 21))
			require.NoError(t, db.WriteVote(&abdrc.VoteMsg{Author: "old-validator"}))
			timeout := &rctypes.TimeoutCert{Timeout: &rctypes.Timeout{Epoch: 1, Round: 99, HighQc: &rctypes.QuorumCert{}}}
			require.NoError(t, db.WriteTC(timeout))
			anchor := &rctypes.EpochAnchor{GenesisID: bytes.Repeat([]byte{1}, 32), Epoch: 2, Slot: 6, StateRoot: bytes.Repeat([]byte{2}, 32)}
			root := &ExecutedBlock{BlockData: &rctypes.BlockData{Version: 2, Epoch: 2, Round: 6, Payload: &rctypes.Payload{Version: 2}, Anchor: anchor}}
			crash := errors.New("injected crash")
			err = db.installEpochAnchorRootWithFault(root, anchor, func(step string) error {
				if step == failAt {
					return crash
				}
				return nil
			})
			require.ErrorIs(t, err, crash)
			blocks, err := db.LoadBlocks()
			require.NoError(t, err)
			require.Len(t, blocks, 2)
			require.EqualValues(t, 5, blocks[0].GetRound())
			require.EqualValues(t, 4, blocks[1].GetRound())
			installed, err := db.ReadEpochAnchorSafety()
			require.NoError(t, err)
			require.Nil(t, installed)
			require.EqualValues(t, 20, db.GetHighestQcRound())
			require.EqualValues(t, 21, db.GetHighestVotedRound())
			vote, err := db.ReadLastVote()
			require.NoError(t, err)
			require.NotNil(t, vote)
			lastTC, err := db.ReadLastTC()
			require.NoError(t, err)
			require.NotNil(t, lastTC)
			require.NoError(t, db.Close())

			db, err = NewBoltStorage(path)
			require.NoError(t, err)
			defer db.Close()
			blocks, err = db.LoadBlocks()
			require.NoError(t, err)
			require.Len(t, blocks, 2)
			installed, err = db.ReadEpochAnchorSafety()
			require.NoError(t, err)
			require.Nil(t, installed)
			require.NoError(t, db.InstallEpochAnchorRoot(root, anchor))
			require.NoError(t, db.Close())

			db, err = NewBoltStorage(path)
			require.NoError(t, err)
			defer db.Close()
			blocks, err = db.LoadBlocks()
			require.NoError(t, err)
			require.Len(t, blocks, 1)
			require.True(t, isEpochAnchorRoot(blocks[0]))
			installed, err = db.ReadEpochAnchorSafety()
			require.NoError(t, err)
			require.Equal(t, anchor, installed)
			require.EqualValues(t, anchor.Slot, db.GetHighestQcRound())
			require.EqualValues(t, anchor.Slot, db.GetHighestVotedRound())
			vote, err = db.ReadLastVote()
			require.NoError(t, err)
			require.Nil(t, vote)
			lastTC, err = db.ReadLastTC()
			require.NoError(t, err)
			require.Nil(t, lastTC)
		})
	}
}

func TestAnchorRootDiscardsOldSuffixAboveFixedStart(t *testing.T) {
	db, err := NewBoltStorage(filepath.Join(t.TempDir(), "late-proof.db"), WithNoSync())
	require.NoError(t, err)
	defer db.Close()
	for _, round := range []uint64{4, 5, 7, 8} {
		require.NoError(t, db.WriteBlock(&ExecutedBlock{BlockData: &rctypes.BlockData{Round: round, Epoch: 1}}, false))
	}
	a := &rctypes.EpochAnchor{GenesisID: bytes.Repeat([]byte{1}, 32), Epoch: 2, Slot: 6, StateRoot: bytes.Repeat([]byte{2}, 32)}
	require.NoError(t, db.WriteBlock(&ExecutedBlock{BlockData: &rctypes.BlockData{Round: 6, Epoch: 2, Anchor: a}}, true))
	blocks, err := db.LoadBlocks()
	require.NoError(t, err)
	require.Len(t, blocks, 1)
	require.Equal(t, a, blocks[0].BlockData.Anchor)
}

func Test_BoltDB_Block(t *testing.T) {
	tempDir := t.TempDir()

	blockForRound := func(round uint64) *ExecutedBlock {
		return &ExecutedBlock{
			BlockData: &rctypes.BlockData{
				Version: 1,
				Author:  "test",
				Round:   round,
				Payload: &rctypes.Payload{},
				Qc: &rctypes.QuorumCert{
					VoteInfo: &rctypes.RoundInfo{RoundNumber: round - 1, ParentRoundNumber: round - 2},
					LedgerCommitInfo: &types.UnicitySeal{
						Version:              1,
						RootChainRoundNumber: round - 1,
						PreviousHash:         test.RandomBytes(32),
						Hash:                 test.RandomBytes(32),
					},
				},
			},
			HashAlgo:   crypto.SHA256,
			RootHash:   test.RandomBytes(32),
			Qc:         &rctypes.QuorumCert{},
			CommitQc:   nil,
			ShardState: ShardStates{},
		}
	}

	t.Run("invalid database", func(t *testing.T) {
		// no blocks bucket
		db, err := NewBoltStorage(filepath.Join(tempDir, "invalid.db"))
		require.NoError(t, err)
		t.Cleanup(func() { db.Close() })

		err = db.db.Update(func(tx *bbolt.Tx) error {
			return tx.DeleteBucket(bucketBlocks)
		})
		require.NoError(t, err)

		b := ExecutedBlock{BlockData: &rctypes.BlockData{Round: 4}}
		require.ErrorIs(t, db.WriteBlock(&b, false), errNoBlocksBucket)

		blocks, err := db.LoadBlocks()
		require.ErrorIs(t, err, errNoBlocksBucket)
		require.Empty(t, blocks)
	})

	t.Run("save - load", func(t *testing.T) {
		// verify that we get back the same data we stored
		db, err := NewBoltStorage(filepath.Join(tempDir, "save_load.db"))
		require.NoError(t, err)
		t.Cleanup(func() { db.Close() })

		pdr := newShardConf(t)
		b := genesisBlockWithShard(t, pdr)
		require.NoError(t, err)
		require.NoError(t, db.WriteBlock(b, false))

		blocks, err := db.LoadBlocks()
		require.NoError(t, err)
		if assert.Len(t, blocks, 1) {
			// set the fields which are not persisted to zero values
			key := types.PartitionShardID{PartitionID: pdr.PartitionID, ShardID: pdr.ShardID.Key()}
			b.ShardState.States[key].nodeIDs = nil
			b.ShardState.States[key].trustBase = nil
			require.Equal(t, b, blocks[0])
		}
	})

	t.Run("history management", func(t *testing.T) {
		// when block is committed (new root block) older blocks are deleted
		db, err := NewBoltStorage(filepath.Join(tempDir, "history.db"))
		require.NoError(t, err)
		t.Cleanup(func() { db.Close() })

		// initially db is empty
		blocks, err := db.LoadBlocks()
		require.NoError(t, err)
		require.Empty(t, blocks)

		b := blockForRound(4)
		require.NoError(t, db.WriteBlock(b, false))
		blocks, err = db.LoadBlocks()
		require.NoError(t, err)
		require.Len(t, blocks, 1)

		b = blockForRound(5)
		require.NoError(t, db.WriteBlock(b, false))
		blocks, err = db.LoadBlocks()
		require.NoError(t, err)
		require.Len(t, blocks, 2)

		// write new root block, older blocks will be deleted
		b = blockForRound(6)
		b.CommitQc = &rctypes.QuorumCert{}
		require.NoError(t, db.WriteBlock(b, true))
		blocks, err = db.LoadBlocks()
		require.NoError(t, err)
		if assert.Len(t, blocks, 1) {
			require.Equal(t, b.GetRound(), blocks[0].GetRound())
		}

		// add two non-root blocks
		b7 := blockForRound(7)
		require.NoError(t, db.WriteBlock(b7, false))
		b = blockForRound(8)
		require.NoError(t, db.WriteBlock(b, false))
		// check we do have expected blocks in DB
		blocks, err = db.LoadBlocks()
		require.NoError(t, err)
		if assert.Len(t, blocks, 3) {
			// "contract" is that blocks are loaded in the descending order of round number
			require.EqualValues(t, 8, blocks[0].GetRound())
			require.EqualValues(t, 7, blocks[1].GetRound())
			require.EqualValues(t, 6, blocks[2].GetRound())
		}

		// commit round 7, the round 6 must go, round 8 must stay
		b7.CommitQc = &rctypes.QuorumCert{}
		require.NoError(t, db.WriteBlock(b7, true))
		blocks, err = db.LoadBlocks()
		require.NoError(t, err)
		if assert.Len(t, blocks, 2) {
			require.EqualValues(t, 8, blocks[0].GetRound())
			require.EqualValues(t, 7, blocks[1].GetRound())
		}
		// and committing the same round again mustn't change the state in DB
		require.NoError(t, db.WriteBlock(b7, true))
		blocks, err = db.LoadBlocks()
		require.NoError(t, err)
		if assert.Len(t, blocks, 2) {
			require.EqualValues(t, 8, blocks[0].GetRound())
			require.EqualValues(t, 7, blocks[1].GetRound())
		}
	})
}

func Test_BoltDB_VoteMsg(t *testing.T) {
	dir := t.TempDir()

	t.Run("invalid database", func(t *testing.T) {
		db, err := NewBoltStorage(filepath.Join(dir, "invalid_db.db"))
		require.NoError(t, err)
		t.Cleanup(func() { db.Close() })
		err = db.db.Update(func(tx *bbolt.Tx) error { return tx.DeleteBucket(bucketVotes) })
		require.NoError(t, err)

		vote := &abdrc.VoteMsg{}
		require.ErrorIs(t, db.WriteVote(vote), errNoVoteBucket)

		msg, err := db.ReadLastVote()
		require.ErrorIs(t, err, errNoVoteBucket)
		require.Nil(t, msg)
	})

	t.Run("invalid data", func(t *testing.T) {
		db, err := NewBoltStorage(filepath.Join(dir, "invalid_data.db"))
		require.NoError(t, err)
		t.Cleanup(func() { db.Close() })

		// invalid input data
		require.EqualError(t, db.WriteVote(42), `unknown vote type int`)
		require.EqualError(t, db.WriteVote(abdrc.ProposalMsg{}), `unknown vote type abdrc.ProposalMsg`)

		// set the vote in DB to invalid data
		// not correct data structure
		err = db.db.Update(func(tx *bbolt.Tx) error {
			b := tx.Bucket(bucketVotes)
			return b.Put(keyVote, []byte("foobar"))
		})
		require.NoError(t, err)
		msg, err := db.ReadLastVote()
		require.EqualError(t, err, `deserializing vote info: unexpected EOF`)
		require.Empty(t, msg)

		// invalid type enum value
		encoded, err := types.Cbor.Marshal(VoteStore{VoteType: 10})
		require.NoError(t, err)
		err = db.db.Update(func(tx *bbolt.Tx) error {
			b := tx.Bucket(bucketVotes)
			return b.Put(keyVote, encoded)
		})
		require.NoError(t, err)
		msg, err = db.ReadLastVote()
		require.EqualError(t, err, `unsupported vote kind: 10`)
		require.Empty(t, msg)
	})

	t.Run("success", func(t *testing.T) {
		db, err := NewBoltStorage(filepath.Join(dir, "votes.db"))
		require.NoError(t, err)
		t.Cleanup(func() { db.Close() })

		// empty db
		msg, err := db.ReadLastVote()
		require.NoError(t, err)
		require.Nil(t, msg)

		// vote
		vote := abdrc.VoteMsg{
			VoteInfo: &rctypes.RoundInfo{
				Version:     1,
				RoundNumber: 9872,
				Epoch:       rctypes.GenesisRootEpoch,
				Timestamp:   types.NewTimestamp(),
			},
			Author:    "node id",
			Signature: test.RandomBytes(32),
		}
		require.NoError(t, db.WriteVote(vote))
		msg, err = db.ReadLastVote()
		require.NoError(t, err)
		require.Equal(t, &vote, msg)

		// timeout vote
		voteTO := &abdrc.TimeoutMsg{
			Timeout: &rctypes.Timeout{
				Epoch: rctypes.GenesisRootEpoch,
				Round: 10,
			},
			LastTC: &rctypes.TimeoutCert{
				Timeout:    &rctypes.Timeout{},
				Signatures: map[string]*rctypes.TimeoutVote{"foobar": {HqcRound: 8, Signature: []byte{5, 1, 0}}},
			},
			Author:    "test",
			Signature: test.RandomBytes(32),
		}
		require.NoError(t, db.WriteVote(voteTO))
		msg, err = db.ReadLastVote()
		require.NoError(t, err)
		require.Equal(t, voteTO, msg)
	})
}

func Test_BoltDB_TimeoutCert(t *testing.T) {
	dir := t.TempDir()

	t.Run("invalid database", func(t *testing.T) {
		db, err := NewBoltStorage(filepath.Join(dir, "invalid.db"))
		require.NoError(t, err)
		t.Cleanup(func() { db.Close() })
		err = db.db.Update(func(tx *bbolt.Tx) error { return tx.DeleteBucket(bucketCertificates) })
		require.NoError(t, err)

		tc := &rctypes.TimeoutCert{Timeout: rctypes.NewTimeout(7, rctypes.GenesisRootEpoch, &rctypes.QuorumCert{})}
		require.ErrorIs(t, db.WriteTC(tc), errNoCertificatesBucket)

		tc, err = db.ReadLastTC()
		require.ErrorIs(t, err, errNoCertificatesBucket)
		require.Nil(t, tc)
	})

	t.Run("success", func(t *testing.T) {
		db, err := NewBoltStorage(filepath.Join(dir, "timeout_cert.db"))
		require.NoError(t, err)
		t.Cleanup(func() { db.Close() })

		tc, err := db.ReadLastTC()
		require.NoError(t, err)
		require.Nil(t, tc)

		tc = &rctypes.TimeoutCert{Timeout: rctypes.NewTimeout(7, rctypes.GenesisRootEpoch, &rctypes.QuorumCert{})}
		require.NoError(t, db.WriteTC(tc))
		tc2, err := db.ReadLastTC()
		require.NoError(t, err)
		require.Equal(t, tc, tc2)

		// when there is a block for the TO round it should be deleted when storing TC
		b := ExecutedBlock{BlockData: &rctypes.BlockData{Round: 17}}
		require.NoError(t, db.WriteBlock(&b, false))
		b = ExecutedBlock{BlockData: &rctypes.BlockData{Round: 18}}
		require.NoError(t, db.WriteBlock(&b, false))
		blocks, err := db.LoadBlocks()
		require.NoError(t, err)
		if assert.Len(t, blocks, 2) {
			require.EqualValues(t, 18, blocks[0].GetRound())
			require.EqualValues(t, 17, blocks[1].GetRound())
		}
		tc.Timeout.Round = b.GetRound()
		require.NoError(t, db.WriteTC(tc))
		tc2, err = db.ReadLastTC()
		require.NoError(t, err)
		require.Equal(t, tc, tc2)
		blocks, err = db.LoadBlocks()
		require.NoError(t, err)
		if assert.Len(t, blocks, 1) {
			require.EqualValues(t, 17, blocks[0].GetRound())
		}
	})
}

func Test_BoltDB_SafetyModule_API(t *testing.T) {
	dbName := filepath.Join(t.TempDir(), "safety.db")
	db, err := NewBoltStorage(dbName)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	// empty DB must have been initialized to genesis round
	require.Equal(t, rctypes.GenesisRootRound, db.GetHighestQcRound())
	require.Equal(t, rctypes.GenesisRootRound, db.GetHighestVotedRound())

	// set new values, voted round
	require.NoError(t, db.SetHighestVotedRound(10))
	require.EqualValues(t, 10, db.GetHighestVotedRound())
	// shouldn't be able to reset into the past
	require.NoError(t, db.SetHighestVotedRound(9))
	require.EqualValues(t, 10, db.GetHighestVotedRound())

	// set new values, high QC round (and voted round)
	require.NoError(t, db.SetHighestQcRound(20, 21))
	require.EqualValues(t, 20, db.GetHighestQcRound())
	require.EqualValues(t, 21, db.GetHighestVotedRound())
	// shouldn't be able to reset into the past
	require.NoError(t, db.SetHighestQcRound(10, 10))
	require.EqualValues(t, 20, db.GetHighestQcRound())
	require.EqualValues(t, 21, db.GetHighestVotedRound())
	// moving one forward mustn't allow to set other into past
	require.NoError(t, db.SetHighestQcRound(10, 22))
	require.EqualValues(t, 20, db.GetHighestQcRound())
	require.EqualValues(t, 22, db.GetHighestVotedRound())
	require.NoError(t, db.SetHighestQcRound(21, 10))
	require.EqualValues(t, 21, db.GetHighestQcRound())
	require.EqualValues(t, 22, db.GetHighestVotedRound())

	// close and reopen, should get back to the last state saved
	require.NoError(t, db.Close())
	db, err = NewBoltStorage(dbName)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	require.EqualValues(t, 21, db.GetHighestQcRound())
	require.EqualValues(t, 22, db.GetHighestVotedRound())

	// invalid db - missing bucket
	err = db.db.Update(func(tx *bbolt.Tx) error { return tx.DeleteBucket(bucketSafety) })
	require.NoError(t, err)
	require.Equal(t, rctypes.GenesisRootRound, db.GetHighestQcRound())
	require.Equal(t, rctypes.GenesisRootRound, db.GetHighestVotedRound())
	require.ErrorIs(t, db.SetHighestQcRound(20, 21), errNoSafetyBucket)
}

func Test_BoltDB_ReadSafetySnapshot(t *testing.T) {
	db, err := NewBoltStorage(filepath.Join(t.TempDir(), "safety-snapshot.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	fileName := filepath.Join(t.TempDir(), "read-only.db")
	readOnlyDB, err := NewBoltStorage(fileName)
	require.NoError(t, err)
	t.Cleanup(func() { _ = readOnlyDB.Close() })
	before, err := os.ReadFile(fileName)
	require.NoError(t, err)
	snapshot, err := readOnlyDB.ReadSafetySnapshot()
	require.NoError(t, err)
	require.Equal(t, SafetySnapshot{HighestQCRound: rctypes.GenesisRootRound, HighestVotedRound: rctypes.GenesisRootRound}, snapshot)
	after, err := os.ReadFile(fileName)
	require.NoError(t, err)
	require.Equal(t, before, after, "successful reads must not modify the database")

	snapshot, err = db.ReadSafetySnapshot()
	require.NoError(t, err)
	require.Equal(t, SafetySnapshot{
		HighestQCRound:    rctypes.GenesisRootRound,
		HighestVotedRound: rctypes.GenesisRootRound,
	}, snapshot)

	require.NoError(t, db.SetHighestQcRound(20, 21))
	snapshot, err = db.ReadSafetySnapshot()
	require.NoError(t, err)
	require.Equal(t, SafetySnapshot{HighestQCRound: 20, HighestVotedRound: 21}, snapshot)

	dbName := filepath.Join(t.TempDir(), "reopen.db")
	require.NoError(t, db.Close())
	db, err = NewBoltStorage(dbName)
	require.NoError(t, err)
	require.NoError(t, db.SetHighestQcRound(30, 31))
	require.NoError(t, db.Close())
	db, err = NewBoltStorage(dbName)
	require.NoError(t, err)
	snapshot, err = db.ReadSafetySnapshot()
	require.NoError(t, err)
	require.Equal(t, SafetySnapshot{HighestQCRound: 30, HighestVotedRound: 31}, snapshot)
	require.NoError(t, db.Close())

	t.Run("uninitialized and closed handles return errors", func(t *testing.T) {
		var zero BoltDB
		got, err := zero.ReadSafetySnapshot()
		require.Error(t, err)
		require.Zero(t, got)

		closed, err := NewBoltStorage(filepath.Join(t.TempDir(), "closed.db"))
		require.NoError(t, err)
		require.NoError(t, closed.Close())
		got, err = closed.ReadSafetySnapshot()
		require.Error(t, err)
		require.Zero(t, got)
	})

	for _, testCase := range []struct {
		name   string
		mutate func(*bbolt.Bucket) error
		want   string
	}{
		{name: "missing bucket", mutate: func(*bbolt.Bucket) error { return nil }, want: "safety module bucket not found"},
		{name: "missing QC", mutate: func(b *bbolt.Bucket) error { return b.Delete(keyHighestQc) }, want: "highest QC"},
		{name: "missing voted", mutate: func(b *bbolt.Bucket) error { return b.Delete(keyHighestVoted) }, want: "highest voted"},
		{name: "malformed QC", mutate: func(b *bbolt.Bucket) error { return b.Put(keyHighestQc, []byte{1}) }, want: "highest QC"},
		{name: "malformed voted", mutate: func(b *bbolt.Bucket) error { return b.Put(keyHighestVoted, []byte{1}) }, want: "highest voted"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			dbName := filepath.Join(t.TempDir(), "invalid.db")
			db, err := NewBoltStorage(dbName)
			require.NoError(t, err)
			t.Cleanup(func() { _ = db.Close() })
			require.NoError(t, db.SetHighestQcRound(20, 21))
			var beforeQC, beforeVoted []byte
			require.NoError(t, db.db.Update(func(tx *bbolt.Tx) error {
				if testCase.name == "missing bucket" {
					return tx.DeleteBucket(bucketSafety)
				}
				b := tx.Bucket(bucketSafety)
				if err := testCase.mutate(b); err != nil {
					return err
				}
				beforeQC = append([]byte(nil), b.Get(keyHighestQc)...)
				beforeVoted = append([]byte(nil), b.Get(keyHighestVoted)...)
				return nil
			}))
			before, err := os.ReadFile(dbName)
			require.NoError(t, err)
			got, err := db.ReadSafetySnapshot()
			require.ErrorContains(t, err, testCase.want)
			require.Zero(t, got, "failed reads must not return a partial snapshot")
			if testCase.name != "missing bucket" {
				require.NoError(t, db.db.View(func(tx *bbolt.Tx) error {
					b := tx.Bucket(bucketSafety)
					require.True(t, bytes.Equal(beforeQC, b.Get(keyHighestQc)))
					require.True(t, bytes.Equal(beforeVoted, b.Get(keyHighestVoted)))
					return nil
				}))
			}
			after, err := os.ReadFile(dbName)
			require.NoError(t, err)
			require.Equal(t, before, after, "failed reads must not modify the database")
		})
	}
}

func Test_BoltDB_ReadSafetySnapshotIsCoherentDuringPairedWrites(t *testing.T) {
	db, err := NewBoltStorage(filepath.Join(t.TempDir(), "concurrent.db"), WithNoSync())
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	const writes = 200
	var wg sync.WaitGroup
	writerErrs := make(chan error, writes)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for round := uint64(1); round <= writes; round++ {
			if err := db.SetHighestQcRound(round, round+1); err != nil {
				writerErrs <- err
				return
			}
		}
	}()

	for i := 0; i < writes*4; i++ {
		snapshot, err := db.ReadSafetySnapshot()
		require.NoError(t, err)
		if snapshot.HighestQCRound == snapshot.HighestVotedRound {
			require.Equal(t, rctypes.GenesisRootRound, snapshot.HighestQCRound,
				"equal non-genesis rounds indicate a mixed read: %+v", snapshot)
		} else {
			require.Equal(t, snapshot.HighestQCRound+1, snapshot.HighestVotedRound,
				"read mixed values from separate writes: %+v", snapshot)
		}
	}
	wg.Wait()
	close(writerErrs)
	for err := range writerErrs {
		require.NoError(t, err)
	}
	snapshot, err := db.ReadSafetySnapshot()
	require.NoError(t, err)
	require.Equal(t, SafetySnapshot{HighestQCRound: writes, HighestVotedRound: writes + 1}, snapshot)
}

// TestNewBoltStorage_Sync pins the durability default: a store opened without options syncs every
// commit, and only WithNoSync — meant for throwaway test fixtures (#127) — turns that off.
func TestNewBoltStorage_Sync(t *testing.T) {
	durable, err := NewBoltStorage(filepath.Join(t.TempDir(), "durable.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = durable.Close() })
	require.False(t, durable.db.NoSync, "a store opened without options must sync every commit")

	throwaway, err := NewBoltStorage(filepath.Join(t.TempDir(), "throwaway.db"), WithNoSync())
	require.NoError(t, err)
	t.Cleanup(func() { _ = throwaway.Close() })
	require.True(t, throwaway.db.NoSync, "WithNoSync must disable syncing")
}
