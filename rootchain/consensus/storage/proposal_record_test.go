package storage

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"go.etcd.io/bbolt"
)

func TestProposalRecordSurvivesEpochAnchorInstallation(t *testing.T) {
	db, err := NewBoltStorage(filepath.Join(t.TempDir(), "root.db"))
	require.NoError(t, err)
	defer db.Close()
	record, err := db.ReadProposalRecord()
	require.NoError(t, err)
	require.Zero(t, record)

	old := ProposalRecord{Epoch: 1, Round: 15, Hash: [32]byte{1}}
	require.NoError(t, db.ReserveProposal(old))
	anchor := &rctypes.EpochAnchor{GenesisID: bytes.Repeat([]byte{1}, 32), Epoch: 2, Slot: 12, StateRoot: bytes.Repeat([]byte{2}, 32)}
	require.NoError(t, db.InstallEpochAnchorSafety(anchor))
	record, err = db.ReadProposalRecord()
	require.NoError(t, err)
	require.Equal(t, old, record)
	require.ErrorIs(t, db.ReserveProposal(old), ErrProposalAlreadyReserved)

	next := ProposalRecord{Epoch: 2, Round: 13, Hash: [32]byte{2}}
	require.NoError(t, db.ReserveProposal(next))
	require.ErrorIs(t, db.ReserveProposal(ProposalRecord{Epoch: 1, Round: 16}), ErrProposalAlreadyReserved)
	require.ErrorIs(t, db.ReserveProposal(ProposalRecord{Epoch: 2, Round: 12}), ErrProposalAlreadyReserved)
	record, err = db.ReadProposalRecord()
	require.NoError(t, err)
	require.Equal(t, next, record)
}

func TestCorruptProposalRecordFailsClosed(t *testing.T) {
	db, err := NewBoltStorage(filepath.Join(t.TempDir(), "root.db"))
	require.NoError(t, err)
	defer db.Close()
	require.NoError(t, db.db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketSafety).Put(keyProposalRecord, []byte{1})
	}))
	_, err = db.ReadProposalRecord()
	require.ErrorIs(t, err, ErrCorruptProposalRecord)
	require.ErrorIs(t, db.ReserveProposal(ProposalRecord{Epoch: 2, Round: 15}), ErrCorruptProposalRecord)
}
