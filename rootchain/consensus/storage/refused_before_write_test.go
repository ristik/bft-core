package storage

import (
	"crypto"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
)

// writeCountingStore counts the blocks written through it.
type writeCountingStore struct {
	PersistentStore
	writes int
}

func (s *writeCountingStore) WriteBlock(b *ExecutedBlock, root bool) error {
	s.writes++
	return s.PersistentStore.WriteBlock(b, root)
}

// A recovery state refused while the head is built is refused before the store is written: the error says so, its message and chain are the
// ones NewRootBlock gave, and nothing was written.
func TestNewFromStateRefusalBuildingTheHeadWritesNothing(t *testing.T) {
	db, err := NewBoltStorage(t.TempDir() + "/refused.db")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	store := &writeCountingStore{PersistentStore: db}

	_, err = NewFromState(crypto.SHA256, &abdrc.CommittedBlock{}, store, nil, nil)
	require.ErrorIs(t, err, ErrRefusedBeforeWrite)
	require.ErrorContains(t, err, "failed to create new root node: missing committed root certificate", "the message is unchanged")
	require.Zero(t, store.writes)

	_, err = NewFromState(crypto.SHA256, &abdrc.CommittedBlock{}, nil, nil, nil)
	require.ErrorIs(t, err, ErrRefusedBeforeWrite)
}
