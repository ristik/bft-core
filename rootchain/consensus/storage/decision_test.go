package storage

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDecisionIsDurableIdempotentAndExclusive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rc.db")
	db, err := NewBoltStorage(path, WithNoSync())
	require.NoError(t, err)

	// a fresh database has no decisions bucket, as one created before it existed: no migration is needed
	got, err := db.Decision(DecisionVote, 1, 5)
	require.NoError(t, err)
	require.Nil(t, got)
	statement, message, err := db.SignedDecision(DecisionVote, 1, 5)
	require.NoError(t, err)
	require.Nil(t, statement)
	require.Nil(t, message)

	require.NoError(t, db.RecordSignedDecision(DecisionVote, 1, 5, []byte("a"), []byte("signed-a")))
	require.NoError(t, db.RecordSignedDecision(DecisionVote, 1, 5, []byte("a"), []byte("another-signature")), "the same statement is idempotent")
	require.ErrorIs(t, db.RecordSignedDecision(DecisionVote, 1, 5, []byte("b"), []byte("signed-b")), ErrDecisionConflict)
	require.ErrorIs(t, db.RecordSignedDecision(DecisionVote, 1, 6, nil, []byte("m")), ErrEmptyDecision, "an empty statement is no decision")
	require.ErrorIs(t, db.RecordSignedDecision(DecisionVote, 1, 6, []byte("a"), nil), ErrEmptyDecision, "a decision without its signed message is no decision")

	// kind, epoch and round each separate decisions
	require.NoError(t, db.RecordSignedDecision(DecisionTimeout, 1, 5, []byte("b"), []byte("m")))
	require.NoError(t, db.RecordSignedDecision(DecisionVote, 2, 5, []byte("b"), []byte("m")))
	require.NoError(t, db.RecordSignedDecision(DecisionVote, 1, 6, []byte("b"), []byte("m")))

	require.NoError(t, db.Close())
	db, err = NewBoltStorage(path, WithNoSync())
	require.NoError(t, err)
	defer db.Close()
	statement, message, err = db.SignedDecision(DecisionVote, 1, 5)
	require.NoError(t, err)
	require.Equal(t, []byte("a"), statement, "the refused statement did not overwrite the recorded one")
	require.Equal(t, []byte("signed-a"), message, "the message first recorded is the one kept")
	require.ErrorIs(t, db.RecordSignedDecision(DecisionVote, 1, 5, []byte("b"), []byte("signed-b")), ErrDecisionConflict)
}

func TestDecisionValueIsAtomicAndRefusesACorruptRecord(t *testing.T) {
	// a value whose length prefix runs past its end is corrupt, never a shorter statement
	_, _, err := splitDecisionValue([]byte{0, 0, 0, 9, 1, 2})
	require.ErrorIs(t, err, ErrCorruptDecision)
	_, _, err = splitDecisionValue([]byte{0, 0})
	require.ErrorIs(t, err, ErrCorruptDecision)
	statement, message, err := splitDecisionValue(decisionValue([]byte("st"), []byte("msg")))
	require.NoError(t, err)
	require.Equal(t, []byte("st"), statement)
	require.Equal(t, []byte("msg"), message)
}
