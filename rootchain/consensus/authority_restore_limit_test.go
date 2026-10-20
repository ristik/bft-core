package consensus

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
)

// H6 (#23), authority loss on a ROOT validator. Its non-equivocation memory is its own safety store (the recorded decisions and the
// highest voted round, durable before a vote is released), and its signing key lives on the same host. Nothing in that store says
// whether it is the live copy: an older backup, or an empty store under the same key, is internally perfect. These are negative
// controls that pin the documented limit (docs/operations/h6/authority-loss.md): the live store refuses a second statement, a
// restored or wiped one does not. A restored root host must therefore never sign with its old key; its replacement is a certified
// key rotation (the retired key is refused), and a quorum of such hosts is outside the root BFT fault bound (f6f section 1).
func TestARestoredOrWipedRootSafetyStoreWithTheSameKeySignsASecondStatement(t *testing.T) {
	for _, c := range []struct {
		name    string
		restore func(t *testing.T, path string, backup []byte)
	}{
		{"an older backup of the safety store", func(t *testing.T, path string, backup []byte) {
			require.NoError(t, os.WriteFile(path, backup, 0o600))
		}},
		{"an empty store (the file deleted)", func(t *testing.T, path string, _ []byte) {
			require.NoError(t, os.Remove(path))
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newDecisionRig(t)
			r.open(r.signer, r.scheme2())
			r.closeDB()
			backup, err := os.ReadFile(r.path) // taken before the vote, as a routine backup would be
			require.NoError(t, err)

			m, _ := r.open(r.signer, r.scheme2())
			first, err := m.MakeVote(r.committingBlock(5), hash32(1), nil, nil)
			require.NoError(t, err)
			r.closeDB()

			// the live store, after any number of restarts, refuses another statement for the round
			live, _ := r.open(r.signer, r.scheme2())
			_, err = live.MakeVote(r.committingBlock(5), hash32(2), nil, nil)
			require.ErrorIs(t, err, storage.ErrDecisionConflict)
			r.closeDB()

			c.restore(t, r.path, backup)
			restored, _ := r.open(r.signer, r.scheme2())
			second, err := restored.MakeVote(r.committingBlock(5), hash32(2), nil, nil)
			require.NoError(t, err, "the limit: the restored store does not know the vote it already released")
			r.verifyVote(second)
			r.verifyVote(first)
			require.Equal(t, first.VoteInfo.RoundNumber, second.VoteInfo.RoundNumber)
			require.NotEqual(t, first.VoteInfo.CurrentRootHash, second.VoteInfo.CurrentRootHash,
				"two valid, conflicting votes for one round under one key")
		})
	}
}
