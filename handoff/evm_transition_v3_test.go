package handoff_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/handoff"
)

func word(b byte) [32]byte { return [32]byte(bytes.Repeat([]byte{b}, 32)) }

func ack(commit byte, parent byte) handoff.AckRecord {
	return handoff.AckRecord{FrozenID: word(0x41), CommitID: word(commit), FrozenParent: word(parent),
		SuccessorParent: word(parent), SuccessorTR: word(0x43), EVMRound: 7}
}

func base() handoff.EVMTransition {
	return handoff.EVMTransition{OldRootEpoch: 1, NewRootEpoch: 2, OldShardEpoch: 0, NewShardEpoch: 0,
		OldActiveConfHash: word(0x11), NewActiveConfHash: word(0x11), NextBodyID: word(0x44), GenesisID: word(0x45), Ack: ack(0x42, 0x33)}
}

func assignment() handoff.EVMTransition {
	t := base()
	t.OldShardEpoch, t.NewShardEpoch, t.NewActiveConfHash = 3, 4, word(0x22)
	return t
}

func supersession(span uint64) handoff.EVMTransition {
	t := base()
	t.NewRootEpoch = t.OldRootEpoch + span
	t.NewShardEpoch = t.OldShardEpoch + span
	t.NewActiveConfHash = word(0x22)
	t.SupersessionSpan = span
	t.SupersessionCommitment = word(0x55)
	return t
}

func mustAck(t *testing.T, a handoff.AckRecord) []byte {
	t.Helper()
	b, err := a.Encode()
	require.NoError(t, err)
	return b
}

func TestEVMTransitionV3Shapes(t *testing.T) {
	for name, tr := range map[string]handoff.EVMTransition{
		"root only keeps shard epoch and hash": base(),
		"ordinary assignment advances both":    assignment(),
		"supersession folds two steps":         supersession(2),
		"supersession folds the maximum":       supersession(handoff.MaxSupersessionSpan),
	} {
		t.Run(name, func(t *testing.T) {
			raw, err := tr.Encode()
			require.NoError(t, err)
			got, err := handoff.DecodeEVMTransition(raw)
			require.NoError(t, err)
			require.Equal(t, tr, got)
		})
	}
}

func TestEVMTransitionV3IsolatedRefusals(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*handoff.EVMTransition)
		from   handoff.EVMTransition
	}{
		{"root epoch goes backwards", func(t *handoff.EVMTransition) { t.NewRootEpoch = t.OldRootEpoch - 1 }, base()},
		{"root epoch repeats", func(t *handoff.EVMTransition) { t.NewRootEpoch = t.OldRootEpoch }, base()},
		{"root only changes the shard epoch alone", func(t *handoff.EVMTransition) { t.NewShardEpoch = 1 }, base()},
		{"root only changes the hash alone", func(t *handoff.EVMTransition) { t.NewActiveConfHash = word(0x99) }, base()},
		{"root only carries a span", func(t *handoff.EVMTransition) { t.SupersessionSpan = 1 }, base()},
		{"root only carries a commitment", func(t *handoff.EVMTransition) { t.SupersessionCommitment = word(1) }, base()},
		{"assignment keeps the hash", func(t *handoff.EVMTransition) { t.NewActiveConfHash = t.OldActiveConfHash }, assignment()},
		{"assignment skips a shard epoch", func(t *handoff.EVMTransition) { t.NewShardEpoch++ }, assignment()},
		{"assignment carries a span", func(t *handoff.EVMTransition) { t.SupersessionSpan = 1 }, assignment()},
		{"assignment carries a commitment", func(t *handoff.EVMTransition) { t.SupersessionCommitment = word(1) }, assignment()},
		{"supersession without commitment", func(t *handoff.EVMTransition) { t.SupersessionCommitment = [32]byte{} }, supersession(3)},
		{"supersession span differs from the root delta", func(t *handoff.EVMTransition) { t.SupersessionSpan = 2 }, supersession(3)},
		{"supersession shard delta differs from the root delta", func(t *handoff.EVMTransition) { t.NewShardEpoch-- }, supersession(3)},
		{"supersession keeps the hash", func(t *handoff.EVMTransition) { t.NewActiveConfHash = t.OldActiveConfHash }, supersession(3)},
		{"supersession beyond the bound", func(t *handoff.EVMTransition) {}, supersession(handoff.MaxSupersessionSpan + 1)},
		{"zero old hash", func(t *handoff.EVMTransition) { t.OldActiveConfHash = [32]byte{} }, base()},
		{"zero new hash", func(t *handoff.EVMTransition) { t.NewActiveConfHash = [32]byte{} }, base()},
		{"zero body id", func(t *handoff.EVMTransition) { t.NextBodyID = [32]byte{} }, base()},
		{"zero genesis id", func(t *handoff.EVMTransition) { t.GenesisID = [32]byte{} }, base()},
		{"ack parents differ", func(t *handoff.EVMTransition) { t.Ack.SuccessorParent = word(0x77) }, base()},
		{"zero ack round", func(t *handoff.EVMTransition) { t.Ack.EVMRound = 0 }, base()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := tc.from
			tc.mutate(&tr)
			require.False(t, tr.Valid())
			_, err := tr.Encode()
			require.ErrorIs(t, err, handoff.ErrCodec)
		})
	}
}

func TestEVMTransitionRefusesTheRetiredVersionAndNonCanonicalBytes(t *testing.T) {
	raw, err := assignment().Encode()
	require.NoError(t, err)
	for name, data := range map[string][]byte{
		"trailing byte": append(bytes.Clone(raw), 0),
		"truncated":     raw[:len(raw)-1],
		"empty":         nil,
	} {
		_, err := handoff.DecodeEVMTransition(data)
		require.ErrorIs(t, err, handoff.ErrCodec, name)
	}
	// The pre-assignment encoding (version 2, seven elements) is never reinterpreted.
	legacy, err := handoff.EncForTest("UNICITY_HANDOFF_EVM_TRANSITION", uint64(2), uint64(1), uint64(2), word(0x44), word(0x45), mustAck(t, base().Ack))
	require.NoError(t, err)
	_, err = handoff.DecodeEVMTransition(legacy)
	require.ErrorIs(t, err, handoff.ErrCodec)
}

func TestFoldTransitionsBindsTheCommittedChain(t *testing.T) {
	step := func(rootOld uint64, shardOld uint64, oldHash, newHash [32]byte, commit byte) handoff.EVMTransition {
		tr := base()
		tr.OldRootEpoch, tr.NewRootEpoch = rootOld, rootOld+1
		tr.OldShardEpoch, tr.NewShardEpoch = shardOld, shardOld+1
		tr.OldActiveConfHash, tr.NewActiveConfHash = oldHash, newHash
		tr.Ack = ack(commit, 0x33)
		return tr
	}
	a := step(1, 0, word(0x10), word(0x20), 0xa1)
	b := step(2, 1, word(0x20), word(0x30), 0xa2)
	folded, err := handoff.FoldTransitions([]handoff.EVMTransition{a, b})
	require.NoError(t, err)
	require.EqualValues(t, 1, folded.OldRootEpoch)
	require.EqualValues(t, 3, folded.NewRootEpoch)
	require.EqualValues(t, 0, folded.OldShardEpoch)
	require.EqualValues(t, 2, folded.NewShardEpoch)
	require.Equal(t, a.OldActiveConfHash, folded.OldActiveConfHash)
	require.Equal(t, b.NewActiveConfHash, folded.NewActiveConfHash)
	require.EqualValues(t, 2, folded.SupersessionSpan)
	require.Equal(t, b.Ack, folded.Ack, "the acknowledgement fields are the latest committed handoff's")
	want, err := evmassign.ChainCommit(1, 0, a.OldActiveConfHash[:], [][]byte{a.Ack.CommitID[:], b.Ack.CommitID[:]})
	require.NoError(t, err)
	require.Equal(t, want, folded.SupersessionCommitment, "the commitment is the one a verifier recomputes from retained history")
	_, err = folded.Encode()
	require.NoError(t, err)

	one, err := handoff.FoldTransitions([]handoff.EVMTransition{a})
	require.NoError(t, err)
	require.Equal(t, a, one)

	c := step(3, 2, word(0x30), word(0x40), 0xa3)
	cases := map[string][]handoff.EVMTransition{
		"empty": nil,
		"a third transition (no recovery ladder)": {a, b, c},
		"gap in root epochs":                      {a, step(3, 1, word(0x20), word(0x30), 0xa2)},
		"gap in shard epochs":                     {a, step(2, 2, word(0x20), word(0x30), 0xa2)},
		"hash does not continue":                  {a, step(2, 1, word(0x99), word(0x30), 0xa2)},
		"another frozen parent":                   {a, func() handoff.EVMTransition { s := b; s.Ack = ack(0xa2, 0x34); return s }()},
		"a root-only step in a chain": {a, func() handoff.EVMTransition {
			s := base()
			s.OldRootEpoch, s.NewRootEpoch = 2, 3
			s.OldShardEpoch, s.NewShardEpoch = 1, 1
			s.OldActiveConfHash, s.NewActiveConfHash = word(0x20), word(0x20)
			return s
		}()},
	}
	for name, steps := range cases {
		_, err := handoff.FoldTransitions(steps)
		require.ErrorIs(t, err, handoff.ErrBoundary, name)
	}
	t.Run("order matters", func(t *testing.T) {
		_, err := handoff.FoldTransitions([]handoff.EVMTransition{b, a})
		require.ErrorIs(t, err, handoff.ErrBoundary)
	})
	t.Run("the folded commitment changes with the chain", func(t *testing.T) {
		other := b
		other.Ack = ack(0xa9, 0x33)
		again, err := handoff.FoldTransitions([]handoff.EVMTransition{a, other})
		require.NoError(t, err)
		require.NotEqual(t, folded.SupersessionCommitment, again.SupersessionCommitment)
	})
}
