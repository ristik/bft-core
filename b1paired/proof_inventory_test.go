package b1paired_test

import (
	"context"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/b1state"
	"github.com/unicitynetwork/bft-core/registryproof"
	"github.com/unicitynetwork/bft-core/rootinput"
)

// Evidence row 5c, root side: the storage words one B1 derivation proves against the parent are the open tip's entry (11 + 8 per member and the C_e cache word) and one presence word
// per entry about to be installed, whatever the history before the tip holds. Nothing of any other installed epoch is proven or read.
func TestDeriveProvesOnlyTheOpenTipAndTheAbsenceOfTheNewEntries(t *testing.T) {
	e := newThreeEpochs(t)
	h, err := e.pair.Authority.B1History(15)
	require.NoError(t, err)
	history, err := h.B1Entries(15)
	require.NoError(t, err)
	require.Len(t, history, 3)
	tipWords := func(epoch int) map[common.Hash]bool {
		open := history[epoch-1]
		open.End = nil
		w, err := b1state.EntryStorage(open, e.g.B1Deployment())
		require.NoError(t, err)
		out := map[common.Hash]bool{}
		for k := range w {
			out[common.Hash(k)] = true
		}
		return out
	}
	record := func(pair func(context.Context, registryproof.Snapshot, []common.Hash) ([][][]byte, error)) (func(context.Context, registryproof.Snapshot, []common.Hash) ([][][]byte, error), *[]common.Hash) {
		var seen []common.Hash
		return func(ctx context.Context, s registryproof.Snapshot, keys []common.Hash) ([][][]byte, error) {
			seen = append(seen, keys...)
			return pair(ctx, s, keys)
		}, &seen
	}
	check := func(name string, seen []common.Hash, tip int, installs []int) {
		want := tipWords(tip)
		for _, n := range installs {
			want[common.Hash(b1state.EntrySlot(uint64(n), 0))] = true
		}
		require.Len(t, seen, len(want), "%s: the number of proven words is the tip entry plus one presence word per new entry", name)
		for _, k := range seen {
			require.True(t, want[k], "%s: a word outside the tip entry and the presence words was proven", name)
		}
	}

	// genesis parent: tip = epoch 1, the observation of epoch 3 installs epochs 2 and 3
	pair := *e.pair
	var seen *[]common.Hash
	pair.Proofs, seen = record(e.pair.Proofs)
	_, err = pair.Derive(context.Background(), e.parent, e.obs(3, 15))
	require.NoError(t, err)
	check("tip 1, two new entries", *seen, 1, []int{2, 3})

	// a ready parent at tip = epoch 2 (U = I): one new entry; epoch 1's words are not touched although the registry holds it
	pair2, parent2 := e.parentAt(t, map[string]uint64{"b1.importedTipEpoch": 2, "b1.originReady": 1, "origin.rootEpoch": 2, "clock.rootRound": 8}, e.entryWords(t, 2))
	pair2.Proofs, seen = record(pair2.Proofs)
	_, err = pair2.Derive(context.Background(), parent2, e.obs(3, 15))
	require.NoError(t, err)
	check("tip 2, one new entry", *seen, 2, []int{3})
}

// The registry's genesis epoch is bound to the authenticated history's first epoch, in O(1): a registry that names another epoch as its genesis is refused
// as an admission failure, before any entry is read.
func TestDeriveBindsTheRegistrysGenesisEpochToTheHistorysFirst(t *testing.T) {
	e := newThreeEpochs(t)
	h, err := e.pair.Authority.B1History(15)
	require.NoError(t, err)
	require.EqualValues(t, 1, h.FirstEpoch())
	pair, parent := e.parentAt(t, map[string]uint64{"b1.genesisEpoch": 2, "b1.importedTipEpoch": 2}, e.entryWords(t, 2))
	_, err = pair.Derive(context.Background(), parent, e.obs(3, 15))
	require.ErrorIs(t, err, rootinput.ErrB1Admission)
	// control: the same parent naming the real genesis epoch derives
	pair, parent = e.parentAt(t, map[string]uint64{"b1.importedTipEpoch": 2, "b1.originReady": 1, "origin.rootEpoch": 2, "clock.rootRound": 8}, e.entryWords(t, 2))
	_, err = pair.Derive(context.Background(), parent, e.obs(3, 15))
	require.NoError(t, err)
}
