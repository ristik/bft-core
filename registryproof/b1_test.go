package registryproof_test

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/b1state"
	"github.com/unicitynetwork/bft-core/internal/testutils/b1fixture"
	"github.com/unicitynetwork/bft-core/registryproof"
)

func TestFreshB1FixedProofInvariants(t *testing.T) {
	f := b1fixture.New(t)
	names, err := registryproof.SlotNamesFor(registryproof.FreshB1)
	require.NoError(t, err)
	require.Len(t, names, 43)
	require.NotContains(t, names, "layoutVersion")
	for i, n := range names {
		k, err := registryproof.SlotKeyFor(registryproof.FreshB1, i)
		require.NoError(t, err)
		require.Equal(t, common.Hash(b1state.FixedSlot(n)), k)
	}
	for _, tc := range []struct {
		name  string
		slot  string
		value common.Hash
		want  error
	}{
		{"uninitialized", "b1.initialized", common.Hash{}, registryproof.ErrNotInitialized},
		{"nonliteral-initialized", "b1.initialized", common.Hash(b1state.Word(2)), registryproof.ErrNotInitialized},
		{"network-zero", "b1.network", common.Hash{}, registryproof.ErrConfiguration},
		{"network-width", "b1.network", common.Hash(b1state.Word(65536)), registryproof.ErrConfiguration},
		{"format-zero", "b1.format", common.Hash{}, registryproof.ErrConfiguration},
		{"format-other", "b1.format", common.Hash(b1state.Word(3)), registryproof.ErrConfiguration},
		{"tip-below-genesis", "b1.genesisEpoch", common.Hash(b1state.Word(5)), registryproof.ErrConfiguration},
		{"ready-flag-width", "b1.originReady", common.Hash(b1state.Word(2)), registryproof.ErrConfiguration},
		{"missing-profile", "b1.profileHash", common.Hash{}, registryproof.ErrConfiguration},
		{"scalar-width", "b1.importedTipEpoch", common.Hash{0: 1}, registryproof.ErrValue},
		{"phase", "phase", common.Hash(b1state.Word(1)), registryproof.ErrNotFinalized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			words := f.Genesis.B1Words()
			words[common.Hash(b1state.FixedSlot(tc.slot))] = tc.value
			c, h, e, _ := b1fixture.Parent(t, f, words)
			_, err := registryproof.Verify(c, h, e)
			require.ErrorIs(t, err, tc.want)
		})
	}
	var zero registryproof.Snapshot
	_, err = zero.VerifyWords(nil, nil)
	require.ErrorIs(t, err, registryproof.ErrStorageProof)
	_, err = f.Parent.VerifyWords(make([]common.Hash, 8391), make([][][]byte, 8391))
	require.ErrorIs(t, err, registryproof.ErrStorageProof)
	key := common.Hash(b1state.EntrySlot(1, 0))
	_, err = f.Parent.VerifyWords([]common.Hash{key}, [][][]byte{make([][]byte, 65)})
	require.ErrorIs(t, err, registryproof.ErrBounds)
	_, err = f.Parent.VerifyWords([]common.Hash{key}, [][][]byte{{make([]byte, 65537)}})
	require.ErrorIs(t, err, registryproof.ErrBounds)
}

func TestB1StorageProofResourceGuardsBeforeTrieVerification(t *testing.T) {
	f := b1fixture.New(t)
	key := common.Hash(b1state.EntrySlot(1, 0))
	proof := f.Genesis.B1Proofs([]common.Hash{key})[0]
	_, err := f.Parent.VerifyWords([]common.Hash{key}, [][][]byte{proof})
	require.NoError(t, err)
	tooMany := append([][]byte(nil), proof...)
	for len(tooMany) < 65 {
		tooMany = append(tooMany, proof[0])
	}
	_, err = f.Parent.VerifyWords([]common.Hash{key}, [][][]byte{tooMany})
	require.ErrorIs(t, err, registryproof.ErrBounds)
	largeNode := append(append([][]byte(nil), proof...), make([]byte, 65537))
	_, err = f.Parent.VerifyWords([]common.Hash{key}, [][][]byte{largeNode})
	require.ErrorIs(t, err, registryproof.ErrBounds)
	largeTotal := append([][]byte(nil), proof...)
	padding := make([]byte, 32768)
	for i := 0; i < 33; i++ {
		largeTotal = append(largeTotal, padding)
	}
	_, err = f.Parent.VerifyWords([]common.Hash{key}, [][][]byte{largeTotal})
	require.ErrorIs(t, err, registryproof.ErrBounds)
}

func TestB1StorageProofAggregateBound(t *testing.T) {
	f := b1fixture.New(t)
	padding := make([]byte, 65536)
	proofs := make([][][]byte, 65)
	for i := range proofs {
		proofs[i] = make([][]byte, 16)
		for j := range proofs[i] {
			proofs[i][j] = padding
		}
	}
	_, err := f.Parent.VerifyWords(make([]common.Hash, 65), proofs)
	require.ErrorIs(t, err, registryproof.ErrBounds)
}

func TestB1OrdinaryParentHeadBound(t *testing.T) {
	f := b1fixture.New(t)
	words := f.Genesis.B1Words()
	for name, value := range map[string]uint64{"clock.rootRound": 5, "origin.rootEpoch": 1, "round.authorized": 1, "outcomes.round": 1} {
		words[common.Hash(b1state.FixedSlot(name))] = common.Hash(b1state.Word(value))
	}
	words[common.Hash(b1state.FixedSlot("outcomes.commitment"))] = common.Hash{9}
	c, h, e, _ := b1fixture.ParentAt(t, f, words, 1)
	_, err := registryproof.Verify(c, h, e)
	require.NoError(t, err)
	words[common.Hash(b1state.FixedSlot("b1.originReady"))] = common.Hash(b1state.Word(1))
	words[common.Hash(b1state.FixedSlot("origin.rootEpoch"))] = common.Hash(b1state.Word(9)) // ready with a usable epoch beyond the imported tip
	c, h, e, _ = b1fixture.ParentAt(t, f, words, 1)
	_, err = registryproof.Verify(c, h, e)
	require.ErrorIs(t, err, registryproof.ErrConfiguration)
}
