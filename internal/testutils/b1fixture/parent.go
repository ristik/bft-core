package b1fixture

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/ethereum/go-ethereum/triedb"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/registryproof"
)

type nodes [][]byte

func (n *nodes) Put(_, v []byte) error { *n = append(*n, bytes.Clone(v)); return nil }
func (n *nodes) Delete([]byte) error   { return nil }

// Parent independently commits chosen storage words to real tries. Changing a
// word changes the header; summary RPC values play no part in these fixtures.
func Parent(t *testing.T, f *Fixture, words map[common.Hash]common.Hash) (registryproof.Context, common.Hash, registryproof.Evidence, func([]common.Hash) [][][]byte) {
	return ParentAt(t, f, words, 0)
}
func ParentAt(t *testing.T, f *Fixture, words map[common.Hash]common.Hash, number uint64) (registryproof.Context, common.Hash, registryproof.Evidence, func([]common.Hash) [][][]byte) {
	t.Helper()
	storage := trie.NewEmpty(triedb.NewDatabase(rawdb.NewMemoryDatabase(), nil))
	for k, v := range words {
		if v == (common.Hash{}) {
			continue
		}
		raw, err := rlp.EncodeToBytes(common.TrimLeftZeroes(v[:]))
		require.NoError(t, err)
		require.NoError(t, storage.Update(crypto.Keccak256(k[:]), raw))
	}
	account, err := rlp.EncodeToBytes(&ethtypes.StateAccount{Balance: new(uint256.Int), Root: storage.Hash(), CodeHash: f.Pair.Profile.RuntimeHash[:]})
	require.NoError(t, err)
	state := trie.NewEmpty(triedb.NewDatabase(rawdb.NewMemoryDatabase(), nil))
	address := registryproof.RegistryAddress
	path := crypto.Keccak256(address[:])
	require.NoError(t, state.Update(path, account))
	var header ethtypes.Header
	require.NoError(t, rlp.DecodeBytes(f.Genesis.Header(), &header))
	header.Root = state.Hash()
	header.Number = new(big.Int).SetUint64(number)
	raw, err := rlp.EncodeToBytes(&header)
	require.NoError(t, err)
	hash := header.Hash()
	var proof nodes
	require.NoError(t, state.Prove(path, &proof))
	ev := registryproof.Evidence{Header: raw, AccountProof: proof}
	prove := func(keys []common.Hash) [][][]byte {
		out := make([][][]byte, len(keys))
		for i, k := range keys {
			var p nodes
			require.NoError(t, storage.Prove(crypto.Keccak256(k[:]), &p))
			out[i] = p
		}
		return out
	}
	names, err := registryproof.SlotNamesFor(registryproof.FreshB1)
	require.NoError(t, err)
	keys := make([]common.Hash, len(names))
	for i := range names {
		keys[i], err = registryproof.SlotKeyFor(registryproof.FreshB1, i)
		require.NoError(t, err)
	}
	ev.StorageProofs = prove(keys)
	ctx := f.Genesis.ProofContext()
	if number == 0 {
		ctx.EVMGenesisHash = hash
	}
	return ctx, hash, ev, prove
}
