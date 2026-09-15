package registryproof

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/ethereum/go-ethereum/triedb"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"
)

/*
Fixtures build real state and storage tries with go-ethereum's trie package, the same way a client
commits state, and take proofs with Trie.Prove. The reader under test never sees a trie: only the header
bytes and the proof nodes. testdata/anvil-registry-proof.json adds a vector from an implementation that
does not share this code.

Registry values follow the §9 worked examples of docs/design/f4a-seal-registry-contract.md. Named digests
(U5, X1, S0, ...) are Keccak-256 of their names. The genesis commitment and configuration hash are the §5.4
vector's, and the code hash is the merged registry artifact's; both are fixtures, not a deployment.
*/

// registryCodeHash is artifacts/seal-registry-v1.json in ristik/unicity-pos-contracts at 7dc63acd.
var registryCodeHash = common.HexToHash("0x643b1b983696b0de1f67053daf65c33b55d304de79074b55ee6f8829715a267b")

var (
	genesisCommitment = common.HexToHash("0x071a4f34498689e1f26353434c92f763ddaaba8de9cc634aa68af6e1bf65eab8")
	fullShardConfHash = common.HexToHash("0x3a2c73649214e56d5e98d1c2d06cff56e7a5d67037a25bcf0e43fcaff8987a6b")
)

func named(s string) common.Hash { return crypto.Keccak256Hash([]byte(s)) }
func num(n uint64) common.Hash   { return common.BigToHash(new(big.Int).SetUint64(n)) }

// words maps field names to storage words; a missing name is the zero word.
type words map[string]common.Hash

func (w words) with(kv ...any) words {
	out := words{}
	for k, v := range w {
		out[k] = v
	}
	for i := 0; i < len(kv); i += 2 {
		out[kv[i].(string)] = kv[i+1].(common.Hash)
	}
	return out
}

// §9.1: the six genesis words.
func genesisWords() words {
	return words{
		"layoutVersion": num(1), "genesisCommitment": genesisCommitment, "config.shardConfHash": fullShardConfHash,
		"assignment.epoch": num(0), "assignment.rootEpoch": num(1), "phase": num(2),
	}
}

// executed returns the post-state of a successful open and finalize (§6.2, §6.3).
func executed(n, rootRound, certifiedRound uint64, stateHash string, blockHash string) words {
	w := genesisWords().with(
		"clock.rootRound", num(rootRound), "origin.rootEpoch", num(1), "origin.timestamp", num(1_700_000_000+rootRound),
		"origin.treeRoot", named(fmt.Sprint("U", rootRound)), "origin.identity", named(fmt.Sprint("O", rootRound)),
		"origin.trHash", named(fmt.Sprint("T", rootRound)), "round.authorized", num(n), "input.commitment", named(fmt.Sprint("X", n)),
		"certified.round", num(certifiedRound), "certified.stateHash", named(stateHash),
		"outcomes.round", num(n), "outcomes.commitment", named(fmt.Sprint("R", n)),
	)
	if blockHash != "" {
		w = w.with("certified.hasBlockHash", num(1), "certified.blockHash", named(blockHash))
	}
	return w
}

type spec struct {
	number   uint64
	parent   common.Hash
	words    words
	raw      map[string][]byte // a field's stored trie value, bypassing canonical encoding
	codeHash *common.Hash      // nil: registryCodeHash
	absent   bool              // no account at RegistryAddress
	fillers  int               // other accounts in the state trie
	header   func(*types.Header)
}

type block struct {
	hash        common.Hash
	number      uint64
	stateRoot   common.Hash
	storageRoot common.Hash
	ev          Evidence
	state       *trie.Trie
	storage     *trie.Trie
}

func newTrie() *trie.Trie { return trie.NewEmpty(triedb.NewDatabase(rawdb.NewMemoryDatabase(), nil)) }

type nodeList [][]byte

func (l *nodeList) Put(_, v []byte) error { *l = append(*l, common.CopyBytes(v)); return nil }
func (l *nodeList) Delete([]byte) error   { return nil }

func prove(t testing.TB, tr *trie.Trie, path []byte) [][]byte {
	var l nodeList
	require.NoError(t, tr.Prove(path, &l))
	return l
}

func cancunHeader(number uint64, parent, root common.Hash) *types.Header {
	withdrawals, beacon := types.EmptyWithdrawalsHash, common.Hash{}
	blobGasUsed, excessBlobGas := uint64(0), uint64(0)
	return &types.Header{
		ParentHash: parent, UncleHash: types.EmptyUncleHash, Root: root, TxHash: types.EmptyTxsHash,
		ReceiptHash: types.EmptyReceiptsHash, Difficulty: new(big.Int), Number: new(big.Int).SetUint64(number),
		GasLimit: 30_000_000, Time: 1_700_000_000 + number, Extra: named(fmt.Sprint("extra", number)).Bytes(),
		BaseFee: big.NewInt(7), WithdrawalsHash: &withdrawals, BlobGasUsed: &blobGasUsed,
		ExcessBlobGas: &excessBlobGas, ParentBeaconRoot: &beacon,
	}
}

func build(t testing.TB, s spec) block {
	storage := newTrie()
	for i, name := range SlotNames {
		v, ok := s.raw[name]
		if !ok {
			if w := s.words[name]; w != (common.Hash{}) {
				var err error
				v, err = rlp.EncodeToBytes(common.TrimLeftZeroes(w[:]))
				require.NoError(t, err)
			}
		}
		if v != nil {
			require.NoError(t, storage.Update(trieSlotKeys[i], v))
		}
	}
	storageRoot := storage.Hash()

	state := newTrie()
	for i := 0; i < s.fillers; i++ {
		addr := common.BigToAddress(big.NewInt(int64(i + 1)))
		enc, err := rlp.EncodeToBytes(&types.StateAccount{
			Balance: uint256.NewInt(1e18), Root: types.EmptyRootHash, CodeHash: types.EmptyCodeHash.Bytes(),
		})
		require.NoError(t, err)
		require.NoError(t, state.Update(crypto.Keccak256(addr[:]), enc))
	}
	if !s.absent {
		code := registryCodeHash
		if s.codeHash != nil {
			code = *s.codeHash
		}
		enc, err := rlp.EncodeToBytes(&types.StateAccount{Nonce: 1, Balance: new(uint256.Int), Root: storageRoot, CodeHash: code.Bytes()})
		require.NoError(t, err)
		require.NoError(t, state.Update(accountTrieKey, enc))
	}
	stateRoot := state.Hash()

	h := cancunHeader(s.number, s.parent, stateRoot)
	if s.header != nil {
		s.header(h)
	}
	enc, err := rlp.EncodeToBytes(h)
	require.NoError(t, err)
	require.Equal(t, h.Hash(), crypto.Keccak256Hash(enc), "fixture: the header hash is Keccak-256 of its RLP")

	ev := Evidence{Header: enc, AccountProof: prove(t, state, accountTrieKey), StorageProofs: make([][][]byte, FieldCount)}
	for i := range SlotNames {
		ev.StorageProofs[i] = prove(t, storage, trieSlotKeys[i])
	}
	return block{hash: h.Hash(), number: s.number, stateRoot: stateRoot, storageRoot: storageRoot, ev: ev, state: state, storage: storage}
}

// chain is the §9 history: genesis (§9.1), block 1 executing round 1 (§9.2), block 2 executing round 2
// (§9.3), and block 3 executing round 4 after the round-3 repeat (§9.4).
type chain struct {
	genesis, b1, b2, b3 block
}

const fillers = 64

func newChain(t testing.TB) chain {
	var c chain
	c.genesis = build(t, spec{number: 0, words: genesisWords(), fillers: fillers})
	c.b1 = build(t, spec{number: 1, parent: c.genesis.hash, words: executed(1, 5, 0, "S0", ""), fillers: fillers})
	c.b2 = build(t, spec{number: 2, parent: c.b1.hash, words: executed(2, 6, 1, "S1", "B1"), fillers: fillers})
	c.b3 = build(t, spec{number: 3, parent: c.b2.hash, words: executed(4, 9, 2, "S2", "B2"), fillers: fillers})
	return c
}

func (c chain) context() Context {
	return Context{
		RegistryAddress: RegistryAddress, RegistryCodeHash: registryCodeHash, GenesisCommitment: genesisCommitment,
		FullShardConfHash: fullShardConfHash, ShardEpoch: 0, RootEpoch: 1, EVMGenesisHash: c.genesis.hash,
	}
}

// cloneEvidence deep-copies ev so a test can change one element without touching the fixture.
func cloneEvidence(ev Evidence) Evidence {
	out := Evidence{Header: common.CopyBytes(ev.Header), AccountProof: cloneNodes(ev.AccountProof), StorageProofs: make([][][]byte, len(ev.StorageProofs))}
	for i, p := range ev.StorageProofs {
		out.StorageProofs[i] = cloneNodes(p)
	}
	return out
}

func cloneNodes(in [][]byte) [][]byte {
	if in == nil {
		return nil
	}
	out := make([][]byte, len(in))
	for i, n := range in {
		out[i] = common.CopyBytes(n)
	}
	return out
}
