package evmstate

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"sort"
	"strings"
	"testing"

	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/ethereum/go-ethereum/triedb"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"
)

type word32 = [32]byte

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	require.NoError(t, err)
	return b
}

func hexWord(t testing.TB, s string) (w word32) {
	t.Helper()
	b := unhex(t, s)
	require.Len(t, b, 32)
	copy(w[:], b)
	return w
}

type readEntry struct {
	Name  string            `json:"name"`
	Args  []json.RawMessage `json:"args"`
	Slots []string          `json:"slots"`
	Words []string          `json:"words"`
}

func (r readEntry) args(t testing.TB) []string {
	out := make([]string, len(r.Args))
	for i, a := range r.Args {
		out[i] = strings.Trim(string(a), `"`)
	}
	return out
}

type scenario struct {
	Name       string          `json:"name"`
	Kind       string          `json:"kind"`
	ID         uint64          `json:"id"`
	Generation uint64          `json:"generation"`
	ResultID   string          `json:"resultId"`
	Reads      []readEntry     `json:"reads"`
	Facts      json.RawMessage `json:"facts"`
}

type slotsFixture struct {
	Custody     string     `json:"custody"`
	NetworkWord string     `json:"networkWord"`
	Registry    string     `json:"registry"`
	CodeHash    string     `json:"codeHash"`
	Scenarios   []scenario `json:"scenarios"`
}

func loadFixture(t testing.TB, name string) slotsFixture {
	raw, err := os.ReadFile("testdata/" + name)
	require.NoError(t, err)
	var f slotsFixture
	require.NoError(t, json.Unmarshal(raw, &f))
	require.NotEmpty(t, f.Scenarios)
	return f
}

// storageOf is every slot custody's getters read in the scenario, with its word.
func storageOf(t testing.TB, s scenario) map[word32]word32 {
	out := map[word32]word32{}
	for _, r := range s.Reads {
		require.Len(t, r.Words, len(r.Slots))
		for i := range r.Slots {
			out[hexWord(t, r.Slots[i])] = hexWord(t, r.Words[i])
		}
	}
	return out
}

// ---- a real Merkle-Patricia world built from the fixture words -------------------------------------------------------------------------

type nodeList [][]byte

func (l *nodeList) Put(_, v []byte) error { *l = append(*l, bytes.Clone(v)); return nil }
func (l *nodeList) Delete([]byte) error   { return nil }

func newTrie() *trie.Trie { return trie.NewEmpty(triedb.NewDatabase(rawdb.NewMemoryDatabase(), nil)) }

func trimmed(w word32) []byte { return bytes.TrimLeft(w[:], "\x00") }

// encodeSlotValue is how the world stores a slot word; a test replaces it to store a non-canonical value.
var encodeSlotValue = trimmed

type world struct {
	root     word32
	state    *trie.Trie
	storage  map[ethcommon.Address]*trie.Trie
	contents map[ethcommon.Address]map[word32]word32
}

func (w *world) accountProof(t testing.TB, a [20]byte) [][]byte {
	var nl nodeList
	require.NoError(t, w.state.Prove(ethcrypto.Keccak256(a[:]), &nl))
	return nl
}

func (w *world) slotProof(t testing.TB, a [20]byte, slot word32) [][]byte {
	var nl nodeList
	require.NoError(t, w.storage[ethcommon.Address(a)].Prove(ethcrypto.Keccak256(slot[:]), &nl))
	return nl
}

type contract struct {
	addr     [20]byte
	codeHash word32
	storage  map[word32]word32
}

func buildWorld(t testing.TB, contracts ...contract) *world {
	w := &world{state: newTrie(), storage: map[ethcommon.Address]*trie.Trie{}, contents: map[ethcommon.Address]map[word32]word32{}}
	for _, c := range contracts {
		st := newTrie()
		for slot, v := range c.storage {
			if v == (word32{}) {
				continue
			}
			enc, err := rlp.EncodeToBytes(encodeSlotValue(v))
			require.NoError(t, err)
			require.NoError(t, st.Update(ethcrypto.Keccak256(slot[:]), enc))
		}
		w.storage[ethcommon.Address(c.addr)] = st
		w.contents[ethcommon.Address(c.addr)] = c.storage
		acct, err := rlp.EncodeToBytes(&types.StateAccount{Nonce: 1, Balance: uint256.NewInt(0), Root: st.Hash(), CodeHash: c.codeHash[:]})
		require.NoError(t, err)
		require.NoError(t, w.state.Update(ethcrypto.Keccak256(c.addr[:]), acct))
	}
	// unrelated accounts, so the state trie has real branches
	for i := 0; i < 24; i++ {
		var a [20]byte
		a[0], a[19] = 0xee, byte(i)
		acct, err := rlp.EncodeToBytes(&types.StateAccount{Nonce: uint64(i), Balance: uint256.NewInt(uint64(i)), Root: types.EmptyRootHash, CodeHash: types.EmptyCodeHash[:]})
		require.NoError(t, err)
		require.NoError(t, w.state.Update(ethcrypto.Keccak256(a[:]), acct))
	}
	w.root = w.state.Hash()
	return w
}

// recorder reads a plain map and remembers which slots were read, absent ones as zero.
type recorder struct {
	store map[word32]word32
	read  map[word32]bool
}

func newRecorder(store map[word32]word32) *recorder {
	return &recorder{store: store, read: map[word32]bool{}}
}
func (r *recorder) word(slot word32) (word32, error) {
	r.read[slot] = true
	return r.store[slot], nil
}

// witnessFor builds the witness for exactly the slots each account's reader read.
func witnessFor(t testing.TB, w *world, reads map[[20]byte]*recorder) []byte {
	var addrs [][20]byte
	for a := range reads {
		addrs = append(addrs, a)
	}
	sort.Slice(addrs, func(i, j int) bool { return bytes.Compare(addrs[i][:], addrs[j][:]) < 0 })
	var accounts []accountProof
	for _, a := range addrs {
		ap := accountProof{Addr: a[:], Proofs: w.accountProof(t, a)}
		var slots []word32
		for s := range reads[a].read {
			slots = append(slots, s)
		}
		sort.Slice(slots, func(i, j int) bool { return bytes.Compare(slots[i][:], slots[j][:]) < 0 })
		for _, s := range slots {
			v := w.contents[ethcommon.Address(a)][s]
			ap.Slots = append(ap.Slots, slotProof{Slot: s[:], Value: v[:], Proofs: w.slotProof(t, a, s)})
		}
		accounts = append(accounts, ap)
	}
	raw, err := Witness{Accounts: accounts}.Encode()
	require.NoError(t, err)
	return raw
}

func bigWord(v uint64) (w word32) { new(big.Int).SetUint64(v).FillBytes(w[:]); return w }
