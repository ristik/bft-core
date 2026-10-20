package q3active

import (
	"bytes"
	"context"
	"errors"
	"fmt"
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
	"github.com/unicitynetwork/bft-core/b1registry"
	"github.com/unicitynetwork/bft-core/b1state"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/internal/testutils/certifiedchain"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/keyvaluedb/memorydb"
	"github.com/unicitynetwork/bft-core/q3format"
	"github.com/unicitynetwork/bft-core/registrygenesis"
	"github.com/unicitynetwork/bft-core/registryproof"
	"github.com/unicitynetwork/bft-core/rootinput"
	"github.com/unicitynetwork/bft-core/rootrecords"
	"github.com/unicitynetwork/bft-go-base/types"
)

type scaleNodes [][]byte

func (n *scaleNodes) Put(_, v []byte) error { *n = append(*n, bytes.Clone(v)); return nil }
func (n *scaleNodes) Delete([]byte) error   { return nil }

// emptyRecords is a root-record source whose log is empty (b1fixture.EmptyRecords: not importable here, b1fixture imports this package).
type emptyRecords struct{ UCTime uint64 }

func (emptyRecords) Record(uint64) (rootrecords.Record, error) {
	return rootrecords.Record{}, errors.New("the source log is empty")
}

func (e emptyRecords) Cursor(context.Context, evmroot.RootOriginV2) (rootrecords.Cursor, error) {
	return rootrecords.Cursor{UCTime: e.UCTime}, nil
}

type installedAt uint64

func (e installedAt) CurrentRootEpoch() (uint64, bool) { return uint64(e), true }

// Evidence row 5c, root side, through the real authority: one B1 derivation (rootinput.Derive over a real q3active runtime) costs the same at 7, 60 and
// 4,000 permanent epochs when the imported tip and the observed epoch are the same two epochs of the end of the history. The history is the real three
// activations extended with synthetic copies of the last committee (q3format.Synthesize), each marked completed in the runtime's journal view.
func TestDeriveWorkDoesNotGrowWithThePermanentHistory(t *testing.T) {
	first := q3fixture.New(t, q3fixture.Options{})
	second := q3fixture.New(t, q3fixture.Options{After: first})
	base, err := q3format.NewHistory(first.Old)
	require.NoError(t, err)
	base, err = base.VerifyEnvelope(first.Envelope)
	require.NoError(t, err)
	base, err = base.VerifyEnvelope(second.Envelope)
	require.NoError(t, err)
	chain := certifiedchain.New(t, 5, 0)
	p := b1state.Profile{Network: 5, RootGenesisID: base.Genesis(), ExecutionChainID: 1337, RuntimeHash: [32]byte(common.HexToHash(b1registry.CodeHashHex)),
		CompilerHash: b1registry.CompilerHash(), MaxEpochsPerUpdate: b1state.MinEpochsPerUpdate, DeltaEV: 1, DeltaHold: 2, RestGas: b1registry.MinRestGas(b1state.MinEpochsPerUpdate),
		CompanionBytes: 1 << 20, OtherCompanionBytes: 65536, OrdinaryCapacity: 7000000, GenesisUCTime: 1000}
	p.SystemGas, err = p.RequiredSystemGas()
	require.NoError(t, err)
	p.MaxGas = p.SystemGas + p.OrdinaryCapacity
	g, err := registrygenesis.GenerateB1(certifiedchain.Config(5), p, base, registrygenesis.EVMParams{GasLimit: p.MaxGas})
	require.NoError(t, err)
	full, err := g.FullConfig()
	require.NoError(t, err)

	// scenario builds the runtime, the parent at imported tip `tip` and the observation in `epoch` over a permanent history of n epochs.
	scenario := func(t *testing.T, n int, tip, epoch uint64) (*rootinput.B1Config, registryproof.Snapshot, rootinput.VerifiedObservationV2) {
		hist := q3format.Synthesize(base, n-3) // epochs 1..n
		rt, err := New(Config{DB: memorydb.New(), Genesis: first.Old})
		require.NoError(t, err)
		rt.hist.Store(hist)
		for e := uint64(2); e <= uint64(n); e++ {
			rt.completed.Store(e, struct{}{})
		}
		tipEntry, err := hist.ForEpoch(tip)
		require.NoError(t, err)
		ent, err := hist.ForEpoch(epoch)
		require.NoError(t, err)
		round := ent.Start() + 1

		// the parent: the genesis registry words with the open tip's entry, the cursors at the tip and a usable origin on it
		entries, err := hist.B1EntriesFrom(round, tip, 0)
		require.NoError(t, err)
		words := g.B1Words()
		ew, err := b1state.EntryStorage(entries[0], g.B1Deployment())
		require.NoError(t, err)
		for k, v := range ew {
			words[common.Hash(k)] = common.Hash(v)
		}
		for k, v := range map[string]uint64{"b1.importedTipEpoch": tip, "b1.originReady": 1, "origin.rootEpoch": tip, "clock.rootRound": tipEntry.Start() + 1, "round.authorized": 1, "outcomes.round": 1} {
			words[common.Hash(b1state.FixedSlot(k))] = common.Hash(b1state.Word(v))
		}
		words[common.Hash(b1state.FixedSlot("outcomes.commitment"))] = common.Hash{9}
		snap, prove := scaleParent(t, g, p, words)

		tr := certifiedchain.Technical(0)
		tr.Round = 1
		uc := chain.CertifyFor(full, second.NewNodes[0].Signer, &types.InputRecord{Version: 1}, tr, round)
		uc.UnicitySeal.NetworkID = 5
		uc.UnicitySeal.Epoch = epoch
		uc.UnicitySeal.Signatures = nil
		for _, node := range second.NewNodes[:2] {
			require.NoError(t, uc.UnicitySeal.Sign(node.PeerConf.ID.String(), node.Signer))
		}
		o, err := rootinput.AuthenticateHistoricalObservationV2(context.Background(), rootinput.ObservationContextV2{NetworkID: 5, PartitionID: 8,
			ShardConfHash: g.FullShardConfHash().Bytes(), RootEpoch: epoch, EpochAuthority: installedAt(epoch), TrustBases: rt.Trust(nil)}, uc, tr)
		require.NoError(t, err)
		pair := &rootinput.B1Config{Profile: p, Authority: rt.B1Authority(), Records: emptyRecords{UCTime: p.GenesisUCTime},
			Proofs: func(_ context.Context, _ registryproof.Snapshot, keys []common.Hash) ([][][]byte, error) {
				return prove(keys), nil
			}}
		return pair, snap, o
	}

	allocs := map[int]float64{}
	for _, n := range []int{7, 60, 4000} {
		t.Run(fmt.Sprintf("%d epochs", n), func(t *testing.T) {
			pair, snap, o := scenario(t, n, uint64(n-2), uint64(n-1)) // the imported tip and the epoch the observation is in: the same two epochs of the end
			res, err := pair.Derive(context.Background(), snap, o)
			require.NoError(t, err)
			update, _, err := b1state.Admit(res.Update, p, p.SystemGas)
			require.NoError(t, err)
			require.Len(t, update.NewEntries, 1)
			require.EqualValues(t, n-1, update.NewEntries[0].Epoch)
			allocs[n] = testing.AllocsPerRun(5, func() {
				if _, err := pair.Derive(context.Background(), snap, o); err != nil {
					t.Fatal(err)
				}
			})
		})
	}
	// The proofs are tries of different shapes at each size (different keys), so the counts differ by a percent or two; a cost that grows with the history
	// (the old authority path converts and admits every epoch) multiplies them.
	t.Logf("allocations per Derive: 7 epochs %.0f, 60 epochs %.0f, 4000 epochs %.0f", allocs[7], allocs[60], allocs[4000])
	for _, n := range []int{60, 4000} {
		require.InEpsilon(t, allocs[7], allocs[n], 0.03, "Derive at %d epochs allocates as much as at 7", n)
	}

	// A proposal whose observation is far ahead of the imported tip (more than B epochs missing) is refused after a bounded amount of work, at any history length.
	t.Run("a far-ahead origin is refused with the walk capped at B", func(t *testing.T) {
		pair, snap, o := scenario(t, 4000, 100, 3999)
		_, err := pair.Derive(context.Background(), snap, o)
		require.ErrorIs(t, err, b1state.ErrTooManyEpochs)
		require.ErrorIs(t, err, rootinput.ErrB1Admission)
		require.Less(t, testing.AllocsPerRun(3, func() { _, _ = pair.Derive(context.Background(), snap, o) }), 2*allocs[4000], "the refusal costs about as much as a derivation, not O(gap)")
	})
}

// scaleParent commits the registry words into a block header at height 1 (the parent a derivation proves against) and returns the verified snapshot and the
// proof source for it.
func scaleParent(t *testing.T, g *registrygenesis.Genesis, p b1state.Profile, words map[common.Hash]common.Hash) (registryproof.Snapshot, func([]common.Hash) [][][]byte) {
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
	account, err := rlp.EncodeToBytes(&ethtypes.StateAccount{Balance: new(uint256.Int), Root: storage.Hash(), CodeHash: p.RuntimeHash[:]})
	require.NoError(t, err)
	state := trie.NewEmpty(triedb.NewDatabase(rawdb.NewMemoryDatabase(), nil))
	address := registryproof.RegistryAddress
	path := crypto.Keccak256(address[:])
	require.NoError(t, state.Update(path, account))
	var header ethtypes.Header
	require.NoError(t, rlp.DecodeBytes(g.Header(), &header))
	header.Root = state.Hash()
	header.Number = new(big.Int).SetUint64(1)
	raw, err := rlp.EncodeToBytes(&header)
	require.NoError(t, err)
	var proof scaleNodes
	require.NoError(t, state.Prove(path, &proof))
	ev := registryproof.Evidence{Header: raw, AccountProof: proof}
	names, err := registryproof.SlotNamesFor(registryproof.FreshB1)
	require.NoError(t, err)
	for i := range names {
		k, err := registryproof.SlotKeyFor(registryproof.FreshB1, i)
		require.NoError(t, err)
		var np scaleNodes
		require.NoError(t, storage.Prove(crypto.Keccak256(k[:]), &np))
		ev.StorageProofs = append(ev.StorageProofs, np)
	}
	snap, err := registryproof.Verify(g.ProofContext(), header.Hash(), ev)
	require.NoError(t, err)
	return snap, func(keys []common.Hash) [][][]byte {
		out := make([][][]byte, len(keys))
		for i, k := range keys {
			var np scaleNodes
			require.NoError(t, storage.Prove(crypto.Keccak256(k[:]), &np))
			out[i] = np
		}
		return out
	}
}
