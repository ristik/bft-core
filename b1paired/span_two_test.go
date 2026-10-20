package b1paired_test

// Real-path coverage of the permanent registry's acknowledgement block: the q3active history of three root epochs, rootinput.DeriveV2,
// B1Config.Derive and b1state.Admit.

import (
	"bytes"
	"context"
	stdcrypto "crypto"
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
	"github.com/unicitynetwork/bft-core/b1paired"
	"github.com/unicitynetwork/bft-core/b1registry"
	"github.com/unicitynetwork/bft-core/b1state"
	"github.com/unicitynetwork/bft-core/handoff"
	"github.com/unicitynetwork/bft-core/internal/testutils/b1fixture"
	"github.com/unicitynetwork/bft-core/internal/testutils/certifiedchain"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3process"
	"github.com/unicitynetwork/bft-core/q3active"
	"github.com/unicitynetwork/bft-core/registrygenesis"
	"github.com/unicitynetwork/bft-core/registryproof"
	"github.com/unicitynetwork/bft-core/rootinput"
	"github.com/unicitynetwork/bft-go-base/types"
)

type threeEpochs struct {
	second *q3fixture.Fixture
	p      b1state.Profile
	g      *registrygenesis.Genesis
	origin registrygenesis.GenesisOrigin
	parent registryproof.Snapshot
	pair   *b1paired.Config
	obs    func(epoch, round uint64) rootinput.VerifiedObservationV2
	rt     *q3active.Runtime
}

func newThreeEpochs(t *testing.T) *threeEpochs {
	t.Helper()
	first := q3fixture.New(t, q3fixture.Options{})
	second := q3fixture.New(t, q3fixture.Options{After: first})
	process := q3process.New(t, first)
	rt := process.Start()
	ctx := context.Background()
	require.NoError(t, rt.Activate(ctx, process.Bundle()))
	require.NoError(t, rt.Activate(ctx, q3active.Bundle{Envelope: second.EnvelopeBytes, Snapshot: second.Snapshot}))
	c := certifiedchain.New(t, 5, 0)
	p := b1state.Profile{Network: 5, RootGenesisID: first.Genesis, ExecutionChainID: 1337, RuntimeHash: [32]byte(common.HexToHash(b1registry.CodeHashHex)), CompilerHash: b1registry.CompilerHash(), MaxEpochsPerUpdate: b1state.MinEpochsPerUpdate, DeltaEV: 1, DeltaHold: 2, RestGas: b1registry.MinRestGas(b1state.MinEpochsPerUpdate), CompanionBytes: 1 << 20, OtherCompanionBytes: 65536, OrdinaryCapacity: 7000000, GenesisUCTime: 1000}
	var err error
	p.SystemGas, err = p.RequiredSystemGas()
	require.NoError(t, err)
	p.MaxGas = p.SystemGas + p.OrdinaryCapacity
	g, err := registrygenesis.GenerateB1(certifiedchain.Config(5), p, rt.History(), registrygenesis.EVMParams{GasLimit: p.MaxGas})
	require.NoError(t, err)
	full, err := g.FullConfig()
	require.NoError(t, err)
	origin, err := registrygenesis.B1Origin(full, p, rt.History(), g.GenesisJSON(), nil, registrygenesis.GenesisJSONLimits{})
	require.NoError(t, err)
	parent, err := registryproof.Verify(g.ProofContext(), g.EVMGenesisHash(), g.Evidence())
	require.NoError(t, err)
	pair := &b1paired.Config{Profile: p, Authority: rt.B1Authority(), Records: b1fixture.EmptyRecords{UCTime: p.GenesisUCTime}, Proofs: func(_ context.Context, _ registryproof.Snapshot, keys []common.Hash) ([][][]byte, error) {
		return g.B1Proofs(keys), nil
	}}
	obs := func(epoch, round uint64) rootinput.VerifiedObservationV2 {
		tr := certifiedchain.Technical(0)
		tr.Round = 1
		uc := c.CertifyFor(full, second.NewNodes[0].Signer, &types.InputRecord{Version: 1}, tr, round)
		uc.UnicitySeal.NetworkID = 5
		uc.UnicitySeal.Epoch = epoch
		uc.UnicitySeal.Signatures = nil
		nodes, count := second.NewNodes, 2
		if epoch == 1 {
			nodes, count = first.OldNodes, 3
		}
		if epoch == 2 {
			nodes, count = second.OldNodes, 3
		}
		for _, node := range nodes[:count] {
			require.NoError(t, uc.UnicitySeal.Sign(node.PeerConf.ID.String(), node.Signer))
		}
		o, err := rootinput.AuthenticateHistoricalObservationV2(ctx, rootinput.ObservationContextV2{NetworkID: 5, PartitionID: 8, ShardConfHash: g.FullShardConfHash().Bytes(), RootEpoch: 3, EpochAuthority: installedEpoch(3), TrustBases: rt.Trust(nil)}, uc, tr)
		require.NoError(t, err)
		return o
	}
	return &threeEpochs{second, p, g, origin, parent, pair, obs, rt}
}

type trieNodes [][]byte

func (n *trieNodes) Put(_, v []byte) error { *n = append(*n, bytes.Clone(v)); return nil }
func (n *trieNodes) Delete([]byte) error   { return nil }

// parentWith commits the given registry storage words into a block header at height number (a copy of b1fixture.ParentAt for this fixture).
func (e *threeEpochs) parentWith(t *testing.T, words map[common.Hash]common.Hash, number uint64) (registryproof.Snapshot, func([]common.Hash) [][][]byte) {
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
	account, err := rlp.EncodeToBytes(&ethtypes.StateAccount{Balance: new(uint256.Int), Root: storage.Hash(), CodeHash: e.p.RuntimeHash[:]})
	require.NoError(t, err)
	state := trie.NewEmpty(triedb.NewDatabase(rawdb.NewMemoryDatabase(), nil))
	address := registryproof.RegistryAddress
	path := crypto.Keccak256(address[:])
	require.NoError(t, state.Update(path, account))
	var header ethtypes.Header
	require.NoError(t, rlp.DecodeBytes(e.g.Header(), &header))
	header.Root = state.Hash()
	header.Number = new(big.Int).SetUint64(number)
	raw, err := rlp.EncodeToBytes(&header)
	require.NoError(t, err)
	var proof trieNodes
	require.NoError(t, state.Prove(path, &proof))
	ev := registryproof.Evidence{Header: raw, AccountProof: proof}
	names, err := registryproof.SlotNamesFor(registryproof.FreshB1)
	require.NoError(t, err)
	for i := range names {
		k, err := registryproof.SlotKeyFor(registryproof.FreshB1, i)
		require.NoError(t, err)
		var p trieNodes
		require.NoError(t, storage.Prove(crypto.Keccak256(k[:]), &p))
		ev.StorageProofs = append(ev.StorageProofs, p)
	}
	ctx := e.g.ProofContext()
	snap, err := registryproof.Verify(ctx, header.Hash(), ev)
	require.NoError(t, err)
	prove := func(keys []common.Hash) [][][]byte {
		out := make([][][]byte, len(keys))
		for i, k := range keys {
			var p trieNodes
			require.NoError(t, storage.Prove(crypto.Keccak256(k[:]), &p))
			out[i] = p
		}
		return out
	}
	return snap, prove
}

// The acknowledgement of a supersession folded over two assignment steps (primary + supersession, MaxSupersessionSpan = 2), derived through the
// real path on the ORIGINAL frozen parent: the folded transition names shard epochs 0 -> 2 and a configuration hash that is not the genesis one,
// the observation is epoch 3's certificate over that configuration, and the one B1 update installs the two consecutive entries (root epochs 2 and
// 3) read from the authenticated root history, closing the old tip once. The frozen-parent check is unchanged.
func TestSpanTwoSupersessionAcknowledgementInstallsBothEntriesInOneBlock(t *testing.T) {
	e := newThreeEpochs(t)
	full, err := e.g.FullConfig()
	require.NoError(t, err)
	withParam := func(v string) *types.PartitionDescriptionRecord {
		c := *full
		c.PartitionParams = map[string]string{}
		for k, x := range full.PartitionParams {
			c.PartitionParams[k] = x
		}
		c.PartitionParams["spike.assignment"] = v
		return &c
	}
	conf := func(c *types.PartitionDescriptionRecord) [32]byte {
		h, err := c.Hash(stdcrypto.SHA256)
		require.NoError(t, err)
		return [32]byte(h)
	}
	full2 := withParam("2")
	conf0, conf1, conf2 := [32]byte(e.g.FullShardConfHash()), conf(withParam("1")), conf(full2)
	frozen := e.parent.ParentHash()
	step := func(oldRoot, oldShard uint64, from, to [32]byte, id byte) handoff.EVMTransition {
		var tr handoff.EVMTransition
		tr.OldRootEpoch, tr.NewRootEpoch = oldRoot, oldRoot+1
		tr.OldShardEpoch, tr.NewShardEpoch = oldShard, oldShard+1
		tr.OldActiveConfHash, tr.NewActiveConfHash = from, to
		tr.NextBodyID, tr.GenesisID = [32]byte{1}, [32]byte{2}
		tr.Ack.FrozenID, tr.Ack.CommitID = [32]byte{3}, [32]byte{id}
		copy(tr.Ack.FrozenParent[:], frozen.Bytes()) // every folded step froze the same parent
		tr.Ack.SuccessorParent = tr.Ack.FrozenParent
		tr.Ack.SuccessorTR, tr.Ack.EVMRound = [32]byte{5}, 1
		return tr
	}
	s1, s2 := step(1, 0, conf0, conf1, 4), step(2, 1, conf1, conf2, 5)
	folded, err := handoff.FoldTransitions([]handoff.EVMTransition{s1, s2})
	require.NoError(t, err)
	require.EqualValues(t, 2, folded.SupersessionSpan)
	encoded, err := folded.Encode()
	require.NoError(t, err)

	// the observation: epoch 3's certificate over the second assignment's configuration, shard epoch 2
	tr := certifiedchain.Technical(0)
	tr.Round, tr.Epoch = 1, 2
	chain := certifiedchain.New(t, 5, 0)
	uc := chain.CertifyFor(full2, e.second.NewNodes[0].Signer, &types.InputRecord{Version: 1}, tr, 15)
	uc.UnicitySeal.NetworkID = 5
	uc.UnicitySeal.Epoch = 3
	uc.UnicitySeal.Signatures = nil
	for _, node := range e.second.NewNodes[:2] {
		require.NoError(t, uc.UnicitySeal.Sign(node.PeerConf.ID.String(), node.Signer))
	}
	o, err := rootinput.AuthenticateHistoricalObservationV2(context.Background(), rootinput.ObservationContextV2{NetworkID: 5, PartitionID: 8, ShardConfHash: conf2[:], RootEpoch: 3, EpochAuthority: installedEpoch(3), TrustBases: e.rt.Trust(nil)}, uc, tr)
	require.NoError(t, err)

	c := rootinput.ContextV2{Context: context.Background(), B1: e.pair, Genesis: e.origin, Parent: e.parent, Round: 1, ParentHash: frozen.Bytes(), TransitionsPending: true, Transition: encoded}
	res, err := rootinput.DeriveV2(c, o)
	require.NoError(t, err)
	require.Equal(t, [][]byte{encoded}, res.Input.Transitions)
	update, _, err := b1state.Admit(res.B1Update, e.p, e.p.SystemGas)
	require.NoError(t, err)
	var got []uint64
	for _, n := range update.NewEntries {
		got = append(got, n.Epoch)
	}
	require.Equal(t, []uint64{2, 3}, got, "both missed epochs are installed by the one acknowledgement block")
	require.EqualValues(t, 1, update.PriorTipEpoch)
	require.NotNil(t, update.OldTipEnd)
	require.EqualValues(t, 7, *update.OldTipEnd, "the old tip is closed once, at the first successor's start")
	require.Equal(t, [32]byte(frozen), update.ParentHash, "built on the original frozen parent")

	// the same acknowledgement on any other parent is refused: the frozen-parent check stands
	other, _ := e.parentWith(t, func() map[common.Hash]common.Hash {
		w := e.g.B1Words()
		w[common.Hash(b1state.FixedSlot("round.authorized"))] = common.Hash(b1state.Word(1))
		w[common.Hash(b1state.FixedSlot("outcomes.round"))] = common.Hash(b1state.Word(1))
		w[common.Hash(b1state.FixedSlot("outcomes.commitment"))] = common.Hash{9}
		return w
	}(), 1)
	c.Parent, c.ParentHash = other, other.ParentHash().Bytes()
	_, err = rootinput.DeriveV2(c, o)
	require.ErrorIs(t, err, rootinput.ErrV2Context)

	// span 3 cannot be folded (the root refuses the chain too: storage.CheckSupersessionChainLength)
	s3 := step(3, 2, conf2, conf(withParam("3")), 6)
	_, err = handoff.FoldTransitions([]handoff.EVMTransition{s1, s2, s3})
	require.ErrorIs(t, err, handoff.ErrBoundary)
}

// parentAt builds a committed (non-genesis) parent with the genesis registry words plus the given changes.
func (e *threeEpochs) parentAt(t *testing.T, set map[string]uint64, extra map[common.Hash]common.Hash) (b1paired.Config, registryproof.Snapshot) {
	words := e.g.B1Words()
	for k, v := range map[string]uint64{"round.authorized": 1, "outcomes.round": 1} {
		words[common.Hash(b1state.FixedSlot(k))] = common.Hash(b1state.Word(v))
	}
	words[common.Hash(b1state.FixedSlot("outcomes.commitment"))] = common.Hash{9}
	for k, v := range set {
		words[common.Hash(b1state.FixedSlot(k))] = common.Hash(b1state.Word(v))
	}
	for k, v := range extra {
		words[k] = v
	}
	parent, prove := e.parentWith(t, words, 1)
	pair := *e.pair
	pair.Proofs = func(_ context.Context, _ registryproof.Snapshot, keys []common.Hash) ([][][]byte, error) {
		return prove(keys), nil
	}
	return pair, parent
}

// A ready parent whose usable epoch is behind the imported tip is registry corruption: Derive refuses it instead of healing it with the update.
func TestReadyParentBehindTheImportedTipIsRefusedNotHealed(t *testing.T) {
	e := newThreeEpochs(t)
	pair, parent := e.parentAt(t, map[string]uint64{"b1.importedTipEpoch": 2, "b1.originReady": 1, "origin.rootEpoch": 1, "clock.rootRound": 5}, e.entryWords(t, 2))
	_, err := pair.Derive(context.Background(), parent, e.obs(3, 15))
	require.ErrorIs(t, err, b1state.ErrImportedUsableMismatch)
	// control: the same parent with the usable epoch on the tip derives (installs epoch 3 only)
	pair, parent = e.parentAt(t, map[string]uint64{"b1.importedTipEpoch": 2, "b1.originReady": 1, "origin.rootEpoch": 2, "clock.rootRound": 8}, e.entryWords(t, 2))
	res, err := pair.Derive(context.Background(), parent, e.obs(3, 15))
	require.NoError(t, err)
	update, _, err := b1state.Admit(res.Update, e.p, e.p.SystemGas)
	require.NoError(t, err)
	require.Len(t, update.NewEntries, 1)
	require.EqualValues(t, 3, update.NewEntries[0].Epoch)
}

// Each entry to install must be proven absent: a parent whose presence word for epoch I+1 is already set is refused.
func TestDeriveRequiresEveryNewEntryToBeProvenAbsent(t *testing.T) {
	e := newThreeEpochs(t)
	pair, parent := e.parentAt(t, nil, nil)
	_, err := pair.Derive(context.Background(), parent, e.obs(3, 15))
	require.NoError(t, err, "control: nothing installed yet")
	present := map[common.Hash]common.Hash{common.Hash(b1state.EntrySlot(2, 0)): common.Hash(b1state.Word(1))}
	pair, parent = e.parentAt(t, nil, present)
	_, err = pair.Derive(context.Background(), parent, e.obs(3, 15))
	require.ErrorIs(t, err, b1state.ErrHistory)
	// the second entry too
	present = map[common.Hash]common.Hash{common.Hash(b1state.EntrySlot(3, 0)): common.Hash(b1state.Word(1))}
	pair, parent = e.parentAt(t, nil, present)
	_, err = pair.Derive(context.Background(), parent, e.obs(3, 15))
	require.ErrorIs(t, err, b1state.ErrHistory)
}

func (e *threeEpochs) entryWords(t *testing.T, epoch uint64) map[common.Hash]common.Hash {
	h, err := e.pair.Authority.B1History(15)
	require.NoError(t, err)
	history, err := h.B1Entries(15)
	require.NoError(t, err)
	entry := history[epoch-history[0].Epoch]
	w, err := b1state.EntryStorage(entry, e.g.B1Deployment())
	require.NoError(t, err)
	out := map[common.Hash]common.Hash{}
	for k, v := range w {
		out[common.Hash(k)] = common.Hash(v)
	}
	// the predecessor is closed by this entry
	prev := history[epoch-history[0].Epoch-1]
	prev.End = &entry.Start
	pw, err := b1state.EntryStorage(prev, e.g.B1Deployment())
	require.NoError(t, err)
	for k, v := range pw {
		out[common.Hash(k)] = common.Hash(v)
	}
	return out
}
