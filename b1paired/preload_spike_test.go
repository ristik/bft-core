package b1paired_test

// SPIKE (design briefs/b1-any-age-by-signatures.md section 4, "resolve this integration first"): what the REAL root-input -> block gates do to a
// block that must import the missed epochs (a > B) while the usable origin stays where it is. These tests run real code: the q3active history of
// three root epochs, rootinput.AuthenticateObservationV2, rootinput.DeriveV2, B1Config.Derive and b1state.Admit.

import (
	"bytes"
	"context"
	stdcrypto "crypto"
	"math/big"
	"strings"
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

func newThreeEpochs(t *testing.T, w uint64) *threeEpochs {
	t.Helper()
	first := q3fixture.New(t, q3fixture.Options{})
	second := q3fixture.New(t, q3fixture.Options{After: first})
	process := q3process.New(t, first)
	rt := process.Start()
	ctx := context.Background()
	require.NoError(t, rt.Activate(ctx, process.Bundle()))
	require.NoError(t, rt.Activate(ctx, q3active.Bundle{Envelope: second.EnvelopeBytes, Snapshot: second.Snapshot}))
	c := certifiedchain.New(t, 5, 0)
	p := b1state.Profile{Network: 5, RootGenesisID: first.Genesis, ExecutionChainID: 1337, RuntimeHash: [32]byte(common.HexToHash(b1registry.CodeHashHex)), CompilerHash: b1registry.CompilerHash(), WCert: w, DeltaEV: w + 1, DeltaHold: w + 2, RestGas: 1136500 + 1147500*(w+1), CompanionBytes: 1 << 20, OtherCompanionBytes: 65536, OrdinaryCapacity: 7000000, GenesisUCTime: 1000}
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

// The block a stalled shard builds after the root moved from epoch 1 to 3 carries the shard's authorizing UC, whose seal is in epoch 3
// (engineapi deriveV2: p.AuthorizingCertificate; non-historical authentication requires seal epoch == installed epoch). The registry is still
// at root epoch 1. Today that is refused unless the block itself carries the transition (DeriveV2: "root epoch change requires installed
// transition"), i.e. the observation's epoch and the block's acknowledgement are one decision.
func TestSpikeObservationAheadOfRegistryEpochNeedsTheTransitionInTheSameBlock(t *testing.T) {
	e := newThreeEpochs(t, 15)
	c := rootinput.ContextV2{Context: context.Background(), B1: e.pair, Genesis: e.origin, Parent: e.parent, Round: 1, ParentHash: e.parent.ParentHash().Bytes()}
	_, err := rootinput.DeriveV2(c, e.obs(3, 15))
	t.Logf("observation epoch 3, registry epoch %d, no transition: %v", e.parent.Fields().RootEpoch, err)
	require.Error(t, err)
}

func nonNilEnd(e b1state.Entry) bool { return e.End != nil }

// Today's derivation always imports up to the observation's own epoch, in one update: with a small window it silently drops the epochs in
// between (the pruned-registry behaviour), with a larger one it imports all of them at once, and the Update codec admits nothing else: the tail
// must be the origin epoch and open (b1state.Admit, ErrInterval).
func TestSpikeTodaysUpdateImportsUpToTheOriginInOneStep(t *testing.T) {
	for _, tc := range []struct {
		w       uint64
		entries []uint64
	}{{0, []uint64{3}}, {15, []uint64{2, 3}}} {
		e := newThreeEpochs(t, tc.w)
		res, err := e.pair.Derive(context.Background(), e.parent, e.obs(3, 15))
		require.NoError(t, err)
		u, _, err := b1state.Admit(res.Update, e.p, e.p.SystemGas)
		require.NoError(t, err)
		var got []uint64
		for _, n := range u.NewEntries {
			got = append(got, n.Epoch)
		}
		require.Equal(t, tc.entries, got, "W=%d", tc.w)
	}
	// A preload batch (epoch 2 while the observation is in epoch 3) is not expressible: the tail would be closed and not the origin epoch.
	e := newThreeEpochs(t, 15)
	res, err := e.pair.Derive(context.Background(), e.parent, e.obs(3, 15))
	require.NoError(t, err)
	u, _, err := b1state.Admit(res.Update, e.p, e.p.SystemGas)
	require.NoError(t, err)
	u.NewEntries = u.NewEntries[:1] // epoch 2 only
	_, _, err = b1state.Admit(u.Bytes(), e.p, e.p.SystemGas)
	require.ErrorIs(t, err, b1state.ErrInterval)
}

// The rule the spike proposes: the block's work is a function of the PARENT registry and the observation. While the imported tip is behind the
// observation's epoch the block is a preload block (at most B entries, no transition, usable origin unchanged); the transition is admissible
// only when the tip has reached the observation's epoch. Driven here against the real three-epoch history.
func TestSpikeCatchUpOfMoreThanBEpochsInPreloadBlocks(t *testing.T) {
	e := newThreeEpochs(t, 15)
	h, err := e.pair.Authority.B1History(15)
	require.NoError(t, err)
	history, err := h.B1Entries(15)
	require.NoError(t, err)
	require.Len(t, history, 3)
	const B = 1
	reg := &b1state.Permanent{Entries: []b1state.Entry{history[0]}, UsableEpoch: 1}
	reg.Entries[0].End = nil
	obs := e.obs(3, 15)
	require.EqualValues(t, 3, obs.Origin().RootEpoch)
	blocks := 0
	for reg.TipEpoch() < obs.Origin().RootEpoch {
		batch := b1state.NextBatch(history, reg.TipEpoch(), B)
		require.NoError(t, reg.Preload(history, batch, B))
		require.EqualValues(t, 1, reg.UsableEpoch, "preload never advances the usable origin")
		blocks++
		// interrupted preload: a node restarted here rebuilds the same next batch from the parent state alone
		if blocks == 1 {
			again := b1state.NextBatch(history, reg.TipEpoch(), B)
			require.EqualValues(t, 3, again[0].Epoch)
			require.ErrorIs(t, reg.Preload(history, batch, B), b1state.ErrPreloadTip, "replaying the committed batch is refused")
		}
	}
	require.Equal(t, 2, blocks, "a = 2 missed epochs with B = 1 take two preload blocks")
	require.ErrorIs(t, reg.Preload(history, b1state.NextBatch(history, 0, 2), B), b1state.ErrPreloadBatch)
	require.Len(t, reg.Entries, 3)
	for i, got := range reg.Entries {
		require.Equal(t, history[i].Epoch, got.Epoch)
		require.Equal(t, history[i].Start, got.Start)
		if i < 2 {
			require.True(t, nonNilEnd(got), "entry %d closed exactly once by its successor", got.Epoch)
			require.Equal(t, history[i+1].Start, *got.End)
		} else {
			require.Nil(t, got.End)
		}
	}
	reg.UsableEpoch = obs.Origin().RootEpoch // the acknowledgement block: only now
}

type trieNodes [][]byte

func (n *trieNodes) Put(_, v []byte) error { *n = append(*n, bytes.Clone(v)); return nil }
func (n *trieNodes) Delete([]byte) error   { return nil }

// parentWith commits the given registry storage words into a block header at height number (a copy of b1fixture.ParentAt for this fixture).
func (e *threeEpochs) parentWith(t *testing.T, words map[common.Hash]common.Hash, number uint64) registryproof.Snapshot {
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
	return snap
}

// The frozen-parent conflict (arch blocker, section preload): a root handoff freezes the shard at one EVM parent and the acknowledgement block
// must build on exactly that parent (DeriveV2: Ack.FrozenParent == executing parent; every folded step froze the same one). Any block between
// the freeze and the acknowledgement, a preload block included, changes the parent, and the same transition is then refused.
func TestSpikeAcknowledgementAfterAPreloadBlockLosesItsFrozenParent(t *testing.T) {
	e := newThreeEpochs(t, 15)
	genesisConf := [32]byte(e.g.FullShardConfHash())
	frozen := e.parent.ParentHash()
	transition := func(frozenParent common.Hash) []byte {
		var tr handoff.EVMTransition
		tr.OldRootEpoch, tr.NewRootEpoch = 1, 2 // a root-only step: shard epoch and configuration stay
		tr.OldActiveConfHash, tr.NewActiveConfHash = genesisConf, genesisConf
		tr.NextBodyID, tr.GenesisID = [32]byte{1}, [32]byte{2}
		tr.Ack.FrozenID, tr.Ack.CommitID = [32]byte{3}, [32]byte{4}
		copy(tr.Ack.FrozenParent[:], frozenParent.Bytes())
		tr.Ack.SuccessorParent = tr.Ack.FrozenParent
		tr.Ack.SuccessorTR, tr.Ack.EVMRound = [32]byte{5}, 1
		b, err := tr.Encode()
		require.NoError(t, err)
		return b
	}
	o := e.obs(2, 10)
	ctx := func(parent registryproof.Snapshot, frozenParent common.Hash) rootinput.ContextV2 {
		return rootinput.ContextV2{Context: context.Background(), B1: e.pair, Genesis: e.origin, Parent: parent, Round: 1, ParentHash: parent.ParentHash().Bytes(), TransitionsPending: true, Transition: transition(frozenParent)}
	}
	// the acknowledgement block on the frozen parent itself: the frozen-parent check passes (control)
	_, err := rootinput.DeriveV2(ctx(e.parent, frozen), o)
	t.Logf("control, acknowledgement on the frozen parent: %v", err)
	if err != nil {
		require.NotContains(t, err.Error(), "frozen parent mismatch", "control: %v", err)
	}
	// a preload block lands between the freeze and the acknowledgement: the parent is now a different block
	words := e.g.B1Words()
	for k, v := range mustEntryWords(t, e) {
		words[common.Hash(k)] = common.Hash(v)
	}
	words[common.Hash(b1state.FixedSlot("round.authorized"))] = common.Hash(b1state.Word(1))
	words[common.Hash(b1state.FixedSlot("outcomes.round"))] = common.Hash(b1state.Word(1))
	words[common.Hash(b1state.FixedSlot("outcomes.commitment"))] = common.Hash{9}
	p1 := e.parentWith(t, words, 1)
	require.NotEqual(t, frozen, p1.ParentHash())
	_, err = rootinput.DeriveV2(ctx(p1, frozen), o)
	require.ErrorIs(t, err, rootinput.ErrV2Context)
	require.True(t, strings.Contains(err.Error(), "frozen parent mismatch"), "%v", err)
}

func mustEntryWords(t *testing.T, e *threeEpochs) map[[32]byte][32]byte {
	h, err := e.pair.Authority.B1History(15)
	require.NoError(t, err)
	history, err := h.B1Entries(15)
	require.NoError(t, err)
	w, err := b1state.EntryStorage(history[1])
	require.NoError(t, err)
	return w
}

// The acknowledgement of a supersession folded over two assignment steps (primary + supersession, MaxSupersessionSpan = 2), derived through the
// real path on the ORIGINAL frozen parent: the folded transition names shard epochs 0 -> 2 and a configuration hash that is not the genesis one,
// the observation is epoch 3's certificate over that configuration, and the one B1 update installs the two consecutive entries (root epochs 2 and
// 3) read from the authenticated root history, closing the old tip once. The frozen-parent check is unchanged.
func TestSpikeSpanTwoSupersessionAcknowledgementInstallsBothEntriesInOneBlock(t *testing.T) {
	e := newThreeEpochs(t, 15)
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
	other := e.parentWith(t, func() map[common.Hash]common.Hash {
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
