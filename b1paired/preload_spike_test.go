package b1paired_test

// SPIKE (design briefs/b1-any-age-by-signatures.md section 4, "resolve this integration first"): what the REAL root-input -> block gates do to a
// block that must import the missed epochs (a > B) while the usable origin stays where it is. These tests run real code: the q3active history of
// three root epochs, rootinput.AuthenticateObservationV2, rootinput.DeriveV2, B1Config.Derive and b1state.Admit.

import (
	"context"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/b1paired"
	"github.com/unicitynetwork/bft-core/b1registry"
	"github.com/unicitynetwork/bft-core/b1state"
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
		for _, node := range nodes[:count] {
			require.NoError(t, uc.UnicitySeal.Sign(node.PeerConf.ID.String(), node.Signer))
		}
		o, err := rootinput.AuthenticateHistoricalObservationV2(ctx, rootinput.ObservationContextV2{NetworkID: 5, PartitionID: 8, ShardConfHash: g.FullShardConfHash().Bytes(), RootEpoch: 3, EpochAuthority: installedEpoch(3), TrustBases: rt.Trust(nil)}, uc, tr)
		require.NoError(t, err)
		return o
	}
	return &threeEpochs{p, g, origin, parent, pair, obs, rt}
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
