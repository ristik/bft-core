package engineapi

import (
	"bytes"
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/handoff"
	"github.com/unicitynetwork/bft-core/internal/testutils/certifiedchain"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/registrywitness"
	"github.com/unicitynetwork/bft-core/rootinput"
	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-go-base/types"
)

// confResolver is an installed per-epoch configuration set that counts its lookups.
type confResolver struct {
	byEpoch map[uint64][]byte
	calls   int
}

func (r *confResolver) lookup(epoch uint64) ([]byte, bool) {
	r.calls++
	h, ok := r.byEpoch[epoch]
	return bytes.Clone(h), ok
}

// countingTrust counts the trust-base lookups an import performs.
type countingTrust struct {
	inner rootinput.TrustBases
	calls int
}

func (c *countingTrust) GetByEpoch(ctx context.Context, epoch uint64) (*types.RootTrustBaseV1, error) {
	c.calls++
	return c.inner.GetByEpoch(ctx, epoch)
}

// confEpochChain is a certified parent B1 with its authenticated registry witness served over RPC, and a way to
// certify the parent's own shard statement at any root round. Only that root round varies between cases.
type confEpochChain struct {
	t        *testing.T
	verifier *VerifierContext
	chain    *certifiedchain.Chain
	parent   certifiedchain.Block
	tr       *certification.TechnicalRecord
	signerID string
	source   *ParentWitnessSource
	rpcCalls *atomic.Int32
}

func newConfEpochChain(t *testing.T) *confEpochChain {
	t.Helper()
	verifier, _, _ := bootstrapAdapterFixture(t)
	c := certifiedchain.New(t, 3, 3)
	v, err := c.Signer.Verifier()
	require.NoError(t, err)
	pk, err := v.MarshalPublicKey()
	require.NoError(t, err)
	id, err := network.NodeIDFromPublicKeyBytes(pk)
	require.NoError(t, err)
	parent := c.Blocks[1]
	_, tr := c.Certificate(1)
	srv, rpcCalls := sourceServer(t, parent.Hash, parent.Evidence, nil)
	t.Cleanup(srv.Close)
	source, err := NewParentWitnessSource(context.Background(), ParentWitnessPins{
		NetworkID: verifier.NetworkID, PartitionID: verifier.PartitionID, ShardID: verifier.ShardID,
		FullShardConfHash: verifier.GenesisOrigin.FullShardConfHash(), Registry: verifier.GenesisOrigin.ProofContext(),
	}, registrywitness.NewHTTPCaller(srv.URL, time.Second), DefaultParentWitnessBudget())
	require.NoError(t, err)
	t.Cleanup(source.Close)
	return &confEpochChain{t: t, verifier: verifier, chain: c, parent: parent, tr: tr, signerID: id.String(), source: source, rpcCalls: rpcCalls}
}

func (g *confEpochChain) certifyAt(rootRound uint64) *types.UnicityCertificate {
	g.t.Helper()
	uc := g.chain.Certify(g.chain.Signer, g.chain.InputRecord(1), g.tr, rootRound)
	uc.UnicitySeal.NetworkID = g.verifier.NetworkID
	uc.UnicitySeal.Signatures = nil
	require.NoError(g.t, uc.UnicitySeal.Sign(g.signerID, g.chain.Signer))
	return uc
}

func (g *confEpochChain) params(uc *types.UnicityCertificate) shardnode.RoundParams {
	return shardnode.RoundParams{
		Round:                  g.tr.Round,
		Parent:                 shardnode.BlockRef{Number: g.parent.Number, Hash: g.parent.Hash.Bytes(), StateRoot: g.parent.StateRoot.Bytes()},
		AuthorizingCertificate: uc, AuthorizingTechnicalRecord: g.tr,
	}
}

// follower is an adapter over mock engine and eth surfaces; the returned counter is the blocks that reached newPayloadWithSealV1.
func (g *confEpochChain) follower() (*Adapter, *int) {
	g.t.Helper()
	engine, eth := newMockReth(g.t, Secret{}), newMockReth(g.t, Secret{})
	sealCalls := new(int)
	engine.on("engine_newPayloadWithSealV1", func(json.RawMessage) (any, *rpcError) {
		*sealCalls++
		return PayloadStatusV1{Status: PayloadStatusValid}, nil
	})
	eth.on("eth_getBlockByHash", func(json.RawMessage) (any, *rpcError) {
		return blockHeaderJSON{Number: quantity(g.parent.Number), Hash: data32(g.parent.Hash), Timestamp: 0}, nil
	})
	a, closeFn := newTestAdapterWithVerifier(g.t, engine, eth, g.verifier)
	g.t.Cleanup(closeFn)
	a.parentWitness = g.source
	return a, sealCalls
}

// block is what an honest leader disseminates for a round authorized by uc.
func (g *confEpochChain) block(a *Adapter, uc *types.UnicityCertificate) shardnode.Block {
	g.t.Helper()
	derived, err := a.deriveV2(context.Background(), g.params(uc), uc, g.tr)
	require.NoError(g.t, err)
	attrs := DeriveAttributesV2(derived.Input, ParentHeader{}, a.feeCollector)
	payload := samplePayload()
	payload.ParentHash = data32(g.parent.Hash)
	payload.BlockNumber = quantity(g.parent.Number + 1)
	payload.Timestamp, payload.PrevRandao, payload.FeeRecipient, payload.Withdrawals = attrs.Timestamp, attrs.PrevRandao, attrs.SuggestedFeeRecipient, attrs.Withdrawals
	payload.ExtraData = derived.Commitment[:]
	witnesses, err := encodeSealCompanionWitnesses(uc, g.tr)
	require.NoError(g.t, err)
	b, err := EncodeBlockWithSealCompanion(payload, &SealCompanion{RootInput: derived.Encoded, Witnesses: witnesses, Provenance: "build"})
	require.NoError(g.t, err)
	return b
}

// With the per-epoch set installed, the adapter authenticates a certificate under exactly the configuration
// installed for the shard epoch its technical record names (X1 row X-48). There is no scan of other
// installed configurations: the right epoch is accepted, another epoch's configuration is refused as
// unauthenticated, and an epoch with nothing installed is refused as unknown, whatever else is installed.
// Build and Verify are both checked; the certificate and the block are the same in every case.
func TestAdapterV2AuthenticatesUnderTheCertificatesOwnShardEpochConfiguration(t *testing.T) {
	other := bytes.Repeat([]byte{0x5a}, 32)
	for _, tc := range []struct {
		name string
		set  func(genesis []byte) map[uint64][]byte
		want error // nil: accepted
		not  error
	}{
		{"the installed configuration of its epoch", func(g []byte) map[uint64][]byte { return map[uint64][]byte{0: g} }, nil, nil},
		{"epoch 0 holds another configuration", func(g []byte) map[uint64][]byte { return map[uint64][]byte{0: other} }, rootinput.ErrUnauthenticated, rootinput.ErrConfEpochUnknown},
		{"the right configuration is installed only for another epoch", func(g []byte) map[uint64][]byte { return map[uint64][]byte{1: g, 2: other} }, rootinput.ErrConfEpochUnknown, rootinput.ErrUnauthenticated},
		{"nothing installed", func(g []byte) map[uint64][]byte { return map[uint64][]byte{} }, rootinput.ErrConfEpochUnknown, rootinput.ErrUnauthenticated},
	} {
		t.Run(tc.name, func(t *testing.T) {
			verifier, params, want := bootstrapAdapterFixture(t)
			resolver := &confResolver{byEpoch: tc.set(verifier.ShardConfHash)}
			verifier.SetConfForEpoch(resolver.lookup)
			engine, eth := newMockReth(t, Secret{}), newMockReth(t, Secret{})
			sealCalls := 0
			payloadID := data{1, 2, 3, 4, 5, 6, 7, 8}
			engine.on("engine_forkchoiceUpdatedWithSealV1", func(json.RawMessage) (any, *rpcError) {
				return ForkchoiceUpdatedResponse{PayloadStatus: PayloadStatusV1{Status: PayloadStatusValid}, PayloadID: &payloadID}, nil
			})
			engine.on("engine_newPayloadWithSealV1", func(json.RawMessage) (any, *rpcError) {
				sealCalls++
				return PayloadStatusV1{Status: PayloadStatusValid}, nil
			})
			eth.on("eth_getBlockByHash", func(json.RawMessage) (any, *rpcError) {
				return blockHeaderJSON{Number: 0, Hash: data32(verifier.GenesisOrigin.BlockHash()), Timestamp: 0}, nil
			})
			a, closeFn := newTestAdapterWithVerifier(t, engine, eth, verifier)
			defer closeFn()
			attrs := DeriveAttributesV2(want.Input, ParentHeader{}, a.feeCollector)
			payload := samplePayload()
			payload.ParentHash = data32(verifier.GenesisOrigin.BlockHash())
			payload.BlockNumber = 1
			payload.Timestamp, payload.PrevRandao, payload.FeeRecipient, payload.Withdrawals = attrs.Timestamp, attrs.PrevRandao, attrs.SuggestedFeeRecipient, attrs.Withdrawals
			payload.ExtraData = want.Commitment[:]
			witnesses, err := encodeSealCompanionWitnesses(params.AuthorizingCertificate, params.AuthorizingTechnicalRecord)
			require.NoError(t, err)
			block, err := EncodeBlockWithSealCompanion(payload, &SealCompanion{RootInput: want.Encoded, Witnesses: witnesses, Provenance: "build"})
			require.NoError(t, err)

			_, buildErr := a.Build(context.Background(), params)
			status, verifyErr := a.Verify(context.Background(), block, params)
			if tc.want == nil {
				require.NoError(t, buildErr)
				require.NoError(t, verifyErr)
				require.Equal(t, shardnode.StatusValid, status)
				require.Equal(t, 1, sealCalls)
				return
			}
			require.ErrorIs(t, buildErr, tc.want)
			require.NotErrorIs(t, buildErr, tc.not)
			require.ErrorIs(t, verifyErr, tc.want)
			require.NotErrorIs(t, verifyErr, tc.not)
			require.Equal(t, shardnode.StatusInvalid, status)
			require.Zero(t, sealCalls, "a refused block never reaches the execution client")
		})
	}
}

// X1 row X-48 (#12 acceptance), at the adapter: a follower's Verify of one block costs one trust-base lookup,
// one configuration lookup and one parent-witness RPC, and allocates the same, however many assignments are
// installed and however many root rounds the certificate skipped. The installed history is `history`
// configurations in the per-epoch set and as many handoff transitions in the verifier, and the certificate is
// authorized `gap` root rounds after the parent's cursor. Counts and allocations, never time.
func TestAdapterV2ImportWorkDoesNotGrowWithSkippedRoundsOrInstalledHistory(t *testing.T) {
	type measure struct {
		trustLookups, confLookups int
		rpcCalls                  int32
		allocs                    float64
	}
	run := func(t *testing.T, history int, gap uint64) measure {
		g := newConfEpochChain(t)
		resolver := &confResolver{byEpoch: map[uint64][]byte{0: g.verifier.ShardConfHash}}
		g.verifier.transitions = map[uint64]handoff.EVMTransition{}
		for e := 1; e < history; e++ {
			var h [32]byte
			h[0], h[1], h[2] = byte(e), byte(e>>8), 0xee
			resolver.byEpoch[uint64(e)] = h[:]
			g.verifier.transitions[uint64(e)] = handoff.EVMTransition{OldRootEpoch: uint64(e), NewRootEpoch: uint64(e) + 1, OldActiveConfHash: h, NewActiveConfHash: h}
		}
		g.verifier.SetConfForEpoch(resolver.lookup)
		trust := &countingTrust{inner: g.verifier.TrustBases}
		g.verifier.TrustBases = trust
		uc := g.certifyAt(5 + gap)
		a, sealCalls := g.follower()
		block := g.block(a, uc)
		params := g.params(uc)

		status, err := a.Verify(context.Background(), block, params) // warms the parent snapshot
		require.NoError(t, err)
		require.Equal(t, shardnode.StatusValid, status)
		var m measure
		trust.calls, resolver.calls = 0, 0
		before := g.rpcCalls.Load()
		status, err = a.Verify(context.Background(), block, params)
		require.NoError(t, err)
		require.Equal(t, shardnode.StatusValid, status)
		m.trustLookups, m.confLookups, m.rpcCalls = trust.calls, resolver.calls, g.rpcCalls.Load()-before
		m.allocs = testing.AllocsPerRun(20, func() { _, _ = a.Verify(context.Background(), block, params) })
		require.Equal(t, 2+21, *sealCalls, "every import reached the execution client once (warm-up, counted, and AllocsPerRun's 21 runs)")
		return m
	}

	base := run(t, 1, 0)
	require.Equal(t, 1, base.trustLookups, "one trust-base lookup: the certificate's root epoch")
	require.Equal(t, 1, base.confLookups, "one configuration lookup: the certificate's shard epoch")
	for _, tc := range []struct {
		name    string
		history int
		gap     uint64
		slack   float64 // wider round numbers encode into a few more allocations, a constant: a scan of 2048 entries would add thousands
	}{
		{"a long installed history", 2048, 0, 2},
		{"a million skipped root rounds", 1, 1_000_000, 16},
		{"both", 2048, 1_000_000_000, 16},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := run(t, tc.history, tc.gap)
			require.Equal(t, base.trustLookups, got.trustLookups)
			require.Equal(t, base.confLookups, got.confLookups)
			require.Equal(t, base.rpcCalls, got.rpcCalls)
			require.InDelta(t, base.allocs, got.allocs, tc.slack, "allocations per import must not depend on history or the gap")
		})
	}
}
