package configuredadmission

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/certifiedstore"
	"github.com/unicitynetwork/bft-core/configuredprogress"
	"github.com/unicitynetwork/bft-core/internal/testutils/certifiedchain"
	testpeer "github.com/unicitynetwork/bft-core/internal/testutils/peer"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/registrygenesis"
	"github.com/unicitynetwork/bft-core/registryproof"
	"github.com/unicitynetwork/bft-core/rootinput"
	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-go-base/types"
)

type adapterNetwork struct {
	received chan any
}

func (n *adapterNetwork) Send(context.Context, any, ...peer.ID) error { return nil }
func (n *adapterNetwork) ReceivedChannel() <-chan any                 { return n.received }

type adapterSink struct {
	delivered chan *types.UnicityCertificate
}

func (s adapterSink) HandleCertificate(_ context.Context, uc *types.UnicityCertificate, _ *certification.TechnicalRecord) error {
	s.delivered <- uc
	return nil
}

type adapterTrust struct{ tb *types.RootTrustBaseV1 }

func (t adapterTrust) GetByEpoch(context.Context, uint64) (*types.RootTrustBaseV1, error) {
	return t.tb, nil
}

type adapterGate struct{}

func (adapterGate) Hold(context.Context, string) (func(), error) { return func() {}, nil }

func adapterFixture(t *testing.T) (*certifiedchain.Chain, registrygenesis.GenesisOrigin, configuredprogress.Context, shardnode.AdmissionIdentity) {
	t.Helper()
	c := certifiedchain.New(t, 3, 1)
	var doc map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(c.Genesis.GenesisJSON(), &doc))
	var alloc map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(doc["alloc"], &alloc))
	for k := range alloc {
		if strings.EqualFold(strings.TrimPrefix(k, "0x"), strings.TrimPrefix(registryproof.RegistryAddress.Hex(), "0x")) {
			delete(alloc, k)
		}
	}
	doc["alloc"], _ = json.Marshal(alloc)
	source, _ := json.Marshal(doc)
	artifact, err := registrygenesis.PinnedArtifact()
	require.NoError(t, err)
	prepared, err := registrygenesis.PrepareGenesisJSON(certifiedchain.Config(3), c.Pins, artifact, source, registrygenesis.GenesisJSONLimits{})
	require.NoError(t, err)
	origin := prepared.Origin()
	trust := adapterTrust{c.TrustBase}
	obs := rootinput.ObservationContextV2{NetworkID: 3, PartitionID: 8, ShardID: types.ShardID{}, ShardConfHash: origin.FullShardConfHash().Bytes(), RootEpoch: 1, TrustBases: trust}
	record := certifiedstore.Context{NetworkID: 3, PartitionID: 8, ShardID: types.ShardID{}, FullShardConfHash: origin.FullShardConfHash().Bytes(), Registry: origin.ProofContext(), TrustBases: trust}
	ctx := configuredprogress.Context{Origin: origin, Observation: obs, Record: record}
	id := shardnode.AdmissionIdentity{PartitionID: 8, ShardID: types.ShardID{}, FullShardConfHash: origin.FullShardConfHash().Bytes(), TrustBases: trust}
	return c, origin, ctx, id
}

func signAdapterObservation(t *testing.T, c *certifiedchain.Chain) (*types.UnicityCertificate, *certification.TechnicalRecord) {
	t.Helper()
	b := c.Blocks[1]
	ir := &types.InputRecord{Version: 1, RoundNumber: b.Round, Hash: b.StateRoot.Bytes(), SummaryValue: []byte{}, Timestamp: 1_700_000_000 + b.Round, BlockHash: b.Hash.Bytes()}
	tr := certifiedchain.Technical(1)
	tr.Round = 2
	uc := c.Certify(c.Signer, ir, tr, 5)
	uc.UnicitySeal.NetworkID = 3
	uc.UnicitySeal.Signatures = nil
	v, err := c.Signer.Verifier()
	require.NoError(t, err)
	pk, err := v.MarshalPublicKey()
	require.NoError(t, err)
	id, err := network.NodeIDFromPublicKeyBytes(pk)
	require.NoError(t, err)
	require.NoError(t, uc.UnicitySeal.Sign(id.String(), c.Signer))
	return uc, tr
}

func TestAdapterAuthenticatesBeforeFeedAndPersistsBeforeDelivery(t *testing.T) {
	c, origin, progressCtx, id := adapterFixture(t)
	store, err := configuredprogress.OpenConfiguredV2(t.TempDir()+"/progress.db", configuredprogress.Settings{Retain: 2})
	require.NoError(t, err)
	defer store.Close()
	_, _, err = store.Initialize(context.Background(), progressCtx)
	require.NoError(t, err)
	var invalidated atomic.Bool
	feed := make(chan struct{}, 1)
	delivered := make(chan struct{}, 1)
	factory := Factory{Store: store, Origin: origin, Invalidate: func() { invalidated.Store(true) }}
	a, err := factory.Start(context.Background(), id, adapterGate{}, shardnode.AdmissionCallbacks{
		AuthenticatedFeed: func(uc *types.UnicityCertificate, _ *certification.TechnicalRecord) {
			require.NotNil(t, uc)
			st, _, loadErr := store.Load(context.Background(), progressCtx)
			require.NoError(t, loadErr)
			require.Zero(t, st.Revision(), "feed notification precedes persistence")
			feed <- struct{}{}
		},
		DeliverDurable: func(_ context.Context, uc *types.UnicityCertificate, _ *certification.TechnicalRecord) error {
			st, _, loadErr := store.Load(context.Background(), progressCtx)
			require.NoError(t, loadErr)
			observed, ok := st.Observed()
			require.True(t, ok)
			require.Equal(t, observed.Certificate().GetRoundNumber(), uc.GetRoundNumber())
			delivered <- struct{}{}
			return nil
		},
	})
	require.NoError(t, err)
	defer a.Close()
	uc, tr := signAdapterObservation(t, c)
	require.NoError(t, a.Submit(context.Background(), uc, tr))
	select {
	case <-feed:
	case <-time.After(2 * time.Second):
		t.Fatal("authenticated feed callback missing")
	}
	require.True(t, invalidated.Load())
	select {
	case <-delivered:
	case <-time.After(3 * time.Second):
		t.Fatal("durable delivery callback missing")
	}
}

func TestAdapterRejectsClientIdentityMismatch(t *testing.T) {
	_, origin, progressCtx, id := adapterFixture(t)
	store, err := configuredprogress.OpenConfiguredV2(t.TempDir()+"/progress.db", configuredprogress.Settings{Retain: 2})
	require.NoError(t, err)
	defer store.Close()
	_, _, err = store.Initialize(context.Background(), progressCtx)
	require.NoError(t, err)
	id.FullShardConfHash = bytes.Repeat([]byte{0xff}, 32)
	_, err = (Factory{Store: store, Origin: origin, Invalidate: func() {}}).Start(context.Background(), id, adapterGate{}, shardnode.AdmissionCallbacks{AuthenticatedFeed: func(*types.UnicityCertificate, *certification.TechnicalRecord) {}, DeliverDurable: func(context.Context, *types.UnicityCertificate, *certification.TechnicalRecord) error { return nil }})
	require.ErrorContains(t, err, "does not match")
}

func TestAdapterComposesWithBFTClientPreLUCBoundary(t *testing.T) {
	chain, origin, progressCtx, _ := adapterFixture(t)
	store, err := configuredprogress.OpenConfiguredV2(t.TempDir()+"/progress.db", configuredprogress.Settings{Retain: 2})
	require.NoError(t, err)
	defer store.Close()
	_, _, err = store.Initialize(context.Background(), progressCtx)
	require.NoError(t, err)

	net := &adapterNetwork{received: make(chan any, 1)}
	sink := adapterSink{delivered: make(chan *types.UnicityCertificate, 1)}
	p := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	client, err := shardnode.NewBFTClient(p, net, chain.Signer, 8, types.ShardID{}, origin.FullShardConfHash().Bytes(), adapterTrust{chain.TrustBase}, nil, nil, shardnode.DefaultBFTClientOptions)
	require.NoError(t, err)
	require.NoError(t, client.SetCertificateAdmission(Factory{Store: store, Origin: origin, Invalidate: func() {}}, adapterGate{}, sink))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx) }()
	uc, tr := signAdapterObservation(t, chain)
	net.received <- &certification.CertificationResponse{Partition: 8, Shard: types.ShardID{}, UC: *uc, Technical: *tr}
	select {
	case got := <-sink.delivered:
		require.Equal(t, uc.GetRoundNumber(), got.GetRoundNumber())
	case <-time.After(3 * time.Second):
		t.Fatal("configured durable delivery missing")
	}
	state, _, err := store.Load(context.Background(), progressCtx)
	require.NoError(t, err)
	observed, ok := state.Observed()
	require.True(t, ok)
	require.Equal(t, uc.GetRoundNumber(), observed.Certificate().GetRoundNumber())
	cancel()
	require.ErrorIs(t, <-done, context.Canceled)
}
