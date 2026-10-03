package consensus

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	libp2p "github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	libnetwork "github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/certifiedstore"
	"github.com/unicitynetwork/bft-core/configuredadmission"
	"github.com/unicitynetwork/bft-core/configuredprogress"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/registrygenesis"
	"github.com/unicitynetwork/bft-core/registryproof"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/frontiertransport"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/internal/frontiercodec"
	rctest "github.com/unicitynetwork/bft-core/rootchain/testutils"
	"github.com/unicitynetwork/bft-core/rootinput"
	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-go-base/types"
)

// activationOpener dials the root hosts by their consensus node IDs (the test's libp2p hosts have their own
// identities) and can hold every exchange until released, which makes "no receipt yet" deterministic.
type activationOpener struct {
	from  host.Host
	hosts map[peer.ID]peer.ID
	mu    sync.Mutex
	hold  chan struct{}
	calls atomic.Int32
}

func (o *activationOpener) CreateStream(ctx context.Context, to peer.ID, id string) (libnetwork.Stream, error) {
	o.calls.Add(1)
	o.mu.Lock()
	hold := o.hold
	o.mu.Unlock()
	if hold != nil {
		select {
		case <-hold:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return o.from.NewStream(ctx, o.hosts[to], protocol.ID(id))
}

func (o *activationOpener) holdExchanges() chan struct{} {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.hold = make(chan struct{})
	return o.hold
}

type activationGate struct{}

func (activationGate) Hold(context.Context, string) (func(), error) { return func() {}, nil }

// The whole default-startup path with real roots: each root serves through the production handlers, the shard
// side starts through the production journal admission, and readiness follows the receipt, its absence after a
// restart, and ordinary supersession.
func TestFreshnessActivationEndToEndWithProductionServing(t *testing.T) {
	shardNodes, shardInfos := rctest.CreateTestNodes(t, 1)
	var origin registrygenesis.GenesisOrigin
	cms, _ := createConsensusManagersWithPDR(t, 4, shardInfos, func(tb *types.RootTrustBaseV1) []Option {
		return []Option{WithFrontierSampler(DefaultFrontierSamplerConfig(tb)), WithFrontierSigning()}
	}, nil, func(pdr *types.PartitionDescriptionRecord) {
		pdr.PartitionParams = map[string]string{registrygenesis.ChainIDParam: "1337"}
		artifact, prepareErr := registrygenesis.PinnedArtifact()
		require.NoError(t, prepareErr)
		pins := registrygenesis.Pins{RootEpoch: 1, RegistryCodeHash: artifact.CodeHash, SystemAddress: registrygenesis.SystemAddress, RegistryAddress: registryproof.RegistryAddress}
		generated, prepareErr := registrygenesis.Generate(pdr, pins, artifact, registrygenesis.DefaultEVMParams)
		require.NoError(t, prepareErr)
		var doc map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(generated.GenesisJSON(), &doc))
		var alloc map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(doc["alloc"], &alloc))
		for key := range alloc {
			if strings.EqualFold(strings.TrimPrefix(key, "0x"), strings.TrimPrefix(registryproof.RegistryAddress.Hex(), "0x")) {
				delete(alloc, key)
			}
		}
		doc["alloc"], _ = json.Marshal(alloc)
		source, _ := json.Marshal(doc)
		prepared, prepareErr := registrygenesis.PrepareGenesisJSON(pdr, pins, artifact, source, registrygenesis.GenesisJSONLimits{})
		require.NoError(t, prepareErr)
		full, prepareErr := prepared.FullConfig()
		require.NoError(t, prepareErr)
		*pdr = *full
		origin = prepared.Origin()
	})
	ctx, cancel := context.WithCancel(context.Background())
	var running atomic.Int32
	for _, cm := range cms {
		running.Add(1)
		go func() { defer running.Add(-1); _ = cm.Run(ctx) }()
	}
	t.Cleanup(func() {
		cancel()
		require.Eventually(t, func() bool { return running.Load() == 0 }, 3*time.Second, 20*time.Millisecond)
	})
	require.Eventually(t, func() bool { return cms[0].pacemaker.GetCurrentRound() >= 5 }, 5*time.Second, 20*time.Millisecond)
	pdr, err := cms[0].orchestration.ShardConfig(partitionID, shardID, 1)
	require.NoError(t, err)
	conf, err := pdr.Hash(crypto.SHA256)
	require.NoError(t, err)
	trust := cms[0].frontier.trust

	clientHost, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, clientHost.Close()) })
	opener := &activationOpener{from: clientHost, hosts: map[peer.ID]peer.ID{}}
	for _, cm := range cms {
		rootHost, hostErr := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
		require.NoError(t, hostErr)
		t.Cleanup(func() { require.NoError(t, rootHost.Close()) })
		handlers, handlersErr := cm.FrontierHandlers()
		require.NoError(t, handlersErr)
		server, serverErr := frontiertransport.NewServer(ctx, []peer.ID{clientHost.ID()}, DefaultFrontierServerLimits(), handlers)
		require.NoError(t, serverErr)
		t.Cleanup(server.Close)
		rootHost.SetStreamHandler(protocol.ID(frontiertransport.FrontierProtocolID), server.FrontierHandler)
		rootHost.SetStreamHandler(protocol.ID(frontiertransport.CutProtocolID), server.CutHandler)
		require.NoError(t, clientHost.Connect(ctx, peer.AddrInfo{ID: rootHost.ID(), Addrs: rootHost.Addrs()}))
		opener.hosts[cm.id] = rootHost.ID()
	}

	adm := requesterAdmissionTrust{trust}
	progress := configuredprogress.Context{Origin: origin, Observation: rootinput.ObservationContextV2{NetworkID: pdr.NetworkID, PartitionID: pdr.PartitionID, ShardID: pdr.ShardID, ShardConfHash: conf, RootEpoch: trust.Epoch, TrustBases: adm}, Record: certifiedstore.Context{NetworkID: pdr.NetworkID, PartitionID: pdr.PartitionID, ShardID: pdr.ShardID, FullShardConfHash: conf, Registry: origin.ProofContext(), TrustBases: adm}}
	store, err := configuredprogress.OpenConfiguredV2(t.TempDir()+"/journal.db", configuredprogress.Settings{Retain: 2})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	_, _, err = store.Initialize(context.Background(), progress)
	require.NoError(t, err)
	limits := configuredprogress.JournalLimits{Candidates: 2, Observations: 3, Bytes: 16 << 20}
	require.NoError(t, store.EnableJournal(context.Background(), progress, limits))
	id := shardnode.AdmissionIdentity{PartitionID: pdr.PartitionID, ShardID: pdr.ShardID, FullShardConfHash: conf, TrustBases: adm}
	callbacks := shardnode.AdmissionCallbacks{
		AuthenticatedFeed: func(*types.UnicityCertificate, *certification.TechnicalRecord) {},
		DeliverDurable:    func(context.Context, *types.UnicityCertificate, *certification.TechnicalRecord) error { return nil },
	}
	start := func(runCtx context.Context) (*configuredadmission.Freshness, shardnode.CertificateAdmission) {
		f := &configuredadmission.Freshness{Opener: opener, TrustBase: trust}
		a, startErr := (configuredadmission.JournalFactory{Store: store, Origin: origin, Limits: limits, Freshness: f}).Start(runCtx, id, activationGate{}, callbacks)
		require.NoError(t, startErr)
		return f, a
	}

	// 1. Starting the admission is all it takes: the receipt is acquired from the roots, with no operator input.
	runCtx, stopRun := context.WithCancel(context.Background())
	freshness, admission := start(runCtx)
	require.Eventually(t, func() bool { return freshness.Require() == nil }, 20*time.Second, 20*time.Millisecond, "the receipt must be acquired automatically")
	status, ok := freshness.Status()
	require.True(t, ok)
	require.False(t, status.Invalidated)

	// 2. A restart restores nothing: with the roots held back there is no receipt, however recent the last one was.
	stopRun()
	require.NoError(t, admission.Close())
	release := opener.holdExchanges()
	restartCtx, stopRestart := context.WithCancel(context.Background())
	t.Cleanup(stopRestart)
	restarted, restartedAdmission := start(restartCtx)
	t.Cleanup(func() { _ = restartedAdmission.Close() })
	require.ErrorIs(t, restarted.Require(), configuredadmission.ErrFreshnessRequired)
	time.Sleep(100 * time.Millisecond)
	require.ErrorIs(t, restarted.Require(), configuredadmission.ErrFreshnessRequired)
	close(release)
	require.Eventually(t, func() bool { return restarted.Require() == nil }, 20*time.Second, 20*time.Millisecond, "the restarted process acquires its own receipt")

	// 3. Ordinary progress observed through the admission supersedes bootstrap for good.
	si, err := cms[0].ShardInfo(partitionID, shardID)
	require.NoError(t, err)
	require.NoError(t, cms[0].RequestCertification(context.Background(), IRChangeRequest{Partition: partitionID, Shard: shardID, Reason: Quorum, Requests: buildBlockCertificationRequest(t, shardNodes, si.LastCR)}))
	var ordinary *SignedFrontierResponse
	require.Eventually(t, func() bool {
		response, sampleErr := cms[0].SampleSignedFrontier(context.Background(), SignedFrontierRequest{FrontierRequest: FrontierRequest{NetworkID: pdr.NetworkID, PartitionID: pdr.PartitionID, ShardID: pdr.ShardID, FullShardConfHash: conf}, RootEpoch: trust.Epoch, GenesisOriginIdentity: origin.Identity().Bytes(), Nonce: bytes.Repeat([]byte{0xaa}, 32)})
		if sampleErr != nil {
			return false
		}
		var wire frontiercodec.Reply
		var pair frontiercodec.Pair
		if types.Cbor.Unmarshal(response.CanonicalBytes(), &wire) != nil || types.Cbor.Unmarshal(wire.Pair, &pair) != nil || pair.UC.InputRecord.RoundNumber == 0 {
			return false
		}
		ordinary = response
		return true
	}, 5*time.Second, 20*time.Millisecond)
	var wire frontiercodec.Reply
	var pair frontiercodec.Pair
	require.NoError(t, types.Cbor.Unmarshal(ordinary.CanonicalBytes(), &wire))
	require.NoError(t, types.Cbor.Unmarshal(wire.Pair, &pair))
	before := restarted
	require.NoError(t, before.Require())
	err = restartedAdmission.Submit(context.Background(), pair.UC, pair.TR)
	require.ErrorIs(t, err, configuredprogress.ErrUnavailable, "the journal has no bootstrap certificate to continue from, so nothing is written")
	require.False(t, errors.Is(err, configuredadmission.ErrFreshnessRequired))
	status, ok = restarted.Status()
	require.True(t, ok)
	require.True(t, status.Invalidated, "learning ordinary progress ends bootstrap even though its write failed")
	require.NoError(t, restarted.Require(), "ordinary progress needs no bootstrap receipt")
}
