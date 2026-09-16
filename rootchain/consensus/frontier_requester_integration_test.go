package consensus

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	libp2p "github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/certifiedstore"
	"github.com/unicitynetwork/bft-core/configuredprogress"
	"github.com/unicitynetwork/bft-core/registrygenesis"
	"github.com/unicitynetwork/bft-core/registryproof"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/frontierclient"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/frontierrequester"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/frontiertransport"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/internal/frontiercodec"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	rctest "github.com/unicitynetwork/bft-core/rootchain/testutils"
	"github.com/unicitynetwork/bft-core/rootinput"
	"github.com/unicitynetwork/bft-go-base/types"
)

type requesterAdmissionTrust struct{ trust *types.RootTrustBaseV1 }

func (t requesterAdmissionTrust) GetByEpoch(context.Context, uint64) (*types.RootTrustBaseV1, error) {
	return t.trust, nil
}

type requesterAdmissionGate struct{}

func (requesterAdmissionGate) WithinFinality(ctx context.Context, f func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return f()
}

func TestFrontierRequesterRealManagersAndCommittedCutEndToEnd(t *testing.T) {
	runFrontierRequesterIntegration(t, "late-network")
}

func TestReviewReceiptRejectsOrdinaryThroughNormalAdmission(t *testing.T) {
	runFrontierRequesterIntegration(t, "normal-admission")
}

func TestReviewReceiptRejectsClosedAdmission(t *testing.T) {
	runFrontierRequesterIntegration(t, "closed-admission")
}

func runFrontierRequesterIntegration(t *testing.T, scenario string) {
	t.Helper()
	shardNodes, shardInfos := rctest.CreateTestNodes(t, 1)
	var origin registrygenesis.GenesisOrigin
	cms, _ := createConsensusManagersWithPDR(t, 4, shardInfos, func(tb *types.RootTrustBaseV1) []Option {
		return []Option{WithFrontierSampler(FrontierSamplerConfig{TrustBase: tb, QueueSize: 2, MaxPending: 4}), WithFrontierSigning()}
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
	originIdentity := origin.Identity().Bytes()
	contextValue := frontiercodec.Context{NetworkID: pdr.NetworkID, PartitionID: pdr.PartitionID, CanonicalShardBytes: pdr.ShardID.Bytes(), FullShardConfHash: conf, RootEpoch: cms[0].frontier.trust.Epoch, GenesisOriginIdentity: originIdentity}
	for _, cm := range cms {
		manager := cm
		require.Eventually(t, func() bool {
			probeCtx, probeCancel := context.WithTimeout(context.Background(), time.Second)
			defer probeCancel()
			_, probeErr := manager.SampleSignedFrontier(probeCtx, SignedFrontierRequest{FrontierRequest: FrontierRequest{NetworkID: contextValue.NetworkID, PartitionID: contextValue.PartitionID, ShardID: pdr.ShardID, FullShardConfHash: conf}, RootEpoch: contextValue.RootEpoch, GenesisOriginIdentity: originIdentity, Nonce: bytes.Repeat([]byte{0xd2}, 32)})
			return probeErr == nil
		}, 5*time.Second, 20*time.Millisecond)
	}

	clientHost, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, clientHost.Close()) })
	rootHosts := make([]host.Host, len(cms))
	servers := make([]*frontiertransport.Server, len(cms))
	savedInitialPairs := make([][]byte, len(cms))
	var stalePhase atomic.Bool
	staleReady := make(chan struct{}, 3)
	releaseStale, releaseOrdinary := make(chan struct{}), make(chan struct{})
	var releaseStaleOnce, releaseOrdinaryOnce sync.Once
	t.Cleanup(func() {
		releaseStaleOnce.Do(func() { close(releaseStale) })
		releaseOrdinaryOnce.Do(func() { close(releaseOrdinary) })
	})
	limits := frontiertransport.Limits{Deadline: 5 * time.Second, MaxEligiblePeers: 1, MaxPendingStreams: 2, MaxPendingStreamsPerPeer: 1, RequestsPerSecond: 16, Burst: 4}
	for i, cm := range cms {
		rootHosts[i], err = libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
		require.NoError(t, err)
		rootHost := rootHosts[i]
		t.Cleanup(func() { require.NoError(t, rootHost.Close()) })
		manager := cm
		index := i
		server, serverErr := frontiertransport.NewServer(ctx, []peer.ID{clientHost.ID()}, limits, frontiertransport.Handlers{
			Frontier: func(callCtx context.Context, request frontiertransport.FrontierRequest) ([]byte, error) {
				shard, decodeErr := shardFromCanonicalBytes(request.Context.CanonicalShardBytes)
				if decodeErr != nil {
					return nil, decodeErr
				}
				response, sampleErr := manager.SampleSignedFrontier(callCtx, SignedFrontierRequest{FrontierRequest: FrontierRequest{NetworkID: request.Context.NetworkID, PartitionID: request.Context.PartitionID, ShardID: shard, FullShardConfHash: request.Context.FullShardConfHash}, RootEpoch: request.Context.RootEpoch, GenesisOriginIdentity: request.Context.GenesisOriginIdentity, Nonce: request.Nonce})
				if sampleErr != nil {
					return nil, sampleErr
				}
				raw := response.CanonicalBytes()
				var wire frontiercodec.Reply
				if decodeErr = types.Cbor.Unmarshal(raw, &wire); decodeErr != nil {
					return nil, decodeErr
				}
				if !stalePhase.Load() {
					savedInitialPairs[index] = bytes.Clone(wire.Pair)
					return raw, nil
				}
				if index == len(cms)-1 {
					select {
					case <-releaseOrdinary:
						return raw, nil
					case <-callCtx.Done():
						return nil, callCtx.Err()
					}
				}
				var pair frontiercodec.Pair
				if decodeErr = types.Cbor.Unmarshal(savedInitialPairs[index], &pair); decodeErr != nil {
					return nil, decodeErr
				}
				pairID, decodeErr := frontiercodec.PairIdentity(pair, request.Context)
				if decodeErr != nil {
					return nil, decodeErr
				}
				qcDigest := sha256.Sum256(wire.QC)
				preimage, decodeErr := types.Cbor.Marshal(frontiercodec.SigningPreimage{Domain: frontiercodec.SigningDomain, Version: 1, Context: request.Context, Nonce: request.Nonce, Author: manager.id.String(), PairID: pairID[:], QCDigest: qcDigest[:]})
				if decodeErr != nil {
					return nil, decodeErr
				}
				wire.Pair = bytes.Clone(savedInitialPairs[index])
				wire.Signature, decodeErr = manager.frontier.signer.SignBytes(preimage)
				if decodeErr != nil {
					return nil, decodeErr
				}
				staleReady <- struct{}{}
				select {
				case <-releaseStale:
					return types.Cbor.Marshal(wire)
				case <-callCtx.Done():
					return nil, callCtx.Err()
				}
			},
			Cut: func(callCtx context.Context, request frontiertransport.CutRequest) ([]byte, error) {
				shard, decodeErr := shardFromCanonicalBytes(request.Context.CanonicalShardBytes)
				if decodeErr != nil {
					return nil, decodeErr
				}
				var cut *storage.FrontierCutSnapshot
				for {
					cut, decodeErr = manager.blockStore.ReadFrontierCutSnapshot(request.Context.PartitionID, shard)
					if decodeErr == nil && cut.RootRound >= request.Floor {
						break
					}
					select {
					case <-callCtx.Done():
						return nil, fmt.Errorf("committed cut below requested hint: %w", callCtx.Err())
					case <-time.After(10 * time.Millisecond):
					}
				}
				var binding [32]byte
				copy(binding[:], request.AcquisitionBinding)
				return frontiercodec.EncodeCutProof(binding, cut.RootRound, cut.RootEpoch, cut.RootHash, cut.CommitQC, frontiercodec.Pair{UC: &cut.LastCR.UC, TR: &cut.LastCR.Technical}, cut.ShardTreeCertificate, cut.UnicityTreeCertificate)
			},
		})
		require.NoError(t, serverErr)
		servers[i] = server
		rootHosts[i].SetStreamHandler(protocol.ID(frontiertransport.FrontierProtocolID), server.FrontierHandler)
		rootHosts[i].SetStreamHandler(protocol.ID(frontiertransport.CutProtocolID), server.CutHandler)
	}
	t.Cleanup(func() {
		for _, server := range servers {
			server.Close()
		}
	})
	for _, rootHost := range rootHosts {
		require.NoError(t, clientHost.Connect(ctx, peer.AddrInfo{ID: rootHost.ID(), Addrs: rootHost.Addrs()}))
	}

	progressStore, err := configuredprogress.OpenConfiguredV2(t.TempDir()+"/requester-progress.db", configuredprogress.Settings{Retain: 2})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, progressStore.Close()) })
	trust := requesterAdmissionTrust{cms[0].frontier.trust}
	progressContext := configuredprogress.Context{Origin: origin, Observation: rootinput.ObservationContextV2{NetworkID: pdr.NetworkID, PartitionID: pdr.PartitionID, ShardID: pdr.ShardID, ShardConfHash: conf, RootEpoch: contextValue.RootEpoch, TrustBases: trust}, Record: certifiedstore.Context{NetworkID: pdr.NetworkID, PartitionID: pdr.PartitionID, ShardID: pdr.ShardID, FullShardConfHash: conf, Registry: origin.ProofContext(), TrustBases: trust}}
	_, _, err = progressStore.Initialize(context.Background(), progressContext)
	require.NoError(t, err)
	admission, err := configuredprogress.NewAdmissionCoordinator(ctx, configuredprogress.AdmissionConfig{Store: progressStore, Context: progressContext, Gate: requesterAdmissionGate{}, Invalidate: func() {}, Deliver: func(context.Context, rootinput.VerifiedObservationV2) error { return nil }})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, admission.Close()) })
	peers := make([]frontierrequester.RootPeer, len(rootHosts))
	for i, rootHost := range rootHosts {
		peers[i] = frontierrequester.RootPeer{Author: cms[i].id.String(), PeerID: rootHost.ID()}
	}
	requester, err := frontierrequester.New(frontierrequester.Config{Process: ctx, Profile: frontierclient.Profile{TrustBase: cms[0].frontier.trust, NetworkID: pdr.NetworkID, PartitionID: pdr.PartitionID, ShardID: pdr.ShardID, FullShardConfHash: conf, RootEpoch: contextValue.RootEpoch, GenesisOriginIdentity: originIdentity}, Peers: peers, Opener: frontierHostOpener{clientHost}, Admission: admission})
	require.NoError(t, err)
	acquisitionCtx, acquisitionCancel := context.WithCancel(context.Background())
	result := requester.Acquire(acquisitionCtx)
	require.NoError(t, result.Err)
	require.True(t, result.Receipt.Valid())
	replacementCtx, replacementCancel := context.WithCancel(context.Background())
	replacement := requester.Acquire(replacementCtx)
	require.NoError(t, replacement.Err)
	require.True(t, replacement.Receipt.Valid())
	require.ErrorIs(t, requester.Validate(result.Receipt), frontierrequester.ErrInvalidated, "a successful replacement must invalidate old receipt copies")
	resolved, err := requester.Resolve(replacement.Receipt)
	require.NoError(t, err)
	require.NotNil(t, resolved.UC)
	require.NotNil(t, resolved.TR)
	require.NotZero(t, resolved.CutRoot)
	require.NotZero(t, resolved.CutRound)
	wantRound := resolved.UC.InputRecord.RoundNumber
	resolved.UC.InputRecord.RoundNumber++
	resolvedAgain, err := requester.Resolve(replacement.Receipt)
	require.NoError(t, err)
	require.Equal(t, wantRound, resolvedAgain.UC.InputRecord.RoundNumber, "resolved evidence must be owned")
	acquisitionCancel()
	require.True(t, replacement.Receipt.Valid(), "replacement has an independent caller lifetime")
	defer replacementCancel()
	if scenario == "late-network" {
		replacementCancel()
		require.ErrorIs(t, requester.Validate(replacement.Receipt), frontierrequester.ErrInvalidated)
		_, err = requester.Resolve(replacement.Receipt)
		require.ErrorIs(t, err, frontierrequester.ErrInvalidated)
	}
	if scenario == "closed-admission" {
		require.True(t, replacement.Receipt.Valid())
		require.NoError(t, admission.Close())
		require.ErrorIs(t, requester.Validate(replacement.Receipt), frontierrequester.ErrInvalidated)
		_, err = requester.Resolve(replacement.Receipt)
		require.ErrorIs(t, err, frontierrequester.ErrInvalidated)
		require.ErrorIs(t, requester.Acquire(context.Background()).Err, frontierrequester.ErrInvalidated)
		return
	}

	si, err := cms[0].ShardInfo(partitionID, shardID)
	require.NoError(t, err)
	require.NoError(t, cms[0].RequestCertification(context.Background(), IRChangeRequest{Partition: partitionID, Shard: shardID, Reason: Quorum, Requests: buildBlockCertificationRequest(t, shardNodes, si.LastCR)}))
	require.Eventually(t, func() bool {
		response, sampleErr := cms[0].SampleSignedFrontier(context.Background(), SignedFrontierRequest{FrontierRequest: FrontierRequest{NetworkID: pdr.NetworkID, PartitionID: pdr.PartitionID, ShardID: pdr.ShardID, FullShardConfHash: conf}, RootEpoch: contextValue.RootEpoch, GenesisOriginIdentity: originIdentity, Nonce: bytes.Repeat([]byte{0xaa}, 32)})
		if sampleErr != nil {
			return false
		}
		var wire frontiercodec.Reply
		var pair frontiercodec.Pair
		return types.Cbor.Unmarshal(response.CanonicalBytes(), &wire) == nil && types.Cbor.Unmarshal(wire.Pair, &pair) == nil && pair.UC.InputRecord.RoundNumber > 0
	}, 5*time.Second, 20*time.Millisecond)
	if scenario == "normal-admission" {
		require.True(t, replacement.Receipt.Valid(), "receipt must still be live before normal admission learns progress")
		response, sampleErr := cms[0].SampleSignedFrontier(context.Background(), SignedFrontierRequest{FrontierRequest: FrontierRequest{NetworkID: pdr.NetworkID, PartitionID: pdr.PartitionID, ShardID: pdr.ShardID, FullShardConfHash: conf}, RootEpoch: contextValue.RootEpoch, GenesisOriginIdentity: originIdentity, Nonce: bytes.Repeat([]byte{0xaa}, 32)})
		require.NoError(t, sampleErr)
		var wire frontiercodec.Reply
		var pair frontiercodec.Pair
		require.NoError(t, types.Cbor.Unmarshal(response.CanonicalBytes(), &wire))
		require.NoError(t, types.Cbor.Unmarshal(wire.Pair, &pair))
		_, err = admission.Submit(context.Background(), pair.UC, pair.TR)
		require.NoError(t, err)
		require.True(t, admission.Status().BootstrapInvalidated)
		require.ErrorIs(t, requester.Validate(replacement.Receipt), frontierrequester.ErrInvalidated)
		_, err = requester.Resolve(replacement.Receipt)
		require.ErrorIs(t, err, frontierrequester.ErrInvalidated)
		require.ErrorIs(t, requester.Acquire(context.Background()).Err, frontierrequester.ErrInvalidated)
		return
	}
	stalePhase.Store(true)
	ordinaryDone := make(chan frontierrequester.Result, 1)
	go func() { ordinaryDone <- requester.Acquire(context.Background()) }()
	for range 3 {
		select {
		case <-staleReady:
		case <-time.After(2 * time.Second):
			t.Fatal("stale quorum callbacks did not reach the drain gate")
		}
	}
	releaseStaleOnce.Do(func() { close(releaseStale) })
	time.Sleep(50 * time.Millisecond)
	releaseOrdinaryOnce.Do(func() { close(releaseOrdinary) })
	var ordinary frontierrequester.Result
	select {
	case ordinary = <-ordinaryDone:
	case <-time.After(5 * time.Second):
		t.Fatal("requester did not drain late ordinary response")
	}
	require.ErrorIs(t, ordinary.Err, frontierrequester.ErrOrdinary)
	status := admission.Status()
	require.True(t, status.BootstrapInvalidated)
	require.NotEmpty(t, status.FirstOrdinaryPair)
	require.NotEmpty(t, status.LatestOrdinaryPair)

	canceled, cancelImmediately := context.WithCancel(context.Background())
	cancelImmediately()
	require.ErrorIs(t, requester.Acquire(canceled).Err, frontierrequester.ErrInvalidated)

	wrong := frontierclient.Profile{TrustBase: cms[0].frontier.trust, NetworkID: pdr.NetworkID, PartitionID: pdr.PartitionID, ShardID: pdr.ShardID, FullShardConfHash: conf, RootEpoch: contextValue.RootEpoch, GenesisOriginIdentity: bytes.Repeat([]byte{0xee}, 32)}
	_, err = frontierrequester.New(frontierrequester.Config{Process: ctx, Profile: wrong, Peers: peers, Opener: frontierHostOpener{clientHost}, Admission: admission})
	require.ErrorIs(t, err, frontierrequester.ErrSettings)
}
