package consensus

import (
	"bytes"
	"context"
	"crypto"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	libp2p "github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	libp2pnetwork "github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/frontierclient"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/frontiertransport"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/internal/frontiercodec"
	rctest "github.com/unicitynetwork/bft-core/rootchain/testutils"
	"github.com/unicitynetwork/bft-go-base/types"
)

type frontierHostOpener struct{ host.Host }

func (h frontierHostOpener) CreateStream(ctx context.Context, to peer.ID, id string) (libp2pnetwork.Stream, error) {
	return h.NewStream(ctx, to, protocol.ID(id))
}

func shardFromCanonicalBytes(raw []byte) (types.ShardID, error) {
	b, err := types.Cbor.Marshal(raw)
	if err != nil {
		return types.ShardID{}, err
	}
	var shard types.ShardID
	if err := types.Cbor.Unmarshal(b, &shard); err != nil {
		return types.ShardID{}, err
	}
	return shard, nil
}

func TestFrontierTransportRealManagersAndCommittedCutEndToEnd(t *testing.T) {
	_, shardInfos := rctest.CreateTestNodes(t, 1)
	cms, _ := createConsensusManagersWithOptions(t, 4, shardInfos, func(tb *types.RootTrustBaseV1) []Option {
		return []Option{WithFrontierSampler(FrontierSamplerConfig{TrustBase: tb, QueueSize: 2, MaxPending: 4}), WithFrontierSigning()}
	}, nil)
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
	origin, nonce := bytes.Repeat([]byte{0xc1}, 32), bytes.Repeat([]byte{0xd2}, 32)
	contextValue := frontiercodec.Context{NetworkID: pdr.NetworkID, PartitionID: pdr.PartitionID, CanonicalShardBytes: pdr.ShardID.Bytes(), FullShardConfHash: conf, RootEpoch: cms[0].frontier.trust.Epoch, GenesisOriginIdentity: origin}
	collector, err := frontierclient.NewCollector(frontierclient.Profile{TrustBase: cms[0].frontier.trust, NetworkID: pdr.NetworkID, PartitionID: pdr.PartitionID, ShardID: pdr.ShardID, FullShardConfHash: conf, RootEpoch: contextValue.RootEpoch, GenesisOriginIdentity: origin, Nonce: nonce})
	require.NoError(t, err)
	for _, cm := range cms {
		manager := cm
		require.Eventually(t, func() bool {
			probeCtx, probeCancel := context.WithTimeout(context.Background(), time.Second)
			defer probeCancel()
			_, probeErr := manager.SampleSignedFrontier(probeCtx, SignedFrontierRequest{FrontierRequest: FrontierRequest{NetworkID: contextValue.NetworkID, PartitionID: contextValue.PartitionID, ShardID: pdr.ShardID, FullShardConfHash: conf}, RootEpoch: contextValue.RootEpoch, GenesisOriginIdentity: origin, Nonce: nonce})
			return probeErr == nil
		}, 5*time.Second, 20*time.Millisecond)
	}

	clientHost, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, clientHost.Close()) })
	rootHosts := make([]host.Host, len(cms))
	servers := make([]*frontiertransport.Server, len(cms))
	limits := frontiertransport.Limits{Deadline: 5 * time.Second, MaxEligiblePeers: 1, MaxPendingStreams: 2, MaxPendingStreamsPerPeer: 1, RequestsPerSecond: 16, Burst: 4}
	for i, cm := range cms {
		rootHosts[i], err = libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
		require.NoError(t, err)
		rootHost := rootHosts[i]
		t.Cleanup(func() { require.NoError(t, rootHost.Close()) })
		manager := cm
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
				return response.CanonicalBytes(), nil
			},
			Cut: func(_ context.Context, request frontiertransport.CutRequest) ([]byte, error) {
				shard, decodeErr := shardFromCanonicalBytes(request.Context.CanonicalShardBytes)
				if decodeErr != nil {
					return nil, decodeErr
				}
				cut, readErr := manager.blockStore.ReadFrontierCutSnapshot(request.Context.PartitionID, shard)
				if readErr != nil {
					return nil, readErr
				}
				if cut.RootRound < request.Floor {
					return nil, fmt.Errorf("committed cut below requested hint")
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

	budget, err := frontiertransport.NewReceiveBudget(frontiertransport.MaxReceiveBudget)
	require.NoError(t, err)
	frontierRequest := frontiertransport.FrontierRequest{Version: 1, Context: contextValue, Nonce: nonce}
	for _, rootHost := range rootHosts {
		result := frontiertransport.ExchangeFrontier(context.Background(), frontierHostOpener{clientHost}, rootHost.ID(), frontierRequest, budget, 5*time.Second)
		require.True(t, result.Complete, "frontier exchange: status=%d err=%v partial=%d", result.Status, result.Err, len(result.Partial))
		require.NoError(t, result.Err)
		require.NoError(t, collector.Add(result.Raw).Err)
	}
	candidate := collector.Snapshot().Candidate()
	require.True(t, candidate.Valid())

	require.Eventually(t, func() bool {
		cut, readErr := cms[0].blockStore.ReadFrontierCutSnapshot(partitionID, shardID)
		return readErr == nil && cut.RootRound >= candidate.Floor()
	}, 5*time.Second, 20*time.Millisecond)
	binding := collector.AcquisitionBinding()
	cutRequest := frontiertransport.CutRequest{Version: 1, Context: contextValue, Nonce: nonce, AcquisitionBinding: binding[:], Floor: candidate.Floor()}
	cutResult := frontiertransport.ExchangeCut(context.Background(), frontierHostOpener{clientHost}, rootHosts[0].ID(), cutRequest, budget, 5*time.Second)
	require.True(t, cutResult.Complete)
	require.NoError(t, cutResult.Err)
	verified, err := collector.AddCut(cutResult.Raw)
	require.NoError(t, err)
	require.True(t, verified.Valid())
	require.Equal(t, candidate.PairIdentity(), verified.PairIdentity())
	require.GreaterOrEqual(t, verified.CommittedRound(), candidate.Floor())
	require.LessOrEqual(t, budget.Snapshot().Committed, budget.Snapshot().Limit)
}
