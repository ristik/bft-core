package consensus

import (
	"context"
	"fmt"
	"time"

	"github.com/unicitynetwork/bft-core/rootchain/consensus/frontiertransport"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/internal/frontiercodec"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	"github.com/unicitynetwork/bft-go-base/types"
)

// frontierCutPoll is how often a cut request re-reads the committed root while
// waiting for it to reach the requester's floor. The wait is bounded by the
// transport's per-request deadline, which cancels the handler context.
const frontierCutPoll = 10 * time.Millisecond

// DefaultFrontierSamplerConfig is the bounded sampler a root enables in default
// startup. Queue and pending counts only bound memory: each admitted request
// holds one slot until the consensus loop answers or its stream deadline ends.
func DefaultFrontierSamplerConfig(trust *types.RootTrustBaseV1) FrontierSamplerConfig {
	return FrontierSamplerConfig{TrustBase: trust, QueueSize: 8, MaxPending: 16}
}

// DefaultFrontierServerLimits bounds the root's frontier transport. A requester
// makes at most two frontier and two cut exchanges to one root per acquisition
// (frontierrequester.MaxPasses), so a handful of requests per second per
// shard validator is ample.
func DefaultFrontierServerLimits() frontiertransport.Limits {
	return frontiertransport.Limits{Deadline: frontiertransport.MaxExchangeDuration, MaxEligiblePeers: frontiertransport.MaxEligiblePeers, MaxPendingStreams: 32, MaxPendingStreamsPerPeer: 2, RequestsPerSecond: 2, Burst: 8}
}

// ValidateFrontierProfile reports whether trust satisfies the fixed profile the
// frontier protocol is specified for (F6f section 5: unit-weight roots,
// 2N/3 < q <= N, one epoch). A root whose trust base fails it cannot serve
// frontier replies and must not enable the sampler.
func ValidateFrontierProfile(trust *types.RootTrustBaseV1) error {
	_, err := newFrontierSampler(DefaultFrontierSamplerConfig(trust), unusedSafetyReader{})
	return err
}

type unusedSafetyReader struct{}

func (unusedSafetyReader) ReadSafetySnapshot() (storage.SafetySnapshot, error) {
	return storage.SafetySnapshot{}, ErrFrontierUnavailable
}

// FrontierHandlers returns the transport handlers that serve this root's
// signed frontier replies and committed-cut proofs. The manager must have been
// built with WithFrontierSampler and WithFrontierSigning; the handlers perform
// no admission of their own (the frontiertransport.Server bounds peers, streams
// and rate before a request is read) and sign only what the consensus loop
// samples (F6f section 3).
func (x *ConsensusManager) FrontierHandlers() (frontiertransport.Handlers, error) {
	if x == nil || x.frontier == nil || !x.frontier.signing {
		return frontiertransport.Handlers{}, ErrFrontierSigningDisabled
	}
	return frontiertransport.Handlers{
		Frontier: x.serveFrontier,
		Cut:      x.serveCut,
	}, nil
}

func (x *ConsensusManager) serveFrontier(ctx context.Context, request frontiertransport.FrontierRequest) ([]byte, error) {
	shard, err := decodeFrontierShard(request.Context.CanonicalShardBytes)
	if err != nil {
		return nil, err
	}
	response, err := x.SampleSignedFrontier(ctx, SignedFrontierRequest{
		FrontierRequest:       FrontierRequest{NetworkID: request.Context.NetworkID, PartitionID: request.Context.PartitionID, ShardID: shard, FullShardConfHash: request.Context.FullShardConfHash},
		RootEpoch:             request.Context.RootEpoch,
		GenesisOriginIdentity: request.Context.GenesisOriginIdentity,
		Nonce:                 request.Nonce,
	})
	if err != nil {
		x.log.DebugContext(ctx, "frontier request not served", "error", err)
		return nil, err
	}
	return response.CanonicalBytes(), nil
}

func (x *ConsensusManager) serveCut(ctx context.Context, request frontiertransport.CutRequest) ([]byte, error) {
	if x.frontier == nil || request.Context.RootEpoch != x.frontier.trust.Epoch || request.Context.NetworkID != x.frontier.trust.NetworkID {
		return nil, ErrFrontierUnavailable
	}
	shard, err := decodeFrontierShard(request.Context.CanonicalShardBytes)
	if err != nil {
		return nil, err
	}
	var committed uint64
	for {
		cut, readErr := x.blockStore.ReadFrontierCutSnapshot(request.Context.PartitionID, shard)
		if readErr == nil {
			committed = cut.RootRound
		}
		if readErr == nil && cut.RootRound >= request.Floor {
			var binding [32]byte
			copy(binding[:], request.AcquisitionBinding)
			return frontiercodec.EncodeCutProof(binding, cut.RootRound, cut.RootEpoch, cut.RootHash, cut.CommitQC, frontiercodec.Pair{UC: &cut.LastCR.UC, TR: &cut.LastCR.Technical}, cut.ShardTreeCertificate, cut.UnicityTreeCertificate)
		}
		select {
		case <-ctx.Done():
			x.log.InfoContext(ctx, "frontier cut request not served", "floor", request.Floor, "committedRound", committed, "readError", readErr)
			if readErr != nil {
				return nil, fmt.Errorf("committed cut unavailable: %w", readErr)
			}
			return nil, fmt.Errorf("committed cut below the requested floor: %w", ctx.Err())
		case <-time.After(frontierCutPoll):
		}
	}
}

func decodeFrontierShard(canonical []byte) (types.ShardID, error) {
	b, err := types.Cbor.Marshal(canonical)
	if err != nil {
		return types.ShardID{}, err
	}
	var shard types.ShardID
	if err = types.Cbor.Unmarshal(b, &shard); err != nil {
		return types.ShardID{}, err
	}
	return shard, nil
}
