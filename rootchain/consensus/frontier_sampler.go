package consensus

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/unicitynetwork/bft-core/internal/quorumweight"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

var (
	// ErrFrontierProfile marks a trust base or configuration outside the frontier's fixed unit-weight profile.
	ErrFrontierProfile     = errors.New("root frontier profile refused")
	ErrFrontierDisabled    = errors.New("root frontier sampler is disabled")
	ErrFrontierUnavailable = errors.New("root frontier sample unavailable")
	ErrFrontierBusy        = errors.New("root frontier sampler is busy")
	ErrFrontierStopped     = errors.New("root frontier sampler is stopped")
)

const frontierMaxShardBits = 4096

type FrontierSamplerConfig struct {
	TrustBase  *types.RootTrustBaseV1
	QueueSize  int
	MaxPending int
	// Signing is the signing configuration of the sampled trust base's epoch: the wire form of the QCs the sampler accepts as
	// covering evidence. The zero value is the legacy scheme.
	Signing votesig.Config
}

type FrontierRequest struct {
	NetworkID         types.NetworkID
	PartitionID       types.PartitionID
	ShardID           types.ShardID
	FullShardConfHash []byte
}

type FrontierQCCandidate uint8

const (
	FrontierCommitQC FrontierQCCandidate = iota + 1
	FrontierHighQC
)

// FrontierSample is unsigned diagnostic data. It grants no freshness,
// readiness, signing, receipt, or bootstrap authority.
type FrontierSample struct {
	Safety     storage.SafetySnapshot
	View       *storage.FrontierStorageView
	CoveringQC FrontierQCCandidate
}

type frontierReply struct {
	sample *FrontierSample
	signed *SignedFrontierResponse
	err    error
}
type frontierRequest struct {
	ctx    context.Context
	req    FrontierRequest
	signed *signedFrontierRequest
	reply  chan frontierReply
}
type frontierSafetyReader interface {
	ReadSafetySnapshot() (storage.SafetySnapshot, error)
}
type frontierSampler struct {
	trust     *types.RootTrustBaseV1
	scheme    votesig.Config
	trustHash [32]byte
	requests  chan frontierRequest
	pending   chan struct{}
	stopped   chan struct{}
	stopOnce  sync.Once
	runState  atomic.Uint32 // 0 not started, 1 running, 2 stopped
	eligible  atomic.Bool
	faulted   atomic.Bool
	reader    frontierSafetyReader
	signing   bool
	author    string
	signer    abcrypto.Signer
}

func newFrontierSampler(c FrontierSamplerConfig, reader frontierSafetyReader) (*frontierSampler, error) {
	if reader == nil || c.TrustBase == nil || c.QueueSize <= 0 || c.MaxPending <= 0 || c.QueueSize > c.MaxPending {
		return nil, fmt.Errorf("%w: invalid frontier sampler configuration", ErrFrontierProfile)
	}
	if err := validateFrontierTrustBounds(c.TrustBase); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFrontierProfile, err)
	}
	if c.TrustBase.Version != 1 || c.TrustBase.NetworkID == 0 || c.TrustBase.Epoch == 0 {
		return nil, fmt.Errorf("%w: invalid frontier trust profile", ErrFrontierProfile)
	}
	b, err := types.Cbor.Marshal(c.TrustBase)
	if err != nil {
		return nil, fmt.Errorf("copying frontier trust base: %w", err)
	}
	var trust types.RootTrustBaseV1
	if err := types.Cbor.Unmarshal(b, &trust); err != nil {
		return nil, fmt.Errorf("copying frontier trust base: %w", err)
	}
	slices.SortFunc(trust.RootNodes, func(a, b *types.NodeInfo) int { return bytes.Compare([]byte(a.NodeID), []byte(b.NodeID)) })
	seen := make(map[string]struct{}, len(trust.RootNodes))
	for _, n := range trust.RootNodes {
		if err := n.IsValid(); err != nil {
			return nil, fmt.Errorf("%w: invalid frontier root: %w", ErrFrontierProfile, err)
		}
		if n.Stake != 1 {
			return nil, fmt.Errorf("%w: frontier roots must have unit weight", ErrFrontierProfile)
		}
		if _, ok := seen[n.NodeID]; ok {
			return nil, fmt.Errorf("duplicate frontier root %q", n.NodeID)
		}
		seen[n.NodeID] = struct{}{}
	}
	n, err := quorumweight.TotalWeight(trust.RootNodes)
	if err != nil {
		return nil, fmt.Errorf("frontier root weight: %w", err)
	}
	if min, err := quorumweight.Threshold(n); err != nil || trust.QuorumThreshold < min || trust.QuorumThreshold > n {
		return nil, fmt.Errorf("%w: frontier quorum must satisfy 2N/3 < q <= N", ErrFrontierProfile)
	}
	ownedEncoding, err := types.Cbor.Marshal(&trust)
	if err != nil {
		return nil, fmt.Errorf("encoding frontier trust base: %w", err)
	}
	return &frontierSampler{trust: &trust, scheme: c.Signing, trustHash: sha256.Sum256(ownedEncoding), requests: make(chan frontierRequest, c.QueueSize), pending: make(chan struct{}, c.MaxPending), stopped: make(chan struct{}), reader: reader}, nil
}

func (s *frontierSampler) latchFault() {
	if s != nil {
		s.faulted.Store(true)
		s.eligible.Store(false)
	}
}

func (x *ConsensusManager) SampleFrontier(ctx context.Context, req FrontierRequest) (*FrontierSample, error) {
	if x == nil || x.frontier == nil {
		return nil, ErrFrontierDisabled
	}
	if ctx == nil || req.NetworkID == 0 || req.PartitionID == 0 || req.ShardID.Length() > frontierMaxShardBits || len(req.FullShardConfHash) != crypto.SHA256.Size() {
		return nil, fmt.Errorf("%w: invalid request context", ErrFrontierUnavailable)
	}
	s := x.frontier
	if s.runState.Load() == 2 {
		return nil, ErrFrontierStopped
	}
	if s.runState.Load() != 1 || !s.eligible.Load() || s.faulted.Load() {
		return nil, ErrFrontierUnavailable
	}
	select {
	case s.pending <- struct{}{}:
	default:
		return nil, ErrFrontierBusy
	}
	defer func() { <-s.pending }()
	ownedShard, err := ownFrontierShardID(req.ShardID)
	if err != nil {
		return nil, fmt.Errorf("%w: shard identity", ErrFrontierUnavailable)
	}
	r := frontierRequest{ctx: ctx, req: FrontierRequest{NetworkID: req.NetworkID, PartitionID: req.PartitionID, ShardID: ownedShard, FullShardConfHash: bytes.Clone(req.FullShardConfHash)}, reply: make(chan frontierReply, 1)}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	out, err := x.submitFrontierRequest(ctx, r)
	return out.sample, err
}

func (x *ConsensusManager) submitFrontierRequest(ctx context.Context, r frontierRequest) (frontierReply, error) {
	s := x.frontier
	select {
	case s.requests <- r:
	case <-ctx.Done():
		return frontierReply{}, ctx.Err()
	case <-s.stopped:
		return frontierReply{}, ErrFrontierStopped
	default:
		return frontierReply{}, ErrFrontierBusy
	}
	select {
	case out := <-r.reply:
		if err := ctx.Err(); err != nil {
			return frontierReply{}, err
		}
		select {
		case <-s.stopped:
			return frontierReply{}, ErrFrontierStopped
		default:
		}
		return out, out.err
	case <-ctx.Done():
		return frontierReply{}, ctx.Err()
	case <-s.stopped:
		return frontierReply{}, ErrFrontierStopped
	}
}

func ownFrontierShardID(shard types.ShardID) (types.ShardID, error) {
	b, err := types.Cbor.Marshal(shard)
	if err != nil {
		return types.ShardID{}, err
	}
	var owned types.ShardID
	if err := types.Cbor.Unmarshal(b, &owned); err != nil {
		return types.ShardID{}, err
	}
	return owned, nil
}

func (x *ConsensusManager) handleFrontierRequest(managerCtx context.Context, r frontierRequest) {
	if r.ctx.Err() != nil || managerCtx.Err() != nil {
		return
	}
	sample, err := x.buildFrontierSample(r.req)
	var signed *SignedFrontierResponse
	if err == nil && r.signed != nil {
		if r.ctx.Err() != nil || managerCtx.Err() != nil {
			return
		}
		signed, err = x.signFrontierSample(r.ctx, managerCtx, r.req, r.signed, sample)
	}
	if r.ctx.Err() != nil || managerCtx.Err() != nil {
		return
	}
	if x.frontier.faulted.Load() || !x.frontier.eligible.Load() || x.recovery.InRecovery() {
		sample, signed, err = nil, nil, ErrFrontierUnavailable
	}
	select {
	case r.reply <- frontierReply{sample: sample, signed: signed, err: err}:
	default:
	}
}

func (x *ConsensusManager) buildFrontierSample(req FrontierRequest) (*FrontierSample, error) {
	s := x.frontier
	activeTrust := x.trustBase.Load()
	activeHash, trustErr := frontierTrustHash(activeTrust)
	if s == nil || s.faulted.Load() || !s.eligible.Load() || x.recovery.InRecovery() || trustErr != nil || activeHash != s.trustHash {
		return nil, ErrFrontierUnavailable
	}
	if req.NetworkID != s.trust.NetworkID || x.orchestration.NetworkID() != s.trust.NetworkID {
		return nil, fmt.Errorf("%w: network mismatch", ErrFrontierUnavailable)
	}
	view, err := x.blockStore.ReadFrontierStorageView(req.PartitionID, req.ShardID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFrontierUnavailable, err)
	}
	if view.PartitionID != req.PartitionID || !view.ShardID.Equal(req.ShardID) || view.RootNetworkID != s.trust.NetworkID || view.RootEpoch != s.trust.Epoch {
		return nil, fmt.Errorf("%w: committed context mismatch", ErrFrontierUnavailable)
	}
	pdr, err := x.orchestration.ShardConfig(req.PartitionID, req.ShardID, view.CommittedRootRound)
	if err != nil || pdr == nil {
		return nil, fmt.Errorf("%w: local shard configuration", ErrFrontierUnavailable)
	}
	confHash, err := pdr.Hash(x.params.HashAlgorithm)
	if err != nil || pdr.NetworkID != req.NetworkID || pdr.PartitionID != req.PartitionID || !pdr.ShardID.Equal(req.ShardID) || !bytes.Equal(confHash, req.FullShardConfHash) || !bytes.Equal(confHash, view.ShardConfigHash) {
		return nil, fmt.Errorf("%w: shard configuration mismatch", ErrFrontierUnavailable)
	}
	if err := view.LastCR.IsValid(); err != nil {
		return nil, fmt.Errorf("%w: invalid LastCR: %v", ErrFrontierUnavailable, err)
	}
	if view.LastCR.Partition != req.PartitionID || !view.LastCR.Shard.Equal(req.ShardID) || view.LastCR.Technical.Epoch != pdr.Epoch {
		return nil, fmt.Errorf("%w: LastCR context mismatch", ErrFrontierUnavailable)
	}
	// Shard epochs are authenticated values: the configuration is the one committed history derives for the
	// committed root round (checked above against the technical record's epoch), and the certified input
	// record's epoch never exceeds the authorized one. The root epoch must be the sampled trust base's.
	if view.LastCR.UC.UnicitySeal.NetworkID != s.trust.NetworkID || view.LastCR.UC.UnicitySeal.Epoch != s.trust.Epoch ||
		view.LastCR.UC.InputRecord.Epoch > view.LastCR.Technical.Epoch {
		return nil, fmt.Errorf("%w: LastCR profile mismatch", ErrFrontierUnavailable)
	}
	if err := view.LastCR.UC.Verify(quorumweight.Checked(s.trust), x.params.HashAlgorithm, req.PartitionID, req.ShardID, confHash); err != nil {
		return nil, fmt.Errorf("%w: LastCR authentication: %v", ErrFrontierUnavailable, err)
	}
	safety, err := s.reader.ReadSafetySnapshot()
	if err != nil {
		return nil, fmt.Errorf("%w: checked safety read: %v", ErrFrontierUnavailable, err)
	}
	selected := selectFrontierQCCandidate(view.CommitQC, view.HighQC, s.trust, s.scheme, safety.HighestQCRound, view.CommittedRootRound)
	if selected == 0 {
		return nil, fmt.Errorf("%w: covering-qc-unavailable", ErrFrontierUnavailable)
	}
	return &FrontierSample{Safety: safety, View: view, CoveringQC: selected}, nil
}

func selectFrontierQCCandidate(commitQC, highQC *drctypes.QuorumCert, trust *types.RootTrustBaseV1, cfg votesig.Config, highestQC, committed uint64) FrontierQCCandidate {
	if verifyFrontierQC(commitQC, trust, cfg, highestQC, committed) == nil {
		return FrontierCommitQC
	}
	if verifyFrontierQC(highQC, trust, cfg, highestQC, committed) == nil {
		return FrontierHighQC
	}
	return 0
}

func frontierTrustHash(trust *types.RootTrustBaseV1) ([32]byte, error) {
	if err := validateFrontierTrustBounds(trust); err != nil {
		return [32]byte{}, err
	}
	b, err := types.Cbor.Marshal(trust)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(b), nil
}

func validateFrontierTrustBounds(trust *types.RootTrustBaseV1) error {
	if trust == nil || len(trust.RootNodes) == 0 || len(trust.RootNodes) > 64 || len(trust.Signatures) > 64 {
		return errors.New("frontier root committee must contain 1..64 roots")
	}
	total := len(trust.StateHash) + len(trust.ChangeRecordHash) + len(trust.PreviousEntryHash)
	for _, n := range trust.RootNodes {
		if n == nil || len(n.NodeID) > 256 || len(n.SigKey) > 256 {
			return errors.New("frontier root exceeds bounds")
		}
		total += len(n.NodeID) + len(n.SigKey)
	}
	for id, sig := range trust.Signatures {
		if len(id) > 256 || len(sig) > 256 {
			return errors.New("frontier trust signature exceeds bounds")
		}
		total += len(id) + len(sig)
	}
	if total > 256<<10 {
		return errors.New("frontier trust base exceeds bounds")
	}
	return nil
}

func verifyFrontierQC(qc *drctypes.QuorumCert, trust *types.RootTrustBaseV1, cfg votesig.Config, highestQC, committed uint64) error {
	if qc == nil || qc.VoteInfo == nil || qc.LedgerCommitInfo == nil {
		return errors.New("incomplete QC")
	}
	vote, parent, commit := qc.VoteInfo.RoundNumber, qc.VoteInfo.ParentRoundNumber, qc.LedgerCommitInfo.RootChainRoundNumber
	if vote == drctypes.GenesisRootRound || parent == 0 || commit == 0 || vote == ^uint64(0) || vote != parent+1 || commit != parent {
		return errors.New("QC is not non-genesis commit-capable")
	}
	if vote < highestQC || vote < committed {
		return errors.New("QC does not cover frontier")
	}
	if qc.VoteInfo.Epoch != trust.Epoch || qc.LedgerCommitInfo.Epoch != trust.Epoch || qc.LedgerCommitInfo.NetworkID != trust.NetworkID {
		return errors.New("QC context mismatch")
	}
	// the covering QC is verified by the rule of its epoch, in the wire form that epoch signs with
	return qc.VerifyScheme(trust, cfg)
}
