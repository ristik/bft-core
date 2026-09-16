package frontierrequester

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	libnetwork "github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/certifiedstore"
	"github.com/unicitynetwork/bft-core/configuredprogress"
	"github.com/unicitynetwork/bft-core/internal/testutils/certifiedchain"
	"github.com/unicitynetwork/bft-core/registrygenesis"
	"github.com/unicitynetwork/bft-core/registryproof"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/frontierclient"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/frontiertransport"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/internal/frontiercodec"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootinput"
	"github.com/unicitynetwork/bft-go-base/types"
)

type reviewPolicyClock struct {
	now   time.Time
	waits []time.Duration
}

func (c *reviewPolicyClock) Now() time.Time { return c.now }
func (c *reviewPolicyClock) Wait(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.waits = append(c.waits, d)
	return nil
}

type reviewPolicyTrust struct{ tb *types.RootTrustBaseV1 }

func (s reviewPolicyTrust) GetByEpoch(context.Context, uint64) (*types.RootTrustBaseV1, error) {
	return s.tb, nil
}

type reviewPolicyGate struct{}

func (reviewPolicyGate) WithinFinality(ctx context.Context, f func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return f()
}

type reviewPolicyOpener func(context.Context, peer.ID, string) (libnetwork.Stream, error)

func (f reviewPolicyOpener) CreateStream(c context.Context, p peer.ID, s string) (libnetwork.Stream, error) {
	return f(c, p, s)
}

// This fixture uses the public constructor and a real initialized progress store;
// only the network response and policy backoff are controlled by the test.
func reviewPolicyRequester(t *testing.T, opener reviewPolicyOpener) (*Requester, *configuredprogress.AdmissionCoordinator, *reviewPolicyClock, *certifiedchain.Chain) {
	t.Helper()
	chain := certifiedchain.New(t, 5, 0)
	var doc map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(chain.Genesis.GenesisJSON(), &doc))
	var alloc map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(doc["alloc"], &alloc))
	for k := range alloc {
		if strings.EqualFold(strings.TrimPrefix(k, "0x"), strings.TrimPrefix(registryproof.RegistryAddress.Hex(), "0x")) {
			delete(alloc, k)
		}
	}
	doc["alloc"], _ = json.Marshal(alloc)
	source, err := json.Marshal(doc)
	require.NoError(t, err)
	artifact, err := registrygenesis.PinnedArtifact()
	require.NoError(t, err)
	prepared, err := registrygenesis.PrepareGenesisJSON(certifiedchain.Config(5), chain.Pins, artifact, source, registrygenesis.GenesisJSONLimits{})
	require.NoError(t, err)
	origin := prepared.Origin()
	trust := reviewPolicyTrust{chain.TrustBase}
	oc := rootinput.ObservationContextV2{NetworkID: 5, PartitionID: 8, ShardConfHash: origin.FullShardConfHash().Bytes(), RootEpoch: 1, TrustBases: trust}
	rc := certifiedstore.Context{NetworkID: 5, PartitionID: 8, FullShardConfHash: origin.FullShardConfHash().Bytes(), Registry: origin.ProofContext(), TrustBases: trust}
	store, err := configuredprogress.OpenConfiguredV2(t.TempDir()+"/progress.db", configuredprogress.Settings{Retain: 1})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	progress := configuredprogress.Context{Origin: origin, Observation: oc, Record: rc}
	_, _, err = store.Initialize(context.Background(), progress)
	require.NoError(t, err)
	admission, err := configuredprogress.NewAdmissionCoordinator(context.Background(), configuredprogress.AdmissionConfig{Store: store, Context: progress, Gate: reviewPolicyGate{}, Invalidate: func() {}, Deliver: func(context.Context, rootinput.VerifiedObservationV2) error { return nil }})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, admission.Close()) })
	profile := frontierclient.Profile{TrustBase: chain.TrustBase, NetworkID: 5, PartitionID: 8, FullShardConfHash: oc.ShardConfHash, RootEpoch: 1, GenesisOriginIdentity: origin.Identity().Bytes()}
	clk := &reviewPolicyClock{now: time.Now()}
	r, err := newRequester(Config{Process: context.Background(), Profile: profile, Peers: []RootPeer{{Author: chain.TrustBase.RootNodes[0].NodeID, PeerID: "root"}}, Opener: opener, Admission: admission}, clk, bytes.NewReader(bytes.Repeat([]byte{1}, 128)))
	require.NoError(t, err)
	return r, admission, clk, chain
}

func TestReviewFailedAcquisitionHasTwoPassesAndOneBackoff(t *testing.T) {
	var calls atomic.Int32
	r, _, clk, _ := reviewPolicyRequester(t, func(ctx context.Context, _ peer.ID, _ string) (libnetwork.Stream, error) {
		calls.Add(1)
		deadline, ok := ctx.Deadline()
		require.True(t, ok)
		require.LessOrEqual(t, time.Until(deadline), ExchangeDuration)
		return nil, io.EOF
	})
	got := r.Acquire(context.Background())
	require.ErrorIs(t, got.Err, ErrUnavailable)
	require.False(t, got.Receipt.Valid())
	require.EqualValues(t, 2, calls.Load())
	require.Equal(t, []time.Duration{PassBackoff}, clk.waits)
}

type reviewResponseStream struct {
	libnetwork.Stream
	reader *bytes.Reader
	read   *atomic.Int64
}

func (s *reviewResponseStream) Read(p []byte) (int, error) {
	n, e := s.reader.Read(p)
	s.read.Add(int64(n))
	return n, e
}
func (s *reviewResponseStream) Write(p []byte) (int, error) { return len(p), nil }
func (s *reviewResponseStream) SetDeadline(time.Time) error { return nil }
func (s *reviewResponseStream) CloseWrite() error           { return nil }
func (s *reviewResponseStream) Close() error                { return nil }
func (s *reviewResponseStream) Reset() error                { return nil }

type reviewLifecycleStream struct {
	libnetwork.Stream
	request  bytes.Buffer
	response *bytes.Reader
	build    func([]byte) ([]byte, error)
	err      error
}

func (s *reviewLifecycleStream) Write(p []byte) (int, error) { return s.request.Write(p) }
func (s *reviewLifecycleStream) Read(p []byte) (int, error) {
	if s.err != nil {
		return 0, s.err
	}
	if s.response == nil {
		return 0, io.EOF
	}
	return s.response.Read(p)
}
func (s *reviewLifecycleStream) SetDeadline(time.Time) error { return nil }
func (s *reviewLifecycleStream) Close() error                { return nil }
func (s *reviewLifecycleStream) Reset() error                { return nil }
func (s *reviewLifecycleStream) CloseWrite() error {
	raw := s.request.Bytes()
	if len(raw) < 4 || int(binary.BigEndian.Uint32(raw[:4])) != len(raw)-4 {
		s.err = io.ErrUnexpectedEOF
		return nil
	}
	body, err := s.build(raw[4:])
	if err != nil {
		s.err = err
		return nil
	}
	framed := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(framed, uint32(len(body)))
	copy(framed[4:], body)
	s.response = bytes.NewReader(framed)
	return nil
}

type reviewLifecycleProof struct {
	t       *testing.T
	chain   *certifiedchain.Chain
	author  string
	pair    frontiercodec.Pair
	pairRaw []byte
}

func newReviewLifecycleProof(t *testing.T, chain *certifiedchain.Chain) *reviewLifecycleProof {
	t.Helper()
	tr := certifiedchain.Technical(0)
	uc := chain.Certify(chain.Signer, &types.InputRecord{Version: 1}, tr, 2)
	author := chain.TrustBase.RootNodes[0].NodeID
	uc.UnicitySeal.NetworkID = 5
	uc.UnicitySeal.Signatures = nil
	require.NoError(t, uc.UnicitySeal.Sign(author, chain.Signer))
	pair := frontiercodec.Pair{UC: uc, TR: tr}
	pairRaw, err := types.Cbor.Marshal(pair)
	require.NoError(t, err)
	return &reviewLifecycleProof{t: t, chain: chain, author: author, pair: pair, pairRaw: pairRaw}
}

func (p *reviewLifecycleProof) qc(voteRound uint64, root []byte) *drctypes.QuorumCert {
	p.t.Helper()
	vote := &drctypes.RoundInfo{Version: 1, RoundNumber: voteRound, Epoch: 1, Timestamp: 1_700_000_000 + voteRound, ParentRoundNumber: voteRound - 1, CurrentRootHash: bytes.Clone(root)}
	voteHash, err := vote.Hash(crypto.SHA256)
	require.NoError(p.t, err)
	seal := &types.UnicitySeal{Version: 1, NetworkID: 5, RootChainRoundNumber: voteRound - 1, Epoch: 1, Timestamp: vote.Timestamp, PreviousHash: voteHash, Hash: bytes.Clone(root)}
	require.NoError(p.t, seal.Sign(p.author, p.chain.Signer))
	return &drctypes.QuorumCert{VoteInfo: vote, LedgerCommitInfo: seal, Signatures: seal.Signatures}
}

func (p *reviewLifecycleProof) frontier(raw []byte) ([]byte, error) {
	req, err := frontiertransport.DecodeFrontierRequest(raw)
	if err != nil {
		return nil, err
	}
	qcRaw, err := types.Cbor.Marshal(p.qc(3, p.pair.UC.UnicitySeal.Hash))
	if err != nil {
		return nil, err
	}
	pairID, err := frontiercodec.PairIdentity(p.pair, req.Context)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(qcRaw)
	preimage, err := types.Cbor.Marshal(frontiercodec.SigningPreimage{Domain: frontiercodec.SigningDomain, Version: frontiercodec.Version, Context: req.Context, Nonce: req.Nonce, Author: p.author, PairID: pairID[:], QCDigest: digest[:]})
	if err != nil {
		return nil, err
	}
	sig, err := p.chain.Signer.SignBytes(preimage)
	if err != nil {
		return nil, err
	}
	return types.Cbor.Marshal(frontiercodec.Reply{Version: frontiercodec.Version, Author: p.author, Pair: p.pairRaw, QC: qcRaw, Signature: sig})
}

func (p *reviewLifecycleProof) cut(raw []byte) ([]byte, error) {
	req, err := frontiertransport.DecodeCutRequest(raw)
	if err != nil {
		return nil, err
	}
	var binding [32]byte
	copy(binding[:], req.AcquisitionBinding)
	root := bytes.Clone(p.pair.UC.UnicitySeal.Hash)
	return frontiercodec.EncodeCutProof(binding, 3, 1, root, p.qc(4, root), p.pair, p.pair.UC.ShardTreeCertificate, p.pair.UC.UnicityTreeCertificate)
}

func TestReviewReceiveBudgetIsSharedAcrossQueryPasses(t *testing.T) {
	const bodySize = 600 << 10
	frame := make([]byte, bodySize+4)
	binary.BigEndian.PutUint32(frame, uint32(bodySize))
	var calls atomic.Int32
	var received atomic.Int64
	r, _, _, _ := reviewPolicyRequester(t, func(context.Context, peer.ID, string) (libnetwork.Stream, error) {
		calls.Add(1)
		return &reviewResponseStream{reader: bytes.NewReader(frame), read: &received}, nil
	})
	result := r.Acquire(context.Background())
	require.Error(t, result.Err)
	require.False(t, result.Receipt.Valid())
	require.EqualValues(t, 2, calls.Load())
	// First malformed body is charged; the second attempt may read its prefix
	// but cannot reserve another 600 KiB from the same acquisition budget.
	require.EqualValues(t, bodySize+8, received.Load())
}

func TestReviewClosedAdmissionPreventsNetworkAcquisition(t *testing.T) {
	var calls atomic.Int32
	r, admission, _, _ := reviewPolicyRequester(t, func(context.Context, peer.ID, string) (libnetwork.Stream, error) { calls.Add(1); return nil, io.EOF })
	require.NoError(t, admission.Close())
	got := r.Acquire(context.Background())
	require.Error(t, got.Err)
	require.False(t, got.Receipt.Valid())
	require.Zero(t, calls.Load())
}

func TestReceiptExpiresAtPolicyDeadlineAfterSuccessfulAcquisition(t *testing.T) {
	var proof *reviewLifecycleProof
	r, _, clk, chain := reviewPolicyRequester(t, func(_ context.Context, _ peer.ID, protocolID string) (libnetwork.Stream, error) {
		var build func([]byte) ([]byte, error)
		switch protocolID {
		case frontiertransport.FrontierProtocolID:
			build = proof.frontier
		case frontiertransport.CutProtocolID:
			build = proof.cut
		default:
			return nil, io.ErrUnexpectedEOF
		}
		return &reviewLifecycleStream{build: build}, nil
	})
	proof = newReviewLifecycleProof(t, chain)
	nonce := bytes.Repeat([]byte{1}, 32)
	profile := r.profile
	profile.Nonce = nonce
	collector, err := frontierclient.NewCollector(profile)
	require.NoError(t, err)
	requestContext := frontiercodec.Context{NetworkID: profile.NetworkID, PartitionID: profile.PartitionID, CanonicalShardBytes: profile.ShardID.Bytes(), FullShardConfHash: profile.FullShardConfHash, RootEpoch: profile.RootEpoch, GenesisOriginIdentity: profile.GenesisOriginIdentity}
	frontierRequest, err := frontiertransport.EncodeFrontierRequest(frontiertransport.FrontierRequest{Version: frontiercodec.Version, Context: requestContext, Nonce: nonce})
	require.NoError(t, err)
	frontierRaw, err := proof.frontier(frontierRequest)
	require.NoError(t, err)
	_, err = rootinput.AuthenticateObservationV2(context.Background(), rootinput.ObservationContextV2{NetworkID: profile.NetworkID, PartitionID: profile.PartitionID, ShardID: profile.ShardID, ShardConfHash: profile.FullShardConfHash, RootEpoch: profile.RootEpoch, TrustBases: reviewPolicyTrust{chain.TrustBase}}, proof.pair.UC, proof.pair.TR)
	require.NoError(t, err)
	var reply frontiercodec.Reply
	require.NoError(t, types.Cbor.Unmarshal(frontierRaw, &reply))
	var qc drctypes.QuorumCert
	require.NoError(t, types.Cbor.Unmarshal(reply.QC, &qc))
	require.NoError(t, qc.Verify(chain.TrustBase))
	require.NoError(t, collector.AddFrom(frontierRaw, proof.author).Err)
	candidate := collector.Snapshot().Candidate()
	require.True(t, candidate.Valid())
	binding := collector.AcquisitionBinding()
	cutRequest, err := frontiertransport.EncodeCutRequest(frontiertransport.CutRequest{Version: frontiercodec.Version, Context: requestContext, Nonce: nonce, AcquisitionBinding: binding[:], Floor: candidate.Floor()})
	require.NoError(t, err)
	cutRaw, err := proof.cut(cutRequest)
	require.NoError(t, err)
	_, err = collector.AddCut(cutRaw)
	require.NoError(t, err)

	result := r.Acquire(context.Background())
	require.NoError(t, result.Err)
	require.NoError(t, r.Validate(result.Receipt))
	resolved, err := r.Resolve(result.Receipt)
	require.NoError(t, err)
	require.NotNil(t, resolved.UC)
	require.NotNil(t, resolved.TR)
	require.Equal(t, uint64(3), resolved.CutRound)

	clk.now = clk.now.Add(ReceiptLifetime - time.Nanosecond)
	require.NoError(t, r.Validate(result.Receipt))
	clk.now = clk.now.Add(time.Nanosecond)
	require.ErrorIs(t, r.Validate(result.Receipt), ErrInvalidated)
	_, err = r.Resolve(result.Receipt)
	require.ErrorIs(t, err, ErrInvalidated)
}
