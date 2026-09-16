package consensus

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	basetrust "github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	rctest "github.com/unicitynetwork/bft-core/rootchain/testutils"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

type frontierCountingSigner struct {
	abcrypto.Signer
	frontierCalls atomic.Int32
	entered       chan struct{}
	release       chan struct{}
	lastMu        sync.Mutex
	last          []byte
	badSignature  atomic.Bool
	mutateInput   atomic.Bool
	failFrontier  atomic.Bool
}

func (s *frontierCountingSigner) SignBytes(data []byte) ([]byte, error) {
	var values []any
	_ = types.Cbor.Unmarshal(data, &values)
	frontier := len(values) > 0 && values[0] == frontierSigningDomain
	if !frontier {
		return s.Signer.SignBytes(data)
	}
	s.frontierCalls.Add(1)
	s.lastMu.Lock()
	s.last = bytes.Clone(data)
	s.lastMu.Unlock()
	if s.entered != nil {
		select {
		case s.entered <- struct{}{}:
		default:
		}
	}
	if s.release != nil {
		<-s.release
	}
	if s.mutateInput.Load() && len(data) > 0 {
		data[len(data)-1] ^= 0xff
	}
	if s.failFrontier.Load() {
		return nil, errors.New("frontier signer fail")
	}
	sig, err := s.Signer.SignBytes(data)
	if err == nil && s.badSignature.Load() && len(sig) > 0 {
		sig[0] ^= 0xff
	}
	return sig, err
}

type frontierPermissiveVerifier struct{ key []byte }

func (v frontierPermissiveVerifier) VerifyBytes([]byte, []byte) error { return nil }
func (v frontierPermissiveVerifier) VerifyHash([]byte, []byte) error  { return nil }
func (v frontierPermissiveVerifier) MarshalPublicKey() ([]byte, error) {
	return bytes.Clone(v.key), nil
}
func (v frontierPermissiveVerifier) UnmarshalPubKey() (crypto.PublicKey, error) { return nil, nil }

type frontierPermissiveSigner struct {
	abcrypto.Signer
	key []byte
}

func (s frontierPermissiveSigner) SignBytes(data []byte) ([]byte, error) {
	var values []any
	_ = types.Cbor.Unmarshal(data, &values)
	if len(values) > 0 && values[0] == frontierSigningDomain {
		return bytes.Repeat([]byte{0x55}, 65), nil
	}
	return s.Signer.SignBytes(data)
}
func (s frontierPermissiveSigner) Verifier() (abcrypto.Verifier, error) {
	return frontierPermissiveVerifier{key: s.key}, nil
}

func (s *frontierCountingSigner) lastPreimage() []byte {
	s.lastMu.Lock()
	defer s.lastMu.Unlock()
	return bytes.Clone(s.last)
}

func signedRequest(t *testing.T, h *frontierHarness, fill byte) SignedFrontierRequest {
	t.Helper()
	return SignedFrontierRequest{FrontierRequest: h.request(t), RootEpoch: h.trust.Epoch, GenesisOriginIdentity: bytes.Repeat([]byte{fill}, 32), Nonce: bytes.Repeat([]byte{fill + 1}, 32)}
}

func decodeSignedReply(t *testing.T, response *SignedFrontierResponse) frontierSignedReply {
	t.Helper()
	var reply frontierSignedReply
	require.NoError(t, types.Cbor.Unmarshal(response.CanonicalBytes(), &reply))
	return reply
}

func TestSignedFrontierInitialAndOrdinaryPairsFromRealLoop(t *testing.T) {
	t.Run("initial pair", func(t *testing.T) {
		var counter *frontierCountingSigner
		h := newFrontierHarnessWithSigner(t, func(s abcrypto.Signer) abcrypto.Signer {
			counter = &frontierCountingSigner{Signer: s}
			return counter
		}, true)
		h.start(t)
		h.commitRoundTwo(t)
		request := signedRequest(t, h, 0x11)
		response, err := h.cm.SampleSignedFrontier(context.Background(), request)
		require.NoError(t, err)
		require.EqualValues(t, 1, counter.frontierCalls.Load())
		reply := decodeSignedReply(t, response)
		require.Equal(t, h.author, reply.Author)
		var pair frontierCanonicalPair
		require.NoError(t, types.Cbor.Unmarshal(reply.Pair, &pair))
		require.Zero(t, pair.UC.InputRecord.RoundNumber)
		var qc drctypes.QuorumCert
		require.NoError(t, types.Cbor.Unmarshal(reply.QC, &qc))
		require.NoError(t, verifyFrontierQC(&qc, h.trust, 0, 2))
		verifier, err := h.rootSigner.Verifier()
		require.NoError(t, err)
		confHash := h.request(t).FullShardConfHash
		require.NoError(t, pair.UC.Verify(h.trust, crypto.SHA256, h.pdr.PartitionID, h.pdr.ShardID, confHash))
		trHash, err := pair.TR.Hash()
		require.NoError(t, err)
		require.True(t, bytes.Equal(pair.UC.TRHash, trHash))
		expectedContext := frontierSignedContext{NetworkID: request.NetworkID, PartitionID: request.PartitionID, CanonicalShardBytes: request.ShardID.Bytes(), FullShardConfHash: request.FullShardConfHash, RootEpoch: request.RootEpoch, GenesisOriginIdentity: request.GenesisOriginIdentity}
		pairID, err := frontierPairIdentity(pair, expectedContext)
		require.NoError(t, err)
		qcDigest := sha256.Sum256(reply.QC)
		expectedPreimage, err := types.Cbor.Marshal(frontierSigningPreimage{Domain: frontierSigningDomain, Version: 1, Context: expectedContext, Nonce: request.Nonce, Author: reply.Author, PairID: pairID[:], QCDigest: qcDigest[:]})
		require.NoError(t, err)
		require.NoError(t, verifier.VerifyBytes(reply.Signature, expectedPreimage))
		wrongDomain, err := types.Cbor.Marshal(frontierSigningPreimage{Domain: "wrong/frontier", Version: 1, Context: expectedContext, Nonce: request.Nonce, Author: reply.Author, PairID: pairID[:], QCDigest: qcDigest[:]})
		require.NoError(t, err)
		require.Error(t, verifier.VerifyBytes(reply.Signature, wrongDomain))
	})

	t.Run("ordinary pair", func(t *testing.T) {
		h := newFrontierHarnessWithSigner(t, nil, true)
		h.start(t)
		si, err := h.cm.ShardInfo(partitionID, shardID)
		require.NoError(t, err)
		require.NoError(t, h.cm.RequestCertification(context.Background(), IRChangeRequest{Partition: partitionID, Shard: shardID, Reason: Quorum, Requests: buildBlockCertificationRequest(t, h.shardNodes, si.LastCR)}))
		h.commitRoundTwo(t)
		response, err := h.cm.SampleSignedFrontier(context.Background(), signedRequest(t, h, 0x22))
		require.NoError(t, err)
		var pair frontierCanonicalPair
		require.NoError(t, types.Cbor.Unmarshal(decodeSignedReply(t, response).Pair, &pair))
		require.Equal(t, uint64(1), pair.UC.InputRecord.RoundNumber)
		require.NotEmpty(t, pair.UC.InputRecord.BlockHash)
		require.NotEmpty(t, pair.UC.InputRecord.Hash)
	})
}

func TestSignedFrontierOwnsRequestAndResponse(t *testing.T) {
	var counter *frontierCountingSigner
	h := newFrontierHarnessWithSigner(t, func(s abcrypto.Signer) abcrypto.Signer {
		counter = &frontierCountingSigner{Signer: s}
		return counter
	}, true)
	h.start(t)
	h.commitRoundTwo(t)
	h.store.safetyGate, h.store.safetyEntered = make(chan struct{}), make(chan struct{}, 1)
	var release sync.Once
	releaseSafety := func() { release.Do(func() { close(h.store.safetyGate) }) }
	t.Cleanup(releaseSafety)
	request := signedRequest(t, h, 0x31)
	origin, nonce, config := bytes.Clone(request.GenesisOriginIdentity), bytes.Clone(request.Nonce), bytes.Clone(request.FullShardConfHash)
	result := make(chan *SignedFrontierResponse, 1)
	go func() { response, _ := h.cm.SampleSignedFrontier(context.Background(), request); result <- response }()
	select {
	case <-h.store.safetyEntered:
	case <-time.After(time.Second):
		t.Fatal("signed request did not reach loop")
	}
	request.GenesisOriginIdentity[0] ^= 0xff
	request.Nonce[0] ^= 0xff
	request.FullShardConfHash[0] ^= 0xff
	releaseSafety()
	var response *SignedFrontierResponse
	select {
	case response = <-result:
	case <-time.After(time.Second):
		t.Fatal("signed response was not published")
	}
	require.NotNil(t, response)
	var preimage frontierSigningPreimage
	require.NoError(t, types.Cbor.Unmarshal(counter.lastPreimage(), &preimage))
	require.Equal(t, origin, preimage.Context.GenesisOriginIdentity)
	require.Equal(t, nonce, preimage.Nonce)
	require.Equal(t, config, preimage.Context.FullShardConfHash)
	first := response.CanonicalBytes()
	first[0] ^= 0xff
	again, err := h.cm.SampleSignedFrontier(context.Background(), signedRequest(t, h, 0x31))
	require.NoError(t, err)
	require.Equal(t, response.CanonicalBytes(), again.CanonicalBytes())
}

func TestSignedFrontierCancellationAndSignerVerification(t *testing.T) {
	var counter *frontierCountingSigner
	h := newFrontierHarnessWithSigner(t, func(s abcrypto.Signer) abcrypto.Signer {
		counter = &frontierCountingSigner{Signer: s, entered: make(chan struct{}, 1), release: make(chan struct{})}
		return counter
	}, true)
	h.start(t)
	var release sync.Once
	releaseSigner := func() { release.Do(func() { close(counter.release) }) }
	t.Cleanup(releaseSigner)
	h.commitRoundTwo(t)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := h.cm.SampleSignedFrontier(canceled, signedRequest(t, h, 0x41))
	require.ErrorIs(t, err, context.Canceled)
	require.Zero(t, counter.frontierCalls.Load())

	ctx, cancelDuring := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, callErr := h.cm.SampleSignedFrontier(ctx, signedRequest(t, h, 0x42)); done <- callErr }()
	select {
	case <-counter.entered:
	case <-time.After(time.Second):
		t.Fatal("frontier signer was not entered")
	}
	cancelDuring()
	releaseSigner()
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("canceled signed query did not return")
	}
	require.EqualValues(t, 1, counter.frontierCalls.Load())

	counter.badSignature.Store(true)
	_, err = h.cm.SampleSignedFrontier(context.Background(), signedRequest(t, h, 0x43))
	require.ErrorIs(t, err, ErrFrontierUnavailable)
	counter.badSignature.Store(false)
	counter.mutateInput.Store(true)
	_, err = h.cm.SampleSignedFrontier(context.Background(), signedRequest(t, h, 0x44))
	require.ErrorIs(t, err, ErrFrontierUnavailable, "signer input mutation must not change expected binding")
	counter.mutateInput.Store(false)
	counter.failFrontier.Store(true)
	_, err = h.cm.SampleSignedFrontier(context.Background(), signedRequest(t, h, 0x45))
	require.ErrorIs(t, err, ErrFrontierUnavailable)
}

func TestSignedFrontierRefusesBeforeSigner(t *testing.T) {
	var counter *frontierCountingSigner
	h := newFrontierHarnessWithSigner(t, func(s abcrypto.Signer) abcrypto.Signer {
		counter = &frontierCountingSigner{Signer: s}
		return counter
	}, true)
	h.start(t)
	_, err := h.cm.SampleSignedFrontier(context.Background(), signedRequest(t, h, 0x51))
	require.ErrorIs(t, err, ErrFrontierUnavailable, "genesis-only covering QC must refuse")
	require.Zero(t, counter.frontierCalls.Load())
	h.commitRoundTwo(t)
	h.store.failRead.Store(true)
	_, err = h.cm.SampleSignedFrontier(context.Background(), signedRequest(t, h, 0x52))
	require.ErrorIs(t, err, ErrFrontierUnavailable)
	h.store.failRead.Store(false)
	bad := signedRequest(t, h, 0x52)
	bad.RootEpoch++
	_, err = h.cm.SampleSignedFrontier(context.Background(), bad)
	require.ErrorIs(t, err, ErrFrontierUnavailable)
	sample, err := h.cm.SampleFrontier(context.Background(), h.request(t))
	require.NoError(t, err)
	_, err = h.cm.recovery.Set(sample.View.CommitQC)
	require.NoError(t, err)
	_, err = h.cm.SampleSignedFrontier(context.Background(), signedRequest(t, h, 0x53))
	require.ErrorIs(t, err, ErrFrontierUnavailable)
	h.cm.recovery.Clear()
	h.cm.frontier.latchFault()
	_, err = h.cm.SampleSignedFrontier(context.Background(), signedRequest(t, h, 0x54))
	require.ErrorIs(t, err, ErrFrontierUnavailable)
	require.Zero(t, counter.frontierCalls.Load())
}

func TestSignedAndUnsignedFrontierShareAdmissionBudget(t *testing.T) {
	h := newFrontierHarnessWithSigner(t, nil, true)
	h.start(t)
	h.commitRoundTwo(t)
	h.store.safetyGate, h.store.safetyEntered = make(chan struct{}), make(chan struct{}, 1)
	var release sync.Once
	releaseRead := func() { release.Do(func() { close(h.store.safetyGate) }) }
	t.Cleanup(releaseRead)
	first := make(chan error, 1)
	go func() {
		_, err := h.cm.SampleSignedFrontier(context.Background(), signedRequest(t, h, 0x71))
		first <- err
	}()
	select {
	case <-h.store.safetyEntered:
	case <-time.After(time.Second):
		t.Fatal("signed query did not enter checked read")
	}
	second := make(chan error, 1)
	go func() { _, err := h.cm.SampleFrontier(context.Background(), h.request(t)); second <- err }()
	require.Eventually(t, func() bool { return len(h.cm.frontier.pending) == 2 }, time.Second, time.Millisecond)
	_, err := h.cm.SampleSignedFrontier(context.Background(), signedRequest(t, h, 0x72))
	require.ErrorIs(t, err, ErrFrontierBusy)
	releaseRead()
	select {
	case err := <-first:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("signed query did not finish")
	}
	select {
	case err := <-second:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("unsigned query did not finish")
	}
}

func TestFrontierSigningRequiresEnrolledKey(t *testing.T) {
	h := newFrontierHarness(t)
	wrong, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	require.ErrorContains(t, h.cm.frontier.enableSigning(h.author, wrong), "does not match")
	require.ErrorContains(t, h.cm.frontier.enableSigning("unknown", h.rootSigner), "not enrolled")
}

func TestFrontierSigningDistrustsSignerSuppliedVerifier(t *testing.T) {
	var malicious frontierPermissiveSigner
	h := newFrontierHarnessWithSigner(t, func(s abcrypto.Signer) abcrypto.Signer {
		verifier, err := s.Verifier()
		require.NoError(t, err)
		key, err := verifier.MarshalPublicKey()
		require.NoError(t, err)
		malicious = frontierPermissiveSigner{Signer: s, key: key}
		return malicious
	}, true)
	h.start(t)
	h.commitRoundTwo(t)
	_, err := h.cm.SampleSignedFrontier(context.Background(), signedRequest(t, h, 0x61))
	require.ErrorIs(t, err, ErrFrontierUnavailable)
}

func TestPairIdentityIgnoresSealSignatureSubsetAndQCDigestDoesNot(t *testing.T) {
	h := newFrontierHarnessWithSigner(t, nil, true)
	h.start(t)
	h.commitRoundTwo(t)
	sample, err := h.cm.SampleFrontier(context.Background(), h.request(t))
	require.NoError(t, err)
	ctx := frontierSignedContext{NetworkID: h.pdr.NetworkID, PartitionID: h.pdr.PartitionID, CanonicalShardBytes: h.pdr.ShardID.Bytes(), FullShardConfHash: h.request(t).FullShardConfHash, RootEpoch: h.trust.Epoch, GenesisOriginIdentity: bytes.Repeat([]byte{1}, 32)}
	rootSigners := make(map[string]abcrypto.Signer, 4)
	var authors []string
	for range 4 {
		node := rctest.NewTestNode(t)
		author := node.PeerConf.ID.String()
		rootSigners[author] = node.Signer
		authors = append(authors, author)
	}
	tb := basetrust.NewTrustBaseFromSigners(t, rootSigners).(*types.RootTrustBaseV1)
	basePair := frontierCanonicalPair{UC: &sample.View.LastCR.UC, TR: &sample.View.LastCR.Technical}
	basePair.UC.UnicitySeal.Signatures = nil
	basePair.UC.UnicitySeal.Epoch = tb.Epoch
	basePair.UC.UnicitySeal.NetworkID = tb.NetworkID
	for author, signer := range rootSigners {
		require.NoError(t, basePair.UC.UnicitySeal.Sign(author, signer))
	}
	clonePair := func() frontierCanonicalPair {
		b, cloneErr := types.Cbor.Marshal(basePair)
		require.NoError(t, cloneErr)
		var pair frontierCanonicalPair
		require.NoError(t, types.Cbor.Unmarshal(b, &pair))
		return pair
	}
	pair1, pair2 := clonePair(), clonePair()
	delete(pair1.UC.UnicitySeal.Signatures, authors[0])
	delete(pair2.UC.UnicitySeal.Signatures, authors[1])
	require.NoError(t, pair1.UC.UnicitySeal.Verify(tb))
	require.NoError(t, pair2.UC.UnicitySeal.Verify(tb))
	id1, err := frontierPairIdentity(pair1, ctx)
	require.NoError(t, err)
	id2, err := frontierPairIdentity(pair2, ctx)
	require.NoError(t, err)
	require.Equal(t, id1, id2)
	cloneAndMutate := func(mutate func(*frontierCanonicalPair, *frontierSignedContext)) [32]byte {
		pair := clonePair()
		changedContext := ctx
		changedContext.CanonicalShardBytes = bytes.Clone(ctx.CanonicalShardBytes)
		changedContext.FullShardConfHash = bytes.Clone(ctx.FullShardConfHash)
		changedContext.GenesisOriginIdentity = bytes.Clone(ctx.GenesisOriginIdentity)
		mutate(&pair, &changedContext)
		id, identityErr := frontierPairIdentity(pair, changedContext)
		require.NoError(t, identityErr)
		return id
	}
	changes := []struct {
		name   string
		mutate func(*frontierCanonicalPair, *frontierSignedContext)
	}{
		{"input timestamp", func(p *frontierCanonicalPair, _ *frontierSignedContext) { p.UC.InputRecord.Timestamp++ }},
		{"seal root round", func(p *frontierCanonicalPair, _ *frontierSignedContext) { p.UC.UnicitySeal.RootChainRoundNumber++ }},
		{"seal time", func(p *frontierCanonicalPair, _ *frontierSignedContext) { p.UC.UnicitySeal.Timestamp++ }},
		{"TR assignment", func(p *frontierCanonicalPair, _ *frontierSignedContext) { p.TR.Round++ }},
		{"network", func(_ *frontierCanonicalPair, c *frontierSignedContext) { c.NetworkID++ }},
		{"partition", func(_ *frontierCanonicalPair, c *frontierSignedContext) { c.PartitionID++ }},
		{"shard", func(_ *frontierCanonicalPair, c *frontierSignedContext) { c.CanonicalShardBytes[0] ^= 1 }},
		{"config", func(_ *frontierCanonicalPair, c *frontierSignedContext) { c.FullShardConfHash[0] ^= 1 }},
		{"root epoch", func(_ *frontierCanonicalPair, c *frontierSignedContext) { c.RootEpoch++ }},
		{"origin", func(_ *frontierCanonicalPair, c *frontierSignedContext) { c.GenesisOriginIdentity[0] ^= 1 }},
	}
	for _, tc := range changes {
		t.Run(tc.name, func(t *testing.T) { require.NotEqual(t, id1, cloneAndMutate(tc.mutate)) })
	}
	qc1, err := types.Cbor.Marshal(sample.View.CommitQC)
	require.NoError(t, err)
	qc := cloneFrontierQC(t, sample.View.CommitQC)
	for author := range qc.Signatures {
		qc.Signatures[author][0] ^= 0xff
		break
	}
	qc2, err := types.Cbor.Marshal(qc)
	require.NoError(t, err)
	require.NotEqual(t, sha256.Sum256(qc1), sha256.Sum256(qc2))
}
