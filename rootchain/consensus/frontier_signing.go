package consensus

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-core/rootchain/consensus/internal/frontiercodec"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

const (
	frontierSigningDomain = frontiercodec.SigningDomain
	frontierPairDomain    = frontiercodec.PairDomain
	frontierSigningV1     = frontiercodec.Version
	frontierMaxAuthor     = frontiercodec.MaxAuthor
	frontierMaxSignature  = frontiercodec.MaxSignature
	frontierMaxSignedPart = frontiercodec.MaxPart
	frontierMaxReply      = frontiercodec.MaxReply
)

var ErrFrontierSigningDisabled = errors.New("root frontier signing is disabled")

// SignedFrontierRequest binds a signed response to caller-selected acquisition
// context. GenesisOriginIdentity is echoed binding only, not root endorsement.
type SignedFrontierRequest struct {
	FrontierRequest
	RootEpoch             uint64
	GenesisOriginIdentity []byte
	Nonce                 []byte
}

// SignedFrontierResponse contains an owned canonical reply encoding:
// [1, author, pairBytes, qcBytes, signature], where pairBytes is canonical
// [UC, TR] and qcBytes is the canonical full QC. It is diagnostic evidence only; remote
// authentication, quorum collection, cut proof and bootstrap admission are
// separate protocol stages.
type SignedFrontierResponse struct{ wire []byte }

func (r *SignedFrontierResponse) CanonicalBytes() []byte {
	if r == nil {
		return nil
	}
	return bytes.Clone(r.wire)
}

type frontierSignedContext = frontiercodec.Context
type frontierCanonicalPair = frontiercodec.Pair
type frontierPairIdentityTuple = frontiercodec.PairIdentityTuple
type frontierSigningPreimage = frontiercodec.SigningPreimage
type frontierSignedReply = frontiercodec.Reply

type signedFrontierRequest struct {
	context frontierSignedContext
	nonce   []byte
}

func (s *frontierSampler) enableSigning(author string, signer abcrypto.Signer) error {
	if signer == nil || len(author) == 0 || len(author) > frontierMaxAuthor {
		return errors.New("invalid frontier signing identity")
	}
	var enrolledKey []byte
	for _, n := range s.trust.RootNodes {
		if n.NodeID == author {
			enrolledKey = n.SigKey
			break
		}
	}
	if len(enrolledKey) == 0 {
		return errors.New("frontier signing author is not enrolled")
	}
	verifier, err := signer.Verifier()
	if err != nil {
		return fmt.Errorf("frontier signing verifier: %w", err)
	}
	key, err := verifier.MarshalPublicKey()
	if err != nil {
		return fmt.Errorf("frontier signing public key: %w", err)
	}
	if !bytes.Equal(key, enrolledKey) {
		return errors.New("frontier signing key does not match enrolled author")
	}
	s.signing, s.author, s.signer = true, author, signer
	return nil
}

func (x *ConsensusManager) SampleSignedFrontier(ctx context.Context, req SignedFrontierRequest) (*SignedFrontierResponse, error) {
	if x == nil || x.frontier == nil || !x.frontier.signing {
		return nil, ErrFrontierSigningDisabled
	}
	if ctx == nil || req.NetworkID == 0 || req.PartitionID == 0 || req.ShardID.Length() > frontierMaxShardBits || len(req.FullShardConfHash) != crypto.SHA256.Size() || req.RootEpoch == 0 || len(req.GenesisOriginIdentity) != sha256.Size || len(req.Nonce) != sha256.Size {
		return nil, fmt.Errorf("%w: invalid signed request context", ErrFrontierUnavailable)
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
	canonicalShard := ownedShard.Bytes()
	if len(canonicalShard) > frontierMaxSignedPart {
		return nil, fmt.Errorf("%w: shard identity exceeds signing bounds", ErrFrontierUnavailable)
	}
	owned := FrontierRequest{NetworkID: req.NetworkID, PartitionID: req.PartitionID, ShardID: ownedShard, FullShardConfHash: bytes.Clone(req.FullShardConfHash)}
	signed := &signedFrontierRequest{context: frontierSignedContext{NetworkID: req.NetworkID, PartitionID: req.PartitionID, CanonicalShardBytes: bytes.Clone(canonicalShard), FullShardConfHash: bytes.Clone(req.FullShardConfHash), RootEpoch: req.RootEpoch, GenesisOriginIdentity: bytes.Clone(req.GenesisOriginIdentity)}, nonce: bytes.Clone(req.Nonce)}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	out, err := x.submitFrontierRequest(ctx, frontierRequest{ctx: ctx, req: owned, signed: signed, reply: make(chan frontierReply, 1)})
	return out.signed, err
}

func (x *ConsensusManager) signFrontierSample(callerCtx, managerCtx context.Context, req FrontierRequest, signed *signedFrontierRequest, sample *FrontierSample) (*SignedFrontierResponse, error) {
	s := x.frontier
	if s == nil || !s.signing || sample == nil || sample.View == nil || signed == nil || signed.context.RootEpoch != s.trust.Epoch || signed.context.NetworkID != req.NetworkID || signed.context.PartitionID != req.PartitionID || !bytes.Equal(signed.context.CanonicalShardBytes, req.ShardID.Bytes()) || !bytes.Equal(signed.context.FullShardConfHash, req.FullShardConfHash) {
		return nil, ErrFrontierUnavailable
	}
	qc := sample.View.CommitQC
	if sample.CoveringQC == FrontierHighQC {
		qc = sample.View.HighQC
	}
	pair := frontierCanonicalPair{UC: &sample.View.LastCR.UC, TR: &sample.View.LastCR.Technical}
	pairBytes, err := types.Cbor.Marshal(pair)
	if err != nil || len(pairBytes) == 0 || len(pairBytes) > frontierMaxSignedPart {
		return nil, fmt.Errorf("%w: canonical pair bounds", ErrFrontierUnavailable)
	}
	qcBytes, err := types.Cbor.Marshal(qc)
	if err != nil || len(qcBytes) == 0 || len(qcBytes) > frontierMaxSignedPart {
		return nil, fmt.Errorf("%w: canonical QC bounds", ErrFrontierUnavailable)
	}
	pairID, err := frontierPairIdentity(pair, signed.context)
	if err != nil {
		return nil, fmt.Errorf("%w: pair identity: %v", ErrFrontierUnavailable, err)
	}
	qcDigest := sha256.Sum256(qcBytes)
	preimage, err := types.Cbor.Marshal(frontierSigningPreimage{Domain: frontierSigningDomain, Version: frontierSigningV1, Context: signed.context, Nonce: signed.nonce, Author: s.author, PairID: pairID[:], QCDigest: qcDigest[:]})
	if err != nil || len(preimage) > frontierMaxReply {
		return nil, fmt.Errorf("%w: signing preimage bounds", ErrFrontierUnavailable)
	}
	if err := frontierSignState(callerCtx, managerCtx, s, x); err != nil {
		return nil, err
	}
	signature, err := s.signer.SignBytes(bytes.Clone(preimage))
	if err != nil {
		return nil, fmt.Errorf("%w: signing failed: %v", ErrFrontierUnavailable, err)
	}
	if len(signature) == 0 || len(signature) > frontierMaxSignature {
		return nil, fmt.Errorf("%w: signature bounds", ErrFrontierUnavailable)
	}
	verifiedSignature := bytes.Clone(signature)
	if _, err := s.trust.VerifySignature(preimage, verifiedSignature, s.author); err != nil {
		return nil, fmt.Errorf("%w: signer returned invalid signature", ErrFrontierUnavailable)
	}
	if err := frontierSignState(callerCtx, managerCtx, s, x); err != nil {
		return nil, err
	}
	reply, err := types.Cbor.Marshal(frontierSignedReply{Version: frontierSigningV1, Author: s.author, Pair: bytes.Clone(pairBytes), QC: bytes.Clone(qcBytes), Signature: verifiedSignature})
	if err != nil || len(reply) == 0 || len(reply) > frontierMaxReply {
		return nil, fmt.Errorf("%w: signed reply bounds", ErrFrontierUnavailable)
	}
	return &SignedFrontierResponse{wire: bytes.Clone(reply)}, nil
}

func frontierSignState(callerCtx, managerCtx context.Context, s *frontierSampler, x *ConsensusManager) error {
	if err := callerCtx.Err(); err != nil {
		return err
	}
	if err := managerCtx.Err(); err != nil {
		return ErrFrontierStopped
	}
	if s.runState.Load() != 1 || !s.eligible.Load() || s.faulted.Load() || x.recovery.InRecovery() {
		return ErrFrontierUnavailable
	}
	return nil
}

func frontierPairIdentity(pair frontierCanonicalPair, context frontierSignedContext) ([32]byte, error) {
	return frontiercodec.PairIdentity(pair, context)
}
