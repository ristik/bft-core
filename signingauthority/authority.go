package signingauthority

import (
	"bytes"
	"context"
	gocrypto "crypto"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"

	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

// TrustBases is the authority's own provisioned root trust, keyed by root epoch. It is deliberately
// a source the authority holds rather than an argument a requester supplies: "root trust and
// configuration come from the authority's own provisioned context, never from the requester's
// claimed verifier result" (§4).
type TrustBases interface {
	GetByEpoch(ctx context.Context, epoch uint64) (*types.RootTrustBaseV1, error)
}

// Authority owns one signing key for one enrolled scope.
//
// The key is generated here, lives in this process only, and has no import, export or unwrap path.
// That is the profile's central trade (§1 and ADR 0009): losing this process loses the ability to
// sign for this identity, and in exchange no replayable file can ever be presented as this
// validator's signing history.
type Authority struct {
	mu     sync.Mutex
	enroll Enrollment
	trust  TrustBases
	// signer is nil once the authority is closed. Nothing can put a key back.
	signer abcrypto.Signer
}

// New enrolls a fresh authority lifetime and generates its signing key.
//
// There is no variant of this function that accepts a key, a seed, a key file or a previous
// fingerprint. An enrollment that names a signing key is refused rather than honoured, because the
// only way to hold a key here is to have generated it (Q3: existing exported keys are not silently
// imported and are given no reconstructed signing history).
func New(enroll Enrollment, trust TrustBases) (*Authority, error) {
	if len(enroll.SigningKeyFingerprint) != 0 {
		return nil, errors.New("signingauthority: enrollment names a signing key, and this profile has no key-import path: it generates a key per authority lifetime")
	}
	if err := enroll.validate(); err != nil {
		return nil, fmt.Errorf("signingauthority: %w", err)
	}
	if trust == nil {
		return nil, errors.New("signingauthority: no root trust provisioned, so no certificate could be authenticated")
	}
	signer, err := abcrypto.NewInMemorySecp256K1Signer()
	if err != nil {
		return nil, fmt.Errorf("signingauthority: generating the signing key: %w", err)
	}
	pub, err := publicKeyOf(signer)
	if err != nil {
		return nil, fmt.Errorf("signingauthority: %w", err)
	}
	fingerprint := sha256.Sum256(pub)
	enroll = enroll.clone()
	enroll.SigningKeyFingerprint = fingerprint[:]
	return &Authority{enroll: enroll, trust: trust, signer: signer}, nil
}

// Enrollment returns a copy of the immutable scope this authority signs for.
func (a *Authority) Enrollment() Enrollment {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.enroll.clone()
}

// SigningPublicKey returns the public half of the key generated for this lifetime. A replacement
// authority returns a different key, which is what makes "the same identity came back" impossible
// to claim by restarting a process (§5).
func (a *Authority) SigningPublicKey() ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.signer == nil {
		return nil, fmt.Errorf("%w: this authority has been closed", ErrKeyLost)
	}
	return publicKeyOf(a.signer)
}

// Close discards the key. It models the end of an authority lifetime, and there is deliberately no
// counterpart that restores one: a closed authority cannot be revived, only replaced by a new
// enrollment with a new key.
func (a *Authority) Close() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.signer = nil
}

/*
Authenticate checks one structured request against this authority's enrollment and its own root
trust, and reports the authorization it belongs to.

It answers "is this a genuine assignment for the scope I signed up for, and is this proposal the one
it assigns", and nothing else. It is not permission to sign and it does not record anything: a
replayed but genuine authorization passes here every time, and the signing record of step 2 is what
refuses it. Keeping the two apart is the point of the split, because authenticity is not freshness.
*/
func (a *Authority) Authenticate(ctx context.Context, req Request) (*Authorization, error) {
	a.mu.Lock()
	enroll, trust, hasKey := a.enroll, a.trust, a.signer != nil
	a.mu.Unlock()

	if !hasKey {
		return nil, fmt.Errorf("%w: this authority has no key for %s", ErrKeyLost, enroll.NodeID)
	}
	if err := req.validate(); err != nil {
		return nil, err
	}
	if req.UC.Version != 1 {
		return nil, fmt.Errorf("%w: certificate version %d", ErrUnsupportedVersion, req.UC.Version)
	}
	if req.Proposed.InputRecord.Version != 1 {
		return nil, fmt.Errorf("%w: input record version %d", ErrUnsupportedVersion, req.Proposed.InputRecord.Version)
	}

	// Enrollment guards. These compare the request against fixed values, so a caller cannot reach a
	// different record by naming a different node, partition or shard.
	if req.Proposed.NodeID != enroll.NodeID {
		return nil, fmt.Errorf("%w: proposal is for node %q, this authority signs for %q", ErrContextMismatch, req.Proposed.NodeID, enroll.NodeID)
	}
	if req.Proposed.PartitionID != enroll.PartitionID {
		return nil, fmt.Errorf("%w: proposal is for partition %d, this authority signs for %d", ErrContextMismatch, req.Proposed.PartitionID, enroll.PartitionID)
	}
	if !req.Proposed.ShardID.Equal(enroll.ShardID) {
		return nil, fmt.Errorf("%w: proposal is for shard %s, this authority signs for %s", ErrContextMismatch, req.Proposed.ShardID, enroll.ShardID)
	}

	// The complete signature-free preimage, and its size, before anything is retained (§5 bounds).
	unsigned, err := req.Proposed.Bytes()
	if err != nil {
		return nil, fmt.Errorf("%w: encoding the proposal: %w", ErrProposalMismatch, err)
	}
	if len(unsigned) > MaxUnsignedRequestBytes {
		return nil, fmt.Errorf("%w: %d bytes, limit is %d", ErrRequestTooLarge, len(unsigned), MaxUnsignedRequestBytes)
	}

	// Context checks come first and are their own refusal. UC.Verify would also reject a certificate
	// for another partition, shard or configuration, but it reports that the way it reports a bad
	// signature, and the two are different situations: one is a root chain or peer serving another
	// chain, the other is a forgery. The values compared are this authority's own enrollment.
	if req.UC.GetPartitionID() != enroll.PartitionID {
		return nil, fmt.Errorf("%w: certificate is for partition %d, this authority signs for %d", ErrContextMismatch, req.UC.GetPartitionID(), enroll.PartitionID)
	}
	if !req.UC.GetShardID().Equal(enroll.ShardID) {
		return nil, fmt.Errorf("%w: certificate is for shard %s, this authority signs for %s", ErrContextMismatch, req.UC.GetShardID(), enroll.ShardID)
	}
	if !bytes.Equal(req.UC.ShardConfHash, enroll.ShardConfHash) {
		return nil, fmt.Errorf("%w: certificate names shard configuration %x, this authority is enrolled for %x", ErrContextMismatch, req.UC.ShardConfHash, enroll.ShardConfHash)
	}

	// Authentication against the authority's own trust, for the root epoch the certificate names.
	// An unknown epoch is a refusal rather than a reason to trust the certificate's own claim.
	tb, err := trust.GetByEpoch(ctx, req.UC.GetRootEpoch())
	if err != nil {
		return nil, fmt.Errorf("%w: root epoch %d: %w", ErrUnauthenticated, req.UC.GetRootEpoch(), err)
	}
	if tb == nil {
		return nil, fmt.Errorf("%w: no trust base for root epoch %d", ErrUnauthenticated, req.UC.GetRootEpoch())
	}
	// The legacy preimage carries no network identifier, so the network is enforced as an enrollment
	// guard against the provisioned trust base rather than read off the message (§2).
	if tb.GetNetworkID() != enroll.NetworkID {
		return nil, fmt.Errorf("%w: trust base is for network %d, this authority is enrolled for %d", ErrContextMismatch, tb.GetNetworkID(), enroll.NetworkID)
	}
	if err := req.UC.Verify(tb, gocrypto.SHA256, enroll.PartitionID, enroll.ShardID, enroll.ShardConfHash); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnauthenticated, err)
	}
	if err := req.Technical.IsValid(); err != nil {
		return nil, fmt.Errorf("%w: technical record: %w", ErrUnauthenticated, err)
	}
	if err := req.Technical.HashMatches(req.UC.TRHash); err != nil {
		return nil, fmt.Errorf("%w: technical record is not the one this certificate binds: %w", ErrUnauthenticated, err)
	}

	// Epoch is frozen by enrollment. A transition is refused here rather than served under a new
	// scope, because a new scope is exactly how an old decision would be escaped (§4).
	if req.Technical.Epoch != enroll.ShardEpoch {
		return nil, fmt.Errorf("%w: assignment is for shard epoch %d, this authority is enrolled for %d", ErrContextMismatch, req.Technical.Epoch, enroll.ShardEpoch)
	}
	if req.UC.InputRecord.Epoch != enroll.ShardEpoch {
		return nil, fmt.Errorf("%w: certificate is for shard epoch %d, this authority is enrolled for %d", ErrContextMismatch, req.UC.InputRecord.Epoch, enroll.ShardEpoch)
	}

	// The proposal must be the one this authorization assigns. Round and epoch come from the
	// authenticated technical record, never from the proposal itself.
	if err := validateProposal(req.Proposed.InputRecord, expectationFrom(req.UC, req.Technical)); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrProposalMismatch, err)
	}

	id, err := authorizationID(req.UC, req.Technical)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnauthenticated, err)
	}
	return &Authorization{
		AssignedRound:  req.Technical.Round,
		AssignedEpoch:  req.Technical.Epoch,
		ID:             id,
		Unsigned:       unsigned,
		UnsignedDigest: sha256.Sum256(unsigned),
	}, nil
}

func publicKeyOf(signer abcrypto.Signer) ([]byte, error) {
	verifier, err := signer.Verifier()
	if err != nil {
		return nil, fmt.Errorf("deriving the verifier: %w", err)
	}
	pub, err := verifier.MarshalPublicKey()
	if err != nil {
		return nil, fmt.Errorf("encoding the public key: %w", err)
	}
	return pub, nil
}

// expectation is what the authenticated certificate and technical record require of a proposal.
//
// It restates shardnode.ExpectationFromCertificate and shardnode.ValidateLocal rather than calling
// them, because step 3 wires the shard node's Round to this authority and importing shardnode here
// would make that a cycle. The duplication is deliberate and pinned:
// TestExpectationMatchesTheShardNodeRule in the external test package fails if the two rules drift.
type expectation struct {
	round        uint64
	epoch        uint64
	previousHash []byte
	timestamp    uint64
}

func expectationFrom(uc *types.UnicityCertificate, tr *certification.TechnicalRecord) expectation {
	return expectation{
		round:        tr.Round,
		epoch:        tr.Epoch,
		previousHash: uc.InputRecord.Hash,
		timestamp:    uc.UnicitySeal.Timestamp,
	}
}

func validateProposal(ir *types.InputRecord, exp expectation) error {
	if err := ir.IsValid(); err != nil {
		return fmt.Errorf("input record: %w", err)
	}
	if ir.RoundNumber != exp.round {
		return fmt.Errorf("round number: have %d, this authorization assigns %d", ir.RoundNumber, exp.round)
	}
	if ir.Epoch != exp.epoch {
		return fmt.Errorf("epoch: have %d, this authorization assigns %d", ir.Epoch, exp.epoch)
	}
	if !bytes.Equal(ir.PreviousHash, exp.previousHash) {
		return fmt.Errorf("previous hash: have %x, the certified state is %x", ir.PreviousHash, exp.previousHash)
	}
	if ir.Timestamp != exp.timestamp {
		return fmt.Errorf("timestamp: have %d, the seal's is %d", ir.Timestamp, exp.timestamp)
	}
	return nil
}
