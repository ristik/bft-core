package signingauthority

import (
	"bytes"
	"context"
	gocrypto "crypto"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
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

	// generation is the current client session. Only the operator control plane advances it, and a
	// client cannot mint one: Session carries no exported field to set. Time is never used as proof
	// that an old process has stopped; the key owner checks this counter on every operation (§5).
	generation uint64
	// state latches faulted on a detected inconsistency and never recovers within this lifetime.
	state health
	// rec is the one reservation this authority holds.
	rec record
}

// Session is a client's admission token for one generation of one authority.
//
// Its zero value is never admitted, and outside this package there is no way to construct a
// non-zero one: taking over from an old client is an operator operation (ReplaceSession), not
// something a client can do by presenting a number it chose.
type Session struct{ generation uint64 }

// Generation reports which generation this token belongs to, for diagnostics and logging.
func (s Session) Generation() uint64 { return s.generation }

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

// Close discards the key and the signing record together. It models the end of an authority
// lifetime, and there is deliberately no counterpart that restores one: a closed authority cannot be
// revived, only replaced by a new enrollment with a new key.
//
// The two go together on purpose (§6). A record that outlived its key would describe signing that
// nothing can perform, and a key that outlived its record would be able to sign a round again.
func (a *Authority) Close() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.signer = nil
	a.rec = record{}
}

/*
ReplaceSession fences the current client and admits a new one.

This is the operator control plane, not something a client may invoke on its own behalf in a
deployment: separating those credentials is what stops a stale shard process from taking itself back
into service. It advances the generation, so every token issued earlier stops being admitted, and it
changes nothing else. In particular it does not clear the record: a new client inherits the same
history, which is the point of fencing rather than restarting.
*/
func (a *Authority) ReplaceSession() (Session, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.signer == nil {
		return Session{}, fmt.Errorf("%w: this authority has no key for %s", ErrKeyLost, a.enroll.NodeID)
	}
	if a.state != healthActive {
		return Session{}, fmt.Errorf("%w: this authority has latched faulted", ErrStateUntrusted)
	}
	if a.generation == math.MaxUint64 {
		// Exhaustion disables admission rather than wrapping: a wrapped generation would admit a
		// token that was fenced long ago (§5).
		a.state = healthFaulted
		return Session{}, fmt.Errorf("%w: the generation space is exhausted", ErrStateUntrusted)
	}
	a.generation++
	return Session{generation: a.generation}, nil
}

// MarkUntrusted latches this authority faulted, for an operator or a caller that has detected an
// inconsistency the authority itself cannot see. It is one way: the record is kept, the key is kept,
// and nothing further is signed (§5, §6).
func (a *Authority) MarkUntrusted(reason string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.state = healthFaulted
	_ = reason
}

// Status is a diagnostic view of the authority. It deliberately carries no request bytes and no
// response: it says what is reserved, not what was signed.
type Status struct {
	Generation       uint64
	ReservedRound    uint64
	HasReservation   bool
	ResponseRetained bool
	Faulted          bool
	KeyLost          bool
}

// Status reports what this authority is holding.
func (a *Authority) Status() Status {
	a.mu.Lock()
	defer a.mu.Unlock()
	return Status{
		Generation:       a.generation,
		ReservedRound:    a.rec.reserved,
		HasReservation:   !a.rec.empty(),
		ResponseRetained: len(a.rec.retained) != 0,
		Faulted:          a.state != healthActive,
		KeyLost:          a.signer == nil,
	}
}

// admitLocked is the guard every client operation shares: a key, a healthy record, and the current
// generation. It latches faulted when the record's own parts disagree, and it never clears them.
func (a *Authority) admitLocked(s Session) error {
	if a.signer == nil {
		return fmt.Errorf("%w: this authority has no key for %s", ErrKeyLost, a.enroll.NodeID)
	}
	if a.state != healthActive {
		return fmt.Errorf("%w: this authority has latched faulted and signs nothing further", ErrStateUntrusted)
	}
	if err := a.rec.checkInvariants(); err != nil {
		a.state = healthFaulted
		return fmt.Errorf("%w: %w", ErrStateUntrusted, err)
	}
	if s.generation == 0 || s.generation != a.generation {
		return fmt.Errorf("%w: session %d, current generation is %d", ErrFenced, s.generation, a.generation)
	}
	return nil
}

/*
Reserve authenticates a request and locks the assigned partition round to its complete bytes.

The conflict key is that round, together with the enrolled key and profile. For one round there is
at most one unsigned request: a second authorization for the same round, however genuine, cannot
authorize different bytes, and a round below the highest reserved one is refused even when the bytes
are identical. Reserving is idempotent for the same bytes, so a client that lost its answer retries
rather than rebuilding.

A cancelled caller does not undo an admitted reservation (§6). Cancellation stops waiting; it does
not return the round.
*/
func (a *Authority) Reserve(ctx context.Context, s Session, req Request) (*Authorization, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Admission is checked before the work, so a fenced client cannot make this authority
	// authenticate anything on its behalf. It is checked again below, because fencing may win while
	// the trust lookup is in flight.
	a.mu.Lock()
	err := a.admitLocked(s)
	a.mu.Unlock()
	if err != nil {
		return nil, err
	}

	auth, err := a.Authenticate(ctx, req)
	if err != nil {
		return nil, err
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.admitLocked(s); err != nil {
		return nil, err
	}
	switch {
	case a.rec.empty() || auth.AssignedRound > a.rec.reserved:
		// A higher round replaces the record, including any response for the older one: the slot is
		// bounded, and the older work is superseded rather than kept. Gaps are permitted, because an
		// authenticated technical record assigns the round and those are not consecutive integers.
		next := record{
			reserved:        auth.AssignedRound,
			unsigned:        bytes.Clone(auth.Unsigned),
			digest:          auth.UnsignedDigest,
			authorizationID: bytes.Clone(auth.ID),
		}
		if size := next.size(); size > MaxRecordBytes {
			return nil, fmt.Errorf("%w: record would be %d bytes, limit is %d", ErrRequestTooLarge, size, MaxRecordBytes)
		}
		a.rec = next
		return auth, nil
	case auth.AssignedRound < a.rec.reserved:
		return nil, fmt.Errorf("%w: round %d is below the reserved round %d", ErrStale, auth.AssignedRound, a.rec.reserved)
	case !a.rec.sameRequest(auth.Unsigned):
		return nil, fmt.Errorf("%w: round %d is reserved for different bytes", ErrConflict, a.rec.reserved)
	default:
		return auth, nil
	}
}

// Sign signs the reserved request, and nothing else.
//
// It signs the bytes this authority owns, not bytes supplied now, so a caller cannot present
// something else to be signed under a reservation it made earlier. A signature that has already
// been retained makes this a no-op, and a failure leaves the reservation in place: the round is
// never reclaimed for different bytes (§5).
func (a *Authority) Sign(s Session) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.admitLocked(s); err != nil {
		return err
	}
	if a.rec.empty() {
		return fmt.Errorf("%w: nothing is reserved", ErrNoReservation)
	}
	if len(a.rec.retained) != 0 {
		return nil
	}
	var proposed certification.BlockCertificationRequest
	if err := types.Cbor.Unmarshal(a.rec.unsigned, &proposed); err != nil {
		a.state = healthFaulted
		return fmt.Errorf("%w: the reserved request does not decode: %w", ErrStateUntrusted, err)
	}
	if err := proposed.Sign(a.signer); err != nil {
		return fmt.Errorf("signing the reserved request: %w", err)
	}
	signed, err := types.Cbor.Marshal(proposed)
	if err != nil {
		return fmt.Errorf("encoding the signed request: %w", err)
	}
	a.rec.signed = signed
	return nil
}

// RetainResponse makes the signed response replayable before any of it can leave.
//
// Retention comes before release so that a caller which disappears mid-answer gets identical bytes
// when it asks again, rather than a second signature over the same round (§6).
func (a *Authority) RetainResponse(s Session) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.admitLocked(s); err != nil {
		return err
	}
	if a.rec.empty() {
		return fmt.Errorf("%w: nothing is reserved", ErrNoReservation)
	}
	if len(a.rec.signed) == 0 {
		return fmt.Errorf("%w: nothing has been signed for round %d", ErrResponseNotRetained, a.rec.reserved)
	}
	if len(a.rec.retained) != 0 {
		return nil
	}
	candidate := a.rec
	candidate.retained = bytes.Clone(candidate.signed)
	if size := candidate.size(); size > MaxRecordBytes {
		return fmt.Errorf("%w: record would be %d bytes, limit is %d", ErrRequestTooLarge, size, MaxRecordBytes)
	}
	a.rec = candidate
	return nil
}

/*
Release hands back the retained response for one named reservation.

The caller names both the round and the digest of the request it asked about, and both must be the
reservation this authority is holding. That is what stops a delayed call for an older reservation
from receiving the response of the newer one now occupying the slot (§5).
*/
func (a *Authority) Release(s Session, round uint64, digest [32]byte) ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.admitLocked(s); err != nil {
		return nil, err
	}
	if a.rec.empty() {
		return nil, fmt.Errorf("%w: nothing is reserved", ErrNoReservation)
	}
	if round != a.rec.reserved {
		return nil, fmt.Errorf("%w: asked for round %d, the reservation is round %d", ErrStale, round, a.rec.reserved)
	}
	if digest != a.rec.digest {
		return nil, fmt.Errorf("%w: round %d is reserved for different bytes", ErrConflict, a.rec.reserved)
	}
	if len(a.rec.retained) == 0 {
		return nil, fmt.Errorf("%w: round %d has no retained response", ErrResponseNotRetained, a.rec.reserved)
	}
	return bytes.Clone(a.rec.retained), nil
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

	// One owned snapshot, taken before any check. Everything below reads `own` and nothing reads
	// the caller's structures, because the caller may change them while this authority is waiting
	// for its trust base. An earlier revision encoded the proposal first and validated the caller's
	// structure afterwards, so a change during that window produced an authorization whose
	// validated content and returned preimage were two different messages.
	own, unsigned, err := req.snapshot()
	if err != nil {
		return nil, err
	}

	if own.UC.Version != 1 {
		return nil, fmt.Errorf("%w: certificate version %d", ErrUnsupportedVersion, own.UC.Version)
	}
	if own.Proposed.InputRecord.Version != 1 {
		return nil, fmt.Errorf("%w: input record version %d", ErrUnsupportedVersion, own.Proposed.InputRecord.Version)
	}

	// Enrollment guards. These compare the request against fixed values, so a caller cannot reach a
	// different record by naming a different node, partition or shard.
	if own.Proposed.NodeID != enroll.NodeID {
		return nil, fmt.Errorf("%w: proposal is for node %q, this authority signs for %q", ErrContextMismatch, own.Proposed.NodeID, enroll.NodeID)
	}
	if own.Proposed.PartitionID != enroll.PartitionID {
		return nil, fmt.Errorf("%w: proposal is for partition %d, this authority signs for %d", ErrContextMismatch, own.Proposed.PartitionID, enroll.PartitionID)
	}
	if !own.Proposed.ShardID.Equal(enroll.ShardID) {
		return nil, fmt.Errorf("%w: proposal is for shard %s, this authority signs for %s", ErrContextMismatch, own.Proposed.ShardID, enroll.ShardID)
	}

	// Context checks come first and are their own refusal. UC.Verify would also reject a certificate
	// for another partition, shard or configuration, but it reports that the way it reports a bad
	// signature, and the two are different situations: one is a root chain or peer serving another
	// chain, the other is a forgery. The values compared are this authority's own enrollment.
	if own.UC.GetPartitionID() != enroll.PartitionID {
		return nil, fmt.Errorf("%w: certificate is for partition %d, this authority signs for %d", ErrContextMismatch, own.UC.GetPartitionID(), enroll.PartitionID)
	}
	if !own.UC.GetShardID().Equal(enroll.ShardID) {
		return nil, fmt.Errorf("%w: certificate is for shard %s, this authority signs for %s", ErrContextMismatch, own.UC.GetShardID(), enroll.ShardID)
	}
	if !bytes.Equal(own.UC.ShardConfHash, enroll.ShardConfHash) {
		return nil, fmt.Errorf("%w: certificate names shard configuration %x, this authority is enrolled for %x", ErrContextMismatch, own.UC.ShardConfHash, enroll.ShardConfHash)
	}

	// The root epoch is frozen by enrollment, and this refusal is deliberately not an
	// authentication failure: a certificate from the next genuine root epoch verifies perfectly
	// against that epoch's trust base, which is precisely why accepting it here would carry this
	// key across a transition the profile does not support (§4).
	//
	// The check comes BEFORE the trust lookup on purpose, so that an epoch chosen by whoever sent
	// the request cannot drive which trust base this authority fetches. The cost is that a forged
	// certificate which also names another epoch is refused here, before anything about it has been
	// authenticated, so the message says what the certificate CLAIMS and does not assert that the
	// certificate is genuine. A certificate naming the enrolled epoch reaches verification below,
	// where a forgery is reported as one.
	if own.UC.GetRootEpoch() != *enroll.RootEpoch {
		return nil, fmt.Errorf("%w: certificate claims root epoch %d, this authority is enrolled for %d and does not follow a transition; refused before authentication, so the claim is not established", ErrContextMismatch, own.UC.GetRootEpoch(), *enroll.RootEpoch)
	}

	// Authentication against the authority's own trust, for the root epoch the certificate names.
	// An unknown epoch is a refusal rather than a reason to trust the certificate's own claim.
	tb, err := trust.GetByEpoch(ctx, own.UC.GetRootEpoch())
	if err != nil {
		return nil, fmt.Errorf("%w: root epoch %d: %w", ErrUnauthenticated, own.UC.GetRootEpoch(), err)
	}
	if tb == nil {
		return nil, fmt.Errorf("%w: no trust base for root epoch %d", ErrUnauthenticated, own.UC.GetRootEpoch())
	}
	// The legacy preimage carries no network identifier, so the network is enforced as an enrollment
	// guard against the provisioned trust base rather than read off the message (§2).
	if tb.GetNetworkID() != enroll.NetworkID {
		return nil, fmt.Errorf("%w: trust base is for network %d, this authority is enrolled for %d", ErrContextMismatch, tb.GetNetworkID(), enroll.NetworkID)
	}
	if err := own.UC.Verify(tb, gocrypto.SHA256, enroll.PartitionID, enroll.ShardID, enroll.ShardConfHash); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnauthenticated, err)
	}
	if err := own.Technical.IsValid(); err != nil {
		return nil, fmt.Errorf("%w: technical record: %w", ErrUnauthenticated, err)
	}
	if err := own.Technical.HashMatches(own.UC.TRHash); err != nil {
		return nil, fmt.Errorf("%w: technical record is not the one this certificate binds: %w", ErrUnauthenticated, err)
	}

	// Shard epoch is frozen by enrollment for the same reason as the root epoch above.
	if own.Technical.Epoch != enroll.ShardEpoch {
		return nil, fmt.Errorf("%w: assignment is for shard epoch %d, this authority is enrolled for %d", ErrContextMismatch, own.Technical.Epoch, enroll.ShardEpoch)
	}
	if own.UC.InputRecord.Epoch != enroll.ShardEpoch {
		return nil, fmt.Errorf("%w: certificate is for shard epoch %d, this authority is enrolled for %d", ErrContextMismatch, own.UC.InputRecord.Epoch, enroll.ShardEpoch)
	}

	// The proposal must be the one this authorization assigns. Round and epoch come from the
	// authenticated technical record, never from the proposal itself.
	if err := validateProposal(own.Proposed.InputRecord, expectationFrom(own.UC, own.Technical)); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrProposalMismatch, err)
	}

	id, err := authorizationID(own.UC, own.Technical)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnauthenticated, err)
	}
	return &Authorization{
		AssignedRound:  own.Technical.Round,
		AssignedEpoch:  own.Technical.Epoch,
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
