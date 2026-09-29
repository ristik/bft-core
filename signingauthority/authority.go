package signingauthority

import (
	"bytes"
	"context"
	gocrypto "crypto"
	"crypto/rand"
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

	// instance is this authority lifetime's own identity, drawn at random and never published. It is
	// what makes a session token a capability for THIS authority rather than a number: every
	// authority starts its counter at the same value, so a generation alone is admitted by any
	// authority that happens to be at the same count. It is deliberately not in Status, not in
	// Enrollment and not derived from anything an operator can name.
	instance [16]byte
	// generation is the current client session. Only the operator control plane advances it, and a
	// client cannot mint one: Session carries no exported field to set. Time is never used as proof
	// that an old process has stopped; the key owner checks this counter on every operation (§5).
	generation uint64
	// state latches faulted on a detected inconsistency and never recovers within this lifetime.
	state health
	// rec is the one reservation this authority holds.
	rec          record
	scopeVersion uint64
}

type currentTrust struct{ base *types.RootTrustBaseV1 }

func (t currentTrust) GetByEpoch(_ context.Context, epoch uint64) (*types.RootTrustBaseV1, error) {
	if t.base == nil || t.base.Epoch != epoch {
		return nil, fmt.Errorf("root trust epoch %d is not current", epoch)
	}
	return t.base, nil
}

// Session is a client's admission token for one generation of one authority.
//
// Its zero value is never admitted, and outside this package there is no way to construct a
// non-zero one: taking over from an old client is an operator operation (ReplaceSession), not
// something a client can do by presenting a number it chose.
//
// It names the authority that issued it as well as the generation. Without that, a token is only a
// counter, and every authority starts counting at the same place: a token issued by one authority
// was admitted by another that happened to be at the same generation, which is not the "one
// generation of one authority" scope this is supposed to express.
type Session struct {
	authority  [16]byte
	generation uint64
}

// Generation reports which generation this token belongs to, for diagnostics and logging.
func (s Session) Generation() uint64 { return s.generation }

// New enrolls a fresh authority lifetime and generates its signing key.
//
// There is no variant of this function that accepts a key, a seed, a key file or a previous
// fingerprint. An enrollment that names a signing key is refused rather than honoured, because the
// only way to hold a key here is to have generated it (Q3: existing exported keys are not silently
// imported and are given no reconstructed signing history).
//
// An enrollment without a ShardConfHash is pending, and that is how a deployment starts one: the
// configuration that names this key cannot exist before the key does. The public key is available
// at once, the configuration is stated afterwards with CompleteEnrollment, and every other field is
// fixed here.
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
	var instance [16]byte
	if _, err := rand.Read(instance[:]); err != nil {
		return nil, fmt.Errorf("signingauthority: drawing this authority's identity: %w", err)
	}
	pub, err := publicKeyOf(signer)
	if err != nil {
		return nil, fmt.Errorf("signingauthority: %w", err)
	}
	fingerprint := sha256.Sum256(pub)
	enroll = enroll.clone()
	enroll.SigningKeyFingerprint = fingerprint[:]
	return &Authority{enroll: enroll, trust: trust, signer: signer, instance: instance}, nil
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
	if !a.enroll.complete() {
		// No client is admitted to an authority that cannot yet say which configuration it signs
		// for. Issuing a session first would hand out a credential for work that is refused anyway.
		return Session{}, fmt.Errorf("%w: no session is issued before the shard configuration is stated", ErrEnrollmentIncomplete)
	}
	if a.generation == math.MaxUint64 {
		// Exhaustion disables admission rather than wrapping: a wrapped generation would admit a
		// token that was fenced long ago (§5).
		a.state = healthFaulted
		return Session{}, fmt.Errorf("%w: the generation space is exhausted", ErrStateUntrusted)
	}
	a.generation++
	return Session{authority: a.instance, generation: a.generation}, nil
}

/*
CompleteEnrollment states the shard configuration of a pending authority, once.

The configuration hash a certificate commits to covers every validator's signing key, and this
authority generated its key in New, so the configuration naming that key can only be written after
New has returned. This is the step that closes that gap, and it is deliberately narrow:

  - It is accepted only while the enrollment is pending. A second call is refused, including one with
    the same configuration: enrollment is not reopened within an authority lifetime, and a caller
    that could restate it could move the authority to another configuration.
  - The authority checks the configuration against its own state rather than taking a hash from the
    operator. It must be a valid configuration for the enrolled network, partition, shard and shard
    epoch, and it must name the enrolled node with THIS authority's signing public key. A
    configuration that names the node with another key describes a validator this authority cannot
    sign for.
  - The hash is computed here, from the configuration that passed those checks, and becomes the
    enrolled ShardConfHash. From then on it is immutable like every other enrollment field.

Nothing is admitted before this succeeds: ReplaceSession and Authenticate refuse with
ErrEnrollmentIncomplete. A refused completion changes nothing, so the operator can correct the
configuration and try again.
*/
func (a *Authority) CompleteEnrollment(conf *types.PartitionDescriptionRecord) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.signer == nil {
		return fmt.Errorf("%w: this authority has no key for %s", ErrKeyLost, a.enroll.NodeID)
	}
	if a.state != healthActive {
		return fmt.Errorf("%w: this authority has latched faulted", ErrStateUntrusted)
	}
	enroll := a.enroll
	if enroll.complete() {
		return fmt.Errorf("%w: the enrollment is already complete for shard configuration %x and is not reopened", ErrContextMismatch, enroll.ShardConfHash)
	}
	if conf == nil {
		return fmt.Errorf("%w: no shard configuration", ErrContextMismatch)
	}
	if err := conf.IsValid(); err != nil {
		return fmt.Errorf("%w: the shard configuration is not valid: %w", ErrContextMismatch, err)
	}
	switch {
	case conf.NetworkID != enroll.NetworkID:
		return fmt.Errorf("%w: shard configuration is for network %d, this authority is enrolled for %d", ErrContextMismatch, conf.NetworkID, enroll.NetworkID)
	case conf.PartitionID != enroll.PartitionID:
		return fmt.Errorf("%w: shard configuration is for partition %d, this authority is enrolled for %d", ErrContextMismatch, conf.PartitionID, enroll.PartitionID)
	case !conf.ShardID.Equal(enroll.ShardID):
		return fmt.Errorf("%w: shard configuration is for shard %s, this authority is enrolled for %s", ErrContextMismatch, conf.ShardID, enroll.ShardID)
	case conf.Epoch != enroll.ShardEpoch:
		return fmt.Errorf("%w: shard configuration is for shard epoch %d, this authority is enrolled for %d", ErrContextMismatch, conf.Epoch, enroll.ShardEpoch)
	}
	pub, err := publicKeyOf(a.signer)
	if err != nil {
		return err
	}
	// IsValid has already refused duplicate node identifiers, so the first match is the only one.
	var named *types.NodeInfo
	for _, v := range conf.Validators {
		if v.NodeID == enroll.NodeID {
			named = v
			break
		}
	}
	if named == nil {
		return fmt.Errorf("%w: shard configuration does not name node %s", ErrContextMismatch, enroll.NodeID)
	}
	if !bytes.Equal(named.SigKey, pub) {
		given, own := sha256.Sum256(named.SigKey), sha256.Sum256(pub)
		return fmt.Errorf("%w: shard configuration names node %s with signing key %x, this authority's key is %x", ErrContextMismatch, enroll.NodeID, given, own)
	}
	hash, err := conf.Hash(gocrypto.SHA256)
	if err != nil {
		return fmt.Errorf("hashing the shard configuration: %w", err)
	}
	a.enroll.ShardConfHash = hash
	return nil
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
		ResponseRetained: a.rec.releasable,
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
	if s.authority != a.instance {
		// Including a token from a different authority that happens to hold the same generation.
		return fmt.Errorf("%w: this session was not issued by this authority", ErrFenced)
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
	if auth.scopeVersion != a.scopeVersion {
		return nil, fmt.Errorf("%w: enrollment advanced during authentication", ErrContextMismatch)
	}
	switch {
	case a.rec.empty() || auth.AssignedRound > a.rec.reserved:
		// A higher round replaces the record, including any response for the older one: the slot is
		// bounded, and the older work is superseded rather than kept. Gaps are permitted, because an
		// authenticated technical record assigns the round and those are not consecutive integers.
		// What this record will hold once the request has been signed, checked before the round is
		// locked to it. Admitting work that cannot be completed would leave the round answerable by
		// nothing, which is worse than refusing it now.
		//
		// Recorded as untested: it cannot fire while MaxRecordBytes is derived from
		// MaxUnsignedRequestBytes, because the snapshot already refused anything larger. It is here
		// so that raising one cap without the other fails closed rather than admitting work that
		// cannot be retained, which is the defect this repair came from. A mutation disabling it
		// therefore survives the suite; TestAnAdmittedRequestCanAlwaysBeCompleted checks the same
		// property statically instead.
		if size := projectedSize(auth.Unsigned, auth.ID); size > MaxRecordBytes {
			return nil, fmt.Errorf("%w: the completed record would be %d bytes, limit is %d", ErrRequestTooLarge, size, MaxRecordBytes)
		}
		a.rec = record{
			scopeVersion:    a.scopeVersion,
			reserved:        auth.AssignedRound,
			unsigned:        bytes.Clone(auth.Unsigned),
			digest:          auth.UnsignedDigest,
			authorizationID: bytes.Clone(auth.ID),
		}
		return auth, nil
	case auth.AssignedRound < a.rec.reserved:
		return nil, fmt.Errorf("%w: round %d is below the reserved round %d", ErrStale, auth.AssignedRound, a.rec.reserved)
	case a.rec.scopeVersion != a.scopeVersion:
		return nil, fmt.Errorf("%w: round %d was reserved before the enrollment advanced", ErrConflict, a.rec.reserved)
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
	if a.rec.scopeVersion != a.scopeVersion {
		return fmt.Errorf("%w: reservation belongs to the previous enrollment", ErrContextMismatch)
	}
	if a.rec.releasable {
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
	candidate := a.rec
	candidate.signed = signed
	if size := candidate.size(); size > MaxRecordBytes {
		// Unreachable for an admitted request, since Reserve projected this size with room for the
		// signature. Refusing here rather than storing keeps that guarantee checkable instead of
		// assumed, and leaves the reservation intact.
		return fmt.Errorf("%w: the signed record would be %d bytes, limit is %d", ErrRequestTooLarge, size, MaxRecordBytes)
	}
	a.rec = candidate
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
	if a.rec.scopeVersion != a.scopeVersion {
		return fmt.Errorf("%w: reservation belongs to the previous enrollment", ErrContextMismatch)
	}
	if len(a.rec.signed) == 0 {
		return fmt.Errorf("%w: nothing has been signed for round %d", ErrResponseNotRetained, a.rec.reserved)
	}
	// Retention marks the response releasable. It does not copy it again: the copy is what made the
	// record three copies of the request, so that a request this authority had already admitted and
	// signed could not be retained at all.
	a.rec.releasable = true
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
	if a.rec.scopeVersion != a.scopeVersion {
		return nil, fmt.Errorf("%w: reservation belongs to the previous enrollment", ErrContextMismatch)
	}
	if round != a.rec.reserved {
		return nil, fmt.Errorf("%w: asked for round %d, the reservation is round %d", ErrStale, round, a.rec.reserved)
	}
	if digest != a.rec.digest {
		return nil, fmt.Errorf("%w: round %d is reserved for different bytes", ErrConflict, a.rec.reserved)
	}
	if !a.rec.releasable {
		return nil, fmt.Errorf("%w: round %d has no retained response", ErrResponseNotRetained, a.rec.reserved)
	}
	return bytes.Clone(a.rec.signed), nil
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
	enroll, trust, hasKey, scopeVersion := a.enroll.clone(), a.trust, a.signer != nil, a.scopeVersion
	a.mu.Unlock()

	if !hasKey {
		return nil, fmt.Errorf("%w: this authority has no key for %s", ErrKeyLost, enroll.NodeID)
	}
	if !enroll.complete() {
		return nil, fmt.Errorf("%w: no shard configuration has been stated, so no certificate's configuration can be checked", ErrEnrollmentIncomplete)
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

	// The root epoch is pinned to the current operator-provisioned context. A certificate
	// from another epoch cannot select a trust base for the authority.
	//
	// The check comes BEFORE the trust lookup on purpose, so that an epoch chosen by whoever sent
	// the request cannot drive which trust base this authority fetches. The cost is that a forged
	// certificate which also names another epoch is refused here, before anything about it has been
	// authenticated, so the message says what the certificate CLAIMS and does not assert that the
	// certificate is genuine. A certificate naming the enrolled epoch reaches verification below,
	// where a forgery is reported as one.
	if own.UC.GetRootEpoch() != *enroll.RootEpoch {
		return nil, fmt.Errorf("%w: certificate claims root epoch %d, this authority is enrolled for %d; refused before authentication, so the claim is not established", ErrContextMismatch, own.UC.GetRootEpoch(), *enroll.RootEpoch)
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
		scopeVersion:   scopeVersion,
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
