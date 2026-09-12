/*
Package rootinput derives the canonical D1 root input for an enshrined-EVM shard round from a REAL
Unicity Certificate and technical record, authenticated against an explicit verifier-owned context.

It is the production boundary for the profile in docs/design/d1-canonical-root-input.md; the field
mapping it implements — each field against the signed commitment or pinned local context that supplies
it, and what the current single-configuration profile refuses rather than approximates — is
docs/design/f2b-root-input-derivation-mapping.md (#136).

Two things this package is careful about, because they are how a derivation of this kind goes wrong:

  - **Nothing is taken from an unauthenticated claim.** The expected network, partition, shard and
    configuration commitment come from the caller's configuration; the trust base comes from the
    caller's store, keyed by the epoch the certificate names; the authorizing certificate and the
    certified parent are pinned by the caller. A peer-supplied "verified" flag, a checkpoint's own
    claim about its configuration, the execution client's head and the wall clock are never inputs.
  - **The encoding is not reimplemented.** evmroot is the accepted canonical model (ADR 0003) and
    performs every byte of encoding, hashing and structural validation here; a second hand-written
    codec would be a second opinion about canonicality, which is precisely what must not exist.

The result is a pure function of its inputs: a builder, a follower validating a leader's block and a
replay consumer that pin the same inputs get the same bytes. No call site is activated by this unit
(#136); wiring is the next reviewed unit.
*/
package rootinput

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-go-base/types"
)

// The refusals, named so a caller can tell them apart. A certificate that is simply not this shard's
// business (ErrWrongContext) is a different situation from one that does not authenticate
// (ErrUnauthenticated), from one that is not the certificate the caller pinned (ErrNotPinned), and
// from one whose round the supported profile cannot derive at all (ErrUnsupported).
var (
	// ErrContextIncomplete means the caller did not supply a verifier context this package can use.
	ErrContextIncomplete = errors.New("rootinput: verifier context is incomplete")
	// ErrWrongContext means the certificate belongs to another network, partition, shard or
	// configuration than the one configured.
	ErrWrongContext = errors.New("rootinput: certificate is for another context")
	// ErrUnauthenticated means the certificate, its inclusion paths, its quorum or its technical-record
	// binding did not verify against the configured trust base.
	ErrUnauthenticated = errors.New("rootinput: certificate did not authenticate")
	// ErrNotPinned means the certificate does not match what the caller pinned: the authorized round,
	// or the seal-registry cursor it must not be behind.
	ErrNotPinned = errors.New("rootinput: certificate does not match the pinned round or cursor")
	// ErrUnsupported means the accepted profile defines this case but the supported
	// single-configuration profile cannot authenticate it here; see the mapping document §4.
	ErrUnsupported = errors.New("rootinput: not supported by the single-configuration profile")
)

// TrustBases resolves the root trust base for a root epoch. It is the caller's own store —
// shardnode.TrustBaseStore satisfies it — never anything travelling with a certificate.
type TrustBases interface {
	GetByEpoch(ctx context.Context, epoch uint64) (*types.RootTrustBaseV1, error)
}

/*
Context is everything the verifier owns: what this node is configured to be, where its trust comes
from, and what the caller has pinned for this derivation.

The pinned fields are pinned deliberately. Round is the shard round being derived, not whatever the
certificate happens to authorize; ParentHash is the certified parent the caller is building on, never
the node's later local execution head; LastAppliedRootRound is the seal-registry cursor from committed
state, never the highest root round this node happens to have observed (D1 §5).
*/
type Context struct {
	NetworkID     types.NetworkID
	PartitionID   types.PartitionID
	ShardID       types.ShardID
	ShardConfHash []byte // the configured configuration commitment (#134), 32 bytes
	TrustBases    TrustBases

	Round                uint64 // n — the authorized shard round the caller is deriving
	ParentHash           []byte // h_parent — the pinned certified EVM parent block hash, 32 bytes
	LastAppliedRootRound uint64 // the seal-registry cursor

	// TransitionsPending says the EVM is still missing committed trust-base bodies or handoff
	// acknowledgements (D). There is no authenticated feed of those to a shard node in this
	// codebase, so this is a refusal rather than an empty list: an empty D means "none are pending",
	// and must never stand in for "some are pending and could not be authenticated".
	TransitionsPending bool
}

// Result is the verified representation and what was derived from it. The certificate and technical
// record are this package's own copies, decoded from the bytes it verified, so a caller mutating its
// originals afterwards cannot change what was authenticated or what the commitment covers.
type Result struct {
	Input       evmroot.RootInput
	Encoded     []byte         // canonical deterministic CBOR of Input
	Commitment  evmroot.Hash32 // extraData = SHA-256(Encoded)
	Authorizing evmroot.AuthorizingRef
	Certificate *types.UnicityCertificate
	Technical   *certification.TechnicalRecord
}

/*
Derive authenticates the certificate and technical record against the context and returns the canonical
root input with its commitment, or a named refusal.

The order is deliberate: cheap context checks, then ownership of the inputs, then the technical-record
binding, then the trust base and full certificate verification, then the pinned round and cursor, and
only then the canonical tuple. Each step's failure is a different error, so "this is not my shard's
certificate" is never reported as "this is a forgery".
*/
func Derive(ctx context.Context, c Context, uc *types.UnicityCertificate, tr *certification.TechnicalRecord) (Result, error) {
	if c.TrustBases == nil {
		return Result{}, fmt.Errorf("%w: no trust base source", ErrContextIncomplete)
	}
	if len(c.ShardConfHash) != 32 {
		return Result{}, fmt.Errorf("%w: configured shard configuration hash must be 32 bytes, got %d", ErrContextIncomplete, len(c.ShardConfHash))
	}
	if uc == nil || tr == nil {
		return Result{}, fmt.Errorf("%w: certificate or technical record is missing", ErrContextIncomplete)
	}
	// Genesis installation (authorized round 0) is defined by D1 §6 but cannot be sourced from a live
	// technical record: certification.TechnicalRecord.IsValid rejects round 0, so no such record
	// exists on this pipeline. The first tuple this boundary produces is the first post-genesis
	// payload at round 1, whose parent is the pinned EVM genesis block hash. See the mapping §5.1.
	if c.Round == 0 {
		return Result{}, fmt.Errorf("%w: genesis installation (authorized round 0) is not derived here — no technical record can authorize round 0", ErrUnsupported)
	}
	if len(c.ParentHash) != 32 {
		return Result{}, fmt.Errorf("%w: pinned certified parent hash must be 32 bytes, got %d", ErrContextIncomplete, len(c.ParentHash))
	}
	if c.TransitionsPending {
		return Result{}, fmt.Errorf("%w: committed trust-base bodies or handoff acknowledgements are pending, and no authenticated source for them reaches a shard node — recorded on #10/H-series", ErrUnsupported)
	}

	// Own everything before anything is checked, so what is verified is what is retained and a caller
	// mutating its own objects afterwards cannot change either.
	ownedUC, ownedTR, err := own(uc, tr)
	if err != nil {
		return Result{}, fmt.Errorf("%w: %w", ErrContextIncomplete, err)
	}
	confHash := bytes.Clone(c.ShardConfHash)
	parentHash := bytes.Clone(c.ParentHash)

	if err := ownedTR.IsValid(); err != nil {
		return Result{}, fmt.Errorf("%w: technical record: %w", ErrUnauthenticated, err)
	}
	// The certificate commits to its technical record by hash, and nothing else here establishes that
	// the record handed in is that one: evmroot.RootOriginFromCertificate hashes the record to place it
	// in O_-, but does not compare. Without this, a genuine certificate paired with another shard's
	// record would still produce a well-formed tuple.
	if err := ownedTR.HashMatches(ownedUC.TRHash); err != nil {
		return Result{}, fmt.Errorf("%w: the technical record is not the one this certificate commits to: %w", ErrUnauthenticated, err)
	}

	tb, err := c.TrustBases.GetByEpoch(ctx, ownedUC.GetRootEpoch())
	if err != nil {
		return Result{}, fmt.Errorf("%w: no trust base for root epoch %d: %w", ErrUnauthenticated, ownedUC.GetRootEpoch(), err)
	}
	if tb == nil {
		return Result{}, fmt.Errorf("%w: no trust base for root epoch %d", ErrUnauthenticated, ownedUC.GetRootEpoch())
	}
	// Quorum signatures, both inclusion paths, the partition and shard, and the configuration
	// commitment — all against values this node was configured with, never the certificate's own.
	if err := ownedUC.Verify(tb, crypto.SHA256, c.PartitionID, c.ShardID, confHash); err != nil {
		return Result{}, fmt.Errorf("%w: %w", ErrUnauthenticated, err)
	}
	if uint64(ownedUC.UnicitySeal.NetworkID) != uint64(c.NetworkID) {
		return Result{}, fmt.Errorf("%w: certificate is sealed for network %d, this node runs %d",
			ErrWrongContext, ownedUC.UnicitySeal.NetworkID, c.NetworkID)
	}

	origin, err := evmroot.RootOriginFromCertificate(ownedUC, ownedTR)
	if err != nil {
		return Result{}, fmt.Errorf("%w: %w", ErrUnauthenticated, err)
	}
	ref, err := evmroot.RefFromOrigin(origin)
	if err != nil {
		return Result{}, fmt.Errorf("%w: %w", ErrUnauthenticated, err)
	}
	// SignaturesValid is true because this code verified it above against the configured trust base —
	// it is never a field a caller or a peer supplies.
	bound := evmroot.VerifiedCert{
		SignaturesValid: true,
		RootRound:       origin.RootRound,
		AuthorizedRound: ownedTR.Round,
		OriginID:        ref.OriginID,
		TRHash:          ref.TRHash,
	}
	if res := evmroot.ValidateBoundCertificate(ref, bound, c.Round, c.LastAppliedRootRound); !res.Accept {
		return Result{}, fmt.Errorf("%w: %s", ErrNotPinned, res.Reason)
	}

	ri := evmroot.RootInput{
		Version:         evmroot.ProfileVersion,
		NetworkID:       uint64(c.NetworkID),
		PartitionID:     uint64(c.PartitionID),
		ShardID:         c.ShardID.Bytes(),
		Round:           c.Round,
		CertifiedEpoch:  origin.IR.Epoch,
		AuthorizedEpoch: ownedTR.Epoch,
		ParentHash:      parentHash,
		Origin:          origin,
		TE: evmroot.TechnicalRecord{
			Round:    ownedTR.Round,
			Epoch:    ownedTR.Epoch,
			Leader:   ownedTR.Leader,
			StatHash: bytes.Clone(ownedTR.StatHash),
			FeeHash:  bytes.Clone(ownedTR.FeeHash),
		},
		// D is empty because none are pending — TransitionsPending above is what distinguishes that
		// from "some are pending", which is refused rather than encoded as an empty list.
		Transitions: nil,
	}
	// The handoff boundary is structurally valid in the profile, but authenticating that the successor
	// assignment is the committed one needs the same committed bodies that do not reach a shard node.
	if ri.EpochBoundary() == evmroot.EpochHandoff {
		return Result{}, fmt.Errorf("%w: epoch handoff (certified %d, authorized %d) cannot be authenticated without the committed trust-base bodies — recorded on #10/H-series",
			ErrUnsupported, ri.CertifiedEpoch, ri.AuthorizedEpoch)
	}
	if err := ri.Validate(); err != nil {
		return Result{}, fmt.Errorf("%w: %w", ErrWrongContext, err)
	}

	return Result{
		Input:       ri,
		Encoded:     ri.Encode(),
		Commitment:  ri.ExtraData(),
		Authorizing: ref,
		Certificate: ownedUC,
		Technical:   ownedTR,
	}, nil
}

// own returns this package's own copies of the certificate and technical record, round-tripped through
// the canonical CBOR encoding rather than copied field by field: a shallow copy would keep the caller's
// byte slices, and a hand-written deep copy would silently miss a field added later.
func own(uc *types.UnicityCertificate, tr *certification.TechnicalRecord) (*types.UnicityCertificate, *certification.TechnicalRecord, error) {
	ucBytes, err := types.Cbor.Marshal(uc)
	if err != nil {
		return nil, nil, fmt.Errorf("encoding the certificate: %w", err)
	}
	trBytes, err := types.Cbor.Marshal(tr)
	if err != nil {
		return nil, nil, fmt.Errorf("encoding the technical record: %w", err)
	}
	ownedUC := &types.UnicityCertificate{}
	if err := types.Cbor.Unmarshal(ucBytes, ownedUC); err != nil {
		return nil, nil, fmt.Errorf("decoding the certificate: %w", err)
	}
	ownedTR := &certification.TechnicalRecord{}
	if err := types.Cbor.Unmarshal(trBytes, ownedTR); err != nil {
		return nil, nil, fmt.Errorf("decoding the technical record: %w", err)
	}
	return ownedUC, ownedTR, nil
}
