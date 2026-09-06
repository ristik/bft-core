package evmroot

import (
	"fmt"

	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-go-base/types"
)

// D1 certificate selection: how a block binds the exact authorizing
// certificate and how a follower validates that choice against shared
// committed state — without needing to know the globally latest message.
//
// The rule is: the proposer picks any certificate that is valid and
// authorizes shard round n, and BINDS it in the block (its O_- is committed
// in extraData and its full UC/TR travel in the D2 companion data). A
// follower does NOT independently re-pick from its own view; it validates
// the proposer's bound choice. The only view-dependent input is the
// follower's own seal-registry cursor (the last root round it has already
// applied), which is committed state, identical on every honest node that
// has processed the same certified sequence.

// AuthorizingRef is the identity of the certificate a block binds. It is
// exactly what O_- already commits, surfaced as a small comparable value.
type AuthorizingRef struct {
	RootRound uint64 // C^r_-.r  (UnicitySeal.RootChainRoundNumber)
	OriginID  Hash32 // H(CBOR(O_-)) — pins the whole certified statement, IR included
	TRHash    Hash32 // UC.TRHash
}

// RefFromOrigin derives the AuthorizingRef a block with this root origin
// binds. trHash is O_-.TRHash (must be 32 bytes).
func RefFromOrigin(o RootOrigin) (AuthorizingRef, error) {
	if len(o.TRHash) != 32 {
		return AuthorizingRef{}, fmt.Errorf("evmroot: TRHash must be 32 bytes")
	}
	var tr Hash32
	copy(tr[:], o.TRHash)
	return AuthorizingRef{RootRound: o.RootRound, OriginID: o.Identity(), TRHash: tr}, nil
}

// VerifiedCert is a certificate a node has ALREADY verified against the
// trust base (signature verification is D3's concern; here it is an input).
// It carries just what selection validation needs.
type VerifiedCert struct {
	SignaturesValid bool   // verified against the trust base for its epoch
	RootRound       uint64 // UnicitySeal.RootChainRoundNumber
	AuthorizedRound uint64 // TE_-.Round — the shard round this certificate authorizes
	OriginID        Hash32 // H(CBOR(O_-)) recomputed from the certificate's own fields
	TRHash          Hash32 // UC.TRHash
}

// SelectionResult explains a bound-certificate validation outcome.
type SelectionResult struct {
	Accept bool
	Reason string
}

// ValidateBoundCertificate checks the proposer's bound authorizing
// certificate for shard round n against a follower's committed state.
//
//   - the bound certificate must be one this follower has verified;
//   - it must authorize exactly round n;
//   - its O_- and TRHash must match the block's binding (ref);
//   - its root round must be >= the follower's last-applied root round —
//     a proposer that bound a certificate the follower has already
//     superseded in its seal registry is rejected, and the round is
//     re-proposed against a current certificate. This is the only place a
//     follower's local state enters, and it is committed state, not
//     message-arrival order.
//
// A later valid repeat certificate (same IR, higher root round) that the
// proposer did NOT bind is simply not used for this block; two honest
// nodes still agree because they both validate the one bound certificate,
// not whichever they saw last.
func ValidateBoundCertificate(ref AuthorizingRef, cert VerifiedCert, authorizedRound, lastAppliedRootRound uint64) SelectionResult {
	if !cert.SignaturesValid {
		return SelectionResult{false, "bound certificate is not verified against the trust base"}
	}
	if cert.AuthorizedRound != authorizedRound {
		return SelectionResult{false, fmt.Sprintf("bound certificate authorizes round %d, not %d", cert.AuthorizedRound, authorizedRound)}
	}
	if cert.OriginID != ref.OriginID {
		return SelectionResult{false, "bound certificate O_- identity does not match the block's extraData commitment"}
	}
	if cert.TRHash != ref.TRHash {
		return SelectionResult{false, "bound certificate TRHash does not match the block's binding"}
	}
	if cert.RootRound != ref.RootRound {
		return SelectionResult{false, "bound certificate root round does not match the block's binding"}
	}
	if cert.RootRound < lastAppliedRootRound {
		return SelectionResult{false, fmt.Sprintf("bound certificate root round %d is behind the seal-registry cursor %d — stale selection, re-propose", cert.RootRound, lastAppliedRootRound)}
	}
	return SelectionResult{Accept: true}
}

// RootOriginFromCertificate maps a verified types.UnicityCertificate and
// its certification.TechnicalRecord onto the canonical O_-. It reads only
// committed content; it never touches uc.UnicitySeal.Signatures,
// uc.ShardTreeCertificate paths or uc.UnicityTreeCertificate paths — that
// is what makes alternate valid signature subsets of the same statement
// produce a byte-identical O_-.
func RootOriginFromCertificate(uc *types.UnicityCertificate, tr *certification.TechnicalRecord) (RootOrigin, error) {
	if uc == nil || uc.InputRecord == nil || uc.UnicitySeal == nil || tr == nil {
		return RootOrigin{}, fmt.Errorf("evmroot: certificate or technical record is incomplete")
	}
	trHash, err := tr.Hash()
	if err != nil {
		return RootOrigin{}, fmt.Errorf("evmroot: hashing technical record: %w", err)
	}
	ir := uc.InputRecord
	return RootOrigin{
		NetworkID:       uint64(uc.UnicitySeal.NetworkID),
		RootRound:       uc.UnicitySeal.RootChainRoundNumber,
		RootEpoch:       uc.UnicitySeal.Epoch,
		ReferenceTime:   uc.UnicitySeal.Timestamp,
		UnicityTreeRoot: cloneBytes(uc.UnicitySeal.Hash),
		IR: ShardInputRecord{
			Round:        ir.RoundNumber,
			Epoch:        ir.Epoch,
			PreviousHash: cloneBytes(ir.PreviousHash),
			Hash:         cloneBytes(ir.Hash),
			Timestamp:    ir.Timestamp,
			BlockHash:    cloneBytes(ir.BlockHash),
		},
		TRHash:        trHash,
		ShardConfHash: cloneBytes(uc.ShardConfHash),
	}, nil
}

func cloneBytes(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

// verifiedCertFromOrigin builds the VerifiedCert a follower would hold
// after verifying a certificate whose committed content is o and which
// authorizes authorizedRound. sigValid records the trust-base verification
// result (D3's concern).
func verifiedCertFromOrigin(o RootOrigin, authorizedRound uint64, sigValid bool) VerifiedCert {
	var tr Hash32
	copy(tr[:], o.TRHash)
	return VerifiedCert{
		SignaturesValid: sigValid,
		RootRound:       o.RootRound,
		AuthorizedRound: authorizedRound,
		OriginID:        o.Identity(),
		TRHash:          tr,
	}
}
