package signingauthority

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-go-base/types"
)

// ProfileLegacyBCRv1 is the only signing profile this implementation admits. It signs exactly the
// bytes the shard node already signs, the signature-free CBOR encoding of a complete
// BlockCertificationRequest, and adds nothing to that preimage. Scope metadata is an authority
// policy binding rather than a cryptographic addition to the wire message (§2 of the design note).
const ProfileLegacyBCRv1 = "legacy-bcr-v1"

// Enrollment is the immutable scope of one signing key. Every field is fixed when the authority is
// created and none of them is a conflict namespace a caller may select: a request naming a
// different value is refused with ErrContextMismatch rather than served from a separate record.
//
// Root-epoch transitions and configuration or key changes are out of this profile. The response to
// one is to freeze, not to open a fresh record under a new scope (§4).
type Enrollment struct {
	// AuthorityID is an opaque operator-assigned name for this authority lifetime. It identifies the
	// process in diagnostics and carries no authority of its own.
	AuthorityID string

	// NodeID is the shard validator this key signs for, as it appears in a certification request.
	NodeID string

	// NetworkID, PartitionID, ShardID, ShardEpoch and ShardConfHash are the shard identity. The
	// network is checked against the authority's provisioned trust base rather than against anything
	// a requester says, because the legacy preimage carries no network identifier.
	NetworkID     types.NetworkID
	PartitionID   types.PartitionID
	ShardID       types.ShardID
	ShardEpoch    uint64
	ShardConfHash []byte

	// Profile must be ProfileLegacyBCRv1.
	Profile string

	// SigningKeyFingerprint is filled in by New from the key it generates. It is an output of
	// enrollment, not an input: there is no key to name before the authority has generated one.
	SigningKeyFingerprint []byte
}

func (e Enrollment) validate() error {
	switch {
	case e.AuthorityID == "":
		return errors.New("enrollment has no authority id")
	case e.NodeID == "":
		return errors.New("enrollment has no node id")
	case e.NetworkID == 0:
		return errors.New("enrollment has no network id")
	case e.PartitionID == 0:
		return errors.New("enrollment has no partition id")
	case len(e.ShardConfHash) == 0:
		return errors.New("enrollment has no shard configuration hash, so a certificate's configuration could not be checked")
	case e.Profile != ProfileLegacyBCRv1:
		return fmt.Errorf("%w: signing profile %q, this implementation offers only %q", ErrUnsupportedVersion, e.Profile, ProfileLegacyBCRv1)
	}
	return nil
}

// clone copies the mutable bytes, so neither the caller's slice nor a later reader of Enrollment can
// change what this authority enforces.
func (e Enrollment) clone() Enrollment {
	e.ShardConfHash = bytes.Clone(e.ShardConfHash)
	e.SigningKeyFingerprint = bytes.Clone(e.SigningKeyFingerprint)
	return e
}

func (e Enrollment) sameShardAs(other Enrollment) bool {
	return e.NodeID == other.NodeID && e.NetworkID == other.NetworkID &&
		e.PartitionID == other.PartitionID && e.ShardID.Equal(other.ShardID) &&
		e.ShardEpoch == other.ShardEpoch && bytes.Equal(e.ShardConfHash, other.ShardConfHash) &&
		e.Profile == other.Profile
}
