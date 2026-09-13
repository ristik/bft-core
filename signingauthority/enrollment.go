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
	//
	// ShardConfHash is the one field that may be absent at New, and in a deployment it must be. The
	// hash commits to the validators' signing keys, and one of those is the key New is about to
	// generate, so no configuration naming it can exist yet. An authority enrolled without the hash
	// is pending: it generates its key and publishes the public half, and admits nothing until
	// CompleteEnrollment states the configuration, once, after checking that it names this
	// authority's own key for the enrolled node. A hash given at New was necessarily computed
	// before this key existed, so a configuration with that hash cannot name this key.
	NetworkID     types.NetworkID
	PartitionID   types.PartitionID
	ShardID       types.ShardID
	ShardEpoch    uint64
	ShardConfHash []byte

	// RootEpoch is the one root epoch this authority admits. The design makes root-epoch
	// transitions unsupported in this profile, and the response to one is to freeze rather than to
	// carry on under a new scope (§4). It is therefore authority-owned enrollment context: it is
	// fixed here, never taken from a request and never reset per request, so the next genuine root
	// epoch is a refusal in this authority lifetime rather than ordinary work.
	//
	// It is a pointer because "not stated" and "pinned to epoch 0" are different, and only one of
	// them is acceptable: nothing in UnicitySeal.IsValid rejects epoch 0, so a plain zero value
	// would silently pin an epoch instead of refusing an enrollment that never named one. Use
	// PinRootEpoch.
	RootEpoch *uint64

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
	case e.RootEpoch == nil:
		return errors.New("enrollment states no root epoch, and this profile freezes on a root-epoch transition rather than accepting whichever epoch arrives")
	case e.Profile != ProfileLegacyBCRv1:
		return fmt.Errorf("%w: signing profile %q, this implementation offers only %q", ErrUnsupportedVersion, e.Profile, ProfileLegacyBCRv1)
	}
	return nil
}

// complete reports whether the shard configuration has been stated. An enrollment without it is
// pending, and an authority with a pending enrollment admits nothing (see CompleteEnrollment).
func (e Enrollment) complete() bool { return len(e.ShardConfHash) != 0 }

// clone copies the mutable bytes, so neither the caller's slice nor a later reader of Enrollment can
// change what this authority enforces.
// PinRootEpoch states the root epoch an authority is enrolled for.
func PinRootEpoch(epoch uint64) *uint64 { return &epoch }

func (e Enrollment) clone() Enrollment {
	e.ShardConfHash = bytes.Clone(e.ShardConfHash)
	if e.RootEpoch != nil {
		e.RootEpoch = PinRootEpoch(*e.RootEpoch)
	}
	e.SigningKeyFingerprint = bytes.Clone(e.SigningKeyFingerprint)
	return e
}

func (e Enrollment) sameShardAs(other Enrollment) bool {
	return e.NodeID == other.NodeID && e.NetworkID == other.NetworkID &&
		e.PartitionID == other.PartitionID && e.ShardID.Equal(other.ShardID) &&
		e.ShardEpoch == other.ShardEpoch && samePin(e.RootEpoch, other.RootEpoch) &&
		bytes.Equal(e.ShardConfHash, other.ShardConfHash) &&
		e.Profile == other.Profile
}

func samePin(a, b *uint64) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}
