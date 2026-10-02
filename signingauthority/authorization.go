package signingauthority

import (
	"crypto/sha256"
	"fmt"

	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-go-base/types"
)

// authorizationIDVersion versions the canonical authorization identity below. A later profile that
// changes what identifies an authorization changes this number rather than the meaning of 1.
const authorizationIDVersion uint64 = 1

// authorizationIdentity is the signature-free identity of one authorization, as canonical CBOR of a
// versioned array (§4). It deliberately contains the certificate's input record, the seal's own
// signature-free bytes and the bound technical record, and deliberately omits the seal signatures:
// two valid signer subsets of the same seal are the same authorization, not two.
type authorizationIdentity struct {
	_           struct{} `cbor:",toarray"`
	Version     uint64
	InputRecord []byte
	SealSigned  []byte
	Technical   []byte
}

// Authorization is what step 1 produces: an authenticated assignment, the exact bytes that would be
// signed for it, and the identity of the authorization itself.
//
// It is not permission to sign. The signing record in step 2 decides that, and it is the reason
// this type reports AssignedRound separately from ID: the conflict key is the assigned partition
// round, and a different root round producing a different ID must not reopen a round that has
// already been answered.
type Authorization struct {
	scopeVersion uint64
	// AssignedRound and AssignedEpoch come from the authenticated TechnicalRecord.
	AssignedRound uint64
	AssignedEpoch uint64
	// irEpoch is the shard epoch the certificate's input record is at: the enrolled epoch, or (while an acknowledgement is pending) an
	// earlier one. Reserve uses it to latch that the acknowledgement was reached (see Authority.irAckSeen).
	irEpoch uint64

	// ID identifies the authorization. Equal IDs mean the same assignment, including across valid
	// seal signer subsets.
	ID []byte

	// Unsigned is the complete signature-free request this authorization would sign, exactly the
	// preimage the shard node signs today.
	Unsigned []byte

	// UnsignedDigest lets a caller name that preimage without carrying it.
	UnsignedDigest [32]byte
}

func authorizationID(uc *types.UnicityCertificate, tr *certification.TechnicalRecord) ([]byte, error) {
	ir, err := uc.InputRecord.Bytes()
	if err != nil {
		return nil, fmt.Errorf("encoding input record: %w", err)
	}
	seal, err := uc.UnicitySeal.SigBytes()
	if err != nil {
		return nil, fmt.Errorf("encoding unicity seal: %w", err)
	}
	trBytes, err := types.Cbor.Marshal(tr)
	if err != nil {
		return nil, fmt.Errorf("encoding technical record: %w", err)
	}
	id, err := types.Cbor.Marshal(authorizationIdentity{
		Version: authorizationIDVersion, InputRecord: ir, SealSigned: seal, Technical: trBytes,
	})
	if err != nil {
		return nil, fmt.Errorf("encoding authorization identity: %w", err)
	}
	sum := sha256.Sum256(id)
	return sum[:], nil
}
