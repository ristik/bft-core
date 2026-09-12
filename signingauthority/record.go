package signingauthority

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
)

// maxResponseOverheadBytes covers what signing adds to a request: a secp256k1 signature and its CBOR
// framing, with room to spare. It is a bound, not a measurement.
const maxResponseOverheadBytes = 1024

// maxAuthorizationIDBytes is the authorization identity kept beside the request. It is a SHA-256
// digest, and naming it here keeps the record bound below derived from every part it holds rather
// than from most of them: leaving this term out is exactly the kind of arithmetic that made the two
// caps fail to compose in the first place.
const maxAuthorizationIDBytes = sha256.Size

// MaxRecordBytes bounds one active record: the reserved request, the signed response and the
// metadata naming them (§5).
//
// It is DERIVED from the request bound rather than chosen independently, because two independent
// caps do not compose. With a 1 MiB request cap and a flat 2 MiB record cap, a 750 KB request was
// admitted and signed and then could never be retained, leaving a round locked and unanswerable.
// Anything this authority admits must be completable, so the record bound is whatever one admitted
// request plus its response needs.
const MaxRecordBytes = 2*MaxUnsignedRequestBytes + maxAuthorizationIDBytes + maxResponseOverheadBytes

// health is the authority's own view of itself (§5).
type health int

const (
	healthActive health = iota
	// healthFaulted is latched when an invariant fails or the generation space is exhausted. There
	// is no transition back: the key is retained, and nothing more is signed with it.
	healthFaulted
)

// record is the signing record: the single reservation this authority is holding.
//
// There is exactly one, for the highest assigned partition round reserved so far, and it is process
// memory with the same lifetime as the key. That is the whole safety argument of this profile: a
// record that cannot outlive the key needs no durability, because nothing can sign with that
// identity once the process is gone (§6).
type record struct {
	// reserved is the assigned partition round this record locks. It is the conflict key together
	// with the enrolled key and profile; a different root round does not open a second record.
	reserved uint64
	// unsigned is the complete signature-free request admitted for that round, and digest names it.
	unsigned []byte
	digest   [32]byte
	// authorizationID is the identity of the authorization that admitted it, kept for diagnostics.
	// It explains a decision and never partitions the lock (§4).
	authorizationID []byte
	// signed is the result of signing `unsigned`. There is one copy, and `releasable` says whether it
	// may leave: an earlier revision kept a second, identical copy to express the same thing, which
	// made the record three copies of the request and broke the size composition above.
	signed []byte
	// releasable is set by retention, before any response can be released, so a caller that
	// disappears mid-answer replays identical bytes rather than causing a second signature.
	releasable bool
}

func (r *record) empty() bool { return r.reserved == 0 && len(r.unsigned) == 0 }

func (r *record) size() int {
	return len(r.unsigned) + len(r.signed) + len(r.authorizationID)
}

// projectedSize is what this record will hold once the request it admits has been signed. Reserve
// checks it, so an admitted request is never one that cannot be completed.
func projectedSize(unsigned, authorizationID []byte) int {
	return 2*len(unsigned) + len(authorizationID) + maxResponseOverheadBytes
}

// checkInvariants reports the inconsistencies this authority can actually detect. Memory corruption
// in general is outside the honest-authority assumption (§5); what is checked here is that the
// record's own parts agree with each other.
func (r *record) checkInvariants() error {
	if r.empty() {
		if len(r.signed) != 0 || r.releasable {
			return errors.New("a response exists with no reservation")
		}
		return nil
	}
	if r.reserved == 0 {
		return errors.New("a reservation with no assigned round")
	}
	if len(r.unsigned) == 0 {
		return errors.New("a reservation with no request")
	}
	if r.digest != sha256.Sum256(r.unsigned) {
		return errors.New("the reserved request does not match its digest")
	}
	if r.releasable && len(r.signed) == 0 {
		return errors.New("a releasable response with nothing signed")
	}
	if size := r.size(); size > MaxRecordBytes {
		return fmt.Errorf("record is %d bytes, limit is %d", size, MaxRecordBytes)
	}
	return nil
}

// sameRequest reports whether `unsigned` is byte-identical to what is reserved.
func (r *record) sameRequest(unsigned []byte) bool { return bytes.Equal(r.unsigned, unsigned) }
