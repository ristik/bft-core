package signingauthority

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
)

// MaxRecordBytes bounds one active record, including the retained response and metadata (§5). The
// request bound is MaxUnsignedRequestBytes; a signed response is that request plus a signature, so
// this leaves room for one of each rather than for an unbounded history.
const MaxRecordBytes = 2 << 20

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
	// signed is the private result of signing `unsigned`. It is not releasable until retained.
	signed []byte
	// retained is the exact response that may be released, and replayed identically afterwards.
	retained []byte
}

func (r *record) empty() bool { return r.reserved == 0 && len(r.unsigned) == 0 }

func (r *record) size() int {
	return len(r.unsigned) + len(r.signed) + len(r.retained) + len(r.authorizationID)
}

// checkInvariants reports the inconsistencies this authority can actually detect. Memory corruption
// in general is outside the honest-authority assumption (§5); what is checked here is that the
// record's own parts agree with each other.
func (r *record) checkInvariants() error {
	if r.empty() {
		if len(r.signed) != 0 || len(r.retained) != 0 {
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
	if len(r.retained) != 0 && len(r.signed) == 0 {
		return errors.New("a retained response with nothing signed")
	}
	if size := r.size(); size > MaxRecordBytes {
		return fmt.Errorf("record is %d bytes, limit is %d", size, MaxRecordBytes)
	}
	return nil
}

// sameRequest reports whether `unsigned` is byte-identical to what is reserved.
func (r *record) sameRequest(unsigned []byte) bool { return bytes.Equal(r.unsigned, unsigned) }
