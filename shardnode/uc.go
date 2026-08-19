package shardnode

import (
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-go-base/types"
)

// UCClass is what a newly received Unicity Certificate is, relative to the
// last one this node processed. See docs/shard-protocol.md §"UC
// classification" for the normative definition of each class.
type UCClass int

const (
	// UCValid: extends the previous certified state (or is the first UC
	// this node has ever seen). The round driver commits it.
	UCValid UCClass = iota
	// UCDuplicate: same root round as the last UC processed — this node is
	// connected to more than one root node and received the same
	// certificate twice. No-op.
	UCDuplicate
	// UCRepeat: same InputRecord as the last UC, but a later root round —
	// the root chain timed out waiting for this shard's certification
	// request and re-issued the last-good certificate. The round driver
	// must not treat this as a committed block; it starts the next round
	// fresh, from the TechnicalRecord this UC carries.
	UCRepeat
)

func (c UCClass) String() string {
	switch c {
	case UCValid:
		return "valid"
	case UCDuplicate:
		return "duplicate"
	case UCRepeat:
		return "repeat"
	default:
		return "unknown"
	}
}

// ErrEquivocatingUC is returned by ClassifyUC when newUC and prevUC cannot
// both be honest certificates for this shard — see
// types.CheckNonEquivocatingCertificates for the seven checks this wraps.
// A shard node that receives this should treat it as fatal: something is
// wrong with the root chain's certificates, this node's own bookkeeping, or
// both, and continuing to certify on top of an unverified sequence is
// unsafe.
var ErrEquivocatingUC = errors.New("shardnode: equivocating unicity certificate")

// ClassifyUC determines what newUC is relative to prevUC (the last UC this
// node accepted; nil if this is the first UC received since startup).
//
// Callers must have already verified newUC's signature against the trust
// base — classification assumes newUC is authentic and asks only where it
// fits in the certified sequence.
func ClassifyUC(prevUC, newUC *types.UnicityCertificate) (UCClass, error) {
	if newUC == nil {
		return UCValid, fmt.Errorf("unicity certificate is nil")
	}
	if prevUC == nil {
		// First UC this node has seen since startup: nothing to compare
		// against, so trivially "valid" — the sync/genesis distinction is
		// the round driver's concern (see docs/shard-protocol.md), not
		// classification's.
		return UCValid, nil
	}

	if err := types.CheckNonEquivocatingCertificates(prevUC, newUC); err != nil {
		return UCValid, fmt.Errorf("%w: %w", ErrEquivocatingUC, err)
	}
	if newUC.IsDuplicate(prevUC) {
		return UCDuplicate, nil
	}
	repeat, err := newUC.IsRepeat(prevUC)
	if err != nil {
		return UCValid, fmt.Errorf("checking for repeat UC: %w", err)
	}
	if repeat {
		return UCRepeat, nil
	}
	return UCValid, nil
}
