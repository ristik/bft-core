package q3format

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/evmroot"
)

// ErrRecoveryExemption is returned when a link claims the readiness exemption of an exact recovery K and does not earn it.
var ErrRecoveryExemption = errors.New("q3format: the readiness exemption of an exact recovery does not hold")

// maxPreimage bounds the candidate preimage a link carries.
const maxPreimage = 1 << 20

// readiness decides which readiness evidence a link's body needs and checks it.
//
// The selector is deterministic and never a flag or "the receipts are empty": the link carries the canonical candidate preimage, which
// must hash to the committed candidate digest. A preimage that decodes as a KindRecovery candidate, passes its static kind rules
// (evmassign.VerifyKind: no fresh proofs, the replaced assignment, exactly K), names exactly the body's members, and whose authorization
// and replaced assignment chain to the immediately preceding link's primary preimage, needs no receipts and carries none. Every other
// link (a primary, a root-only change, a link without a preimage) needs exactly one valid receipt from every successor member.
//
// What the exemption deliberately does not re-check here, because the committing quorum's commit proof already vouches for it under
// the same trust the history places in that proof everywhere: the incumbent K is the last acknowledged committee and the one-shot
// recovery allowance is unspent (evmassign.VerifyLifecycle at the old committee's Freeze admission and at replay).
func readiness(b BodyV3, attempt uint64, ev Evidence, preimage, priorPreimage []byte, receipts []Receipt) error {
	if len(preimage) != 0 {
		if len(preimage) > maxPreimage {
			return fmt.Errorf("%w: preimage of %d bytes", ErrTooLarge, len(preimage))
		}
		if sum := sha256.Sum256(preimage); !bytes.Equal(sum[:], ev.CandidateDigest) {
			return fmt.Errorf("%w: the preimage is not the committed candidate", ErrBinding)
		}
		c, err := evmassign.DecodeCandidate(preimage)
		if err != nil {
			return errors.Join(ErrBinding, err)
		}
		if c.Kind == evmassign.KindRecovery {
			if len(receipts) != 0 {
				return fmt.Errorf("%w: a recovery carries no readiness receipts", ErrRecoveryExemption)
			}
			if err := recoveryHolds(b, c, priorPreimage); err != nil {
				return errors.Join(ErrRecoveryExemption, err)
			}
			return nil
		}
	}
	return VerifyReceipts(b, ContextFor(b, attempt, [32]byte(ev.CandidateDigest)), receipts)
}

// recoveryHolds is the static half of the exemption: the candidate is a well formed recovery of exactly the body's members that replaces the
// primary the preceding link committed.
func recoveryHolds(b BodyV3, c evmassign.Candidate, priorPreimage []byte) error {
	succ, err := c.Successor()
	if err != nil {
		return err
	}
	if err := evmassign.VerifyKind(c, succ); err != nil {
		return err
	}
	if len(c.RootMembers) != len(b.Members) {
		return errors.New("the recovery names other root members than the body")
	}
	want := slices.Clone(b.Members)
	slices.SortFunc(want, func(x, y evmroot.Member) int { return bytes.Compare([]byte(x.NodeID), []byte(y.NodeID)) })
	got := slices.Clone(c.RootMembers)
	slices.SortFunc(got, func(x, y evmassign.RootMember) int { return bytes.Compare([]byte(x.NodeID), []byte(y.NodeID)) })
	for i := range want {
		if want[i].NodeID != got[i].NodeID || want[i].Weight != got[i].Weight || !bytes.Equal(want[i].ConsensusKey, got[i].Key) {
			return errors.New("the recovery names other root members than the body")
		}
	}
	if len(priorPreimage) == 0 {
		return fmt.Errorf("%w: a recovery replaces a committed primary and the preceding link committed none", evmassign.ErrRecoveryLineage)
	}
	p, err := evmassign.DecodeCandidate(priorPreimage)
	if err != nil {
		return err
	}
	if p.Kind != evmassign.KindPrimary || p.Authorization == nil || c.Authorization == nil {
		return fmt.Errorf("%w: the preceding link is not a primary with a recovery authorization", evmassign.ErrRecoveryLineage)
	}
	pa, err := p.Authorization.Digest()
	if err != nil {
		return err
	}
	ca, err := c.Authorization.Digest()
	if err != nil {
		return err
	}
	if pa != ca {
		return fmt.Errorf("%w: the recovery authorization is not the one the primary published", evmassign.ErrAuthorization)
	}
	id, err := p.AssignmentID()
	if err != nil {
		return err
	}
	if !bytes.Equal(c.ReplacedAssignment, id[:]) {
		return fmt.Errorf("%w: the recovery does not replace the preceding primary's assignment", evmassign.ErrRecoveryLineage)
	}
	return nil
}
