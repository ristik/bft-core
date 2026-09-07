package shardnode

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

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

/*
DescribeUCConflict renders the two certificates a failed ClassifyUC compared, so a
rejection carries its own evidence.

Motivation (F1 #9, review 5132493933): CI reproduced a shard node repeatedly logging
"equivocating UC, different input records for same partition round 4" and never
recovering, and the log said only that. Deciding whether that is two genuinely
conflicting quorum certificates, a stale response, or a local representation bug
requires knowing WHICH field differs and which root rounds the two seals came from.

Equality here is decided by the canonical CBOR the signatures actually cover
(InputRecord.Bytes), never by a field-by-field bytes.Equal scan. An earlier version of
this function did the latter and reported "input records are equal" for the very
conflict it was written to explain — bytes.Equal(nil, []byte{}) is true, while the
canonical encodings differ (0xf6 null versus 0x40 empty byte string). That is exactly
the nil/empty loss issue #86 fixes in the checkpoint encoding, and a diagnostic that
cannot see it is worse than none. Byte fields are therefore reported as nil, empty or
hex, so the distinction is visible in the log line.

This does not change any classification decision.
*/
func DescribeUCConflict(prevUC, newUC *types.UnicityCertificate) string {
	if prevUC == nil || newUC == nil {
		return fmt.Sprintf("prevUC nil=%t newUC nil=%t", prevUC == nil, newUC == nil)
	}
	p, n := prevUC.InputRecord, newUC.InputRecord
	if p == nil || n == nil {
		return fmt.Sprintf("prevUC.IR nil=%t newUC.IR nil=%t", p == nil, n == nil)
	}

	var diffs []string
	cmp := func(name string, same bool) {
		if !same {
			diffs = append(diffs, name)
		}
	}
	// sameBytes is deliberately stricter than bytes.Equal: nil and empty are different
	// values here, because they encode differently and the encoding is what is signed.
	sameBytes := func(a, b []byte) bool {
		if (a == nil) != (b == nil) {
			return false
		}
		return bytes.Equal(a, b)
	}
	cmp("version", p.Version == n.Version)
	cmp("roundNumber", p.RoundNumber == n.RoundNumber)
	cmp("epoch", p.Epoch == n.Epoch)
	cmp("previousHash", sameBytes(p.PreviousHash, n.PreviousHash))
	cmp("hash", sameBytes(p.Hash, n.Hash))
	cmp("blockHash", sameBytes(p.BlockHash, n.BlockHash))
	cmp("summaryValue", sameBytes(p.SummaryValue, n.SummaryValue))
	cmp("timestamp", p.Timestamp == n.Timestamp)
	cmp("sumOfEarnedFees", p.SumOfEarnedFees == n.SumOfEarnedFees)
	cmp("etHash", sameBytes(p.ETHash, n.ETHash))

	// The authority on whether the records differ at all. If this disagrees with the
	// field list above, say so rather than picking one - it means a field this function
	// does not know about changed, and silently reporting "equal" is how the previous
	// version misled.
	canonical := "canonical IR bytes: "
	pb, pErr := p.Bytes()
	nb, nErr := n.Bytes()
	switch {
	case pErr != nil || nErr != nil:
		canonical += fmt.Sprintf("uncomputable (prev err=%v, new err=%v)", pErr, nErr)
	case bytes.Equal(pb, nb):
		canonical += "IDENTICAL"
	default:
		canonical += fmt.Sprintf("DIFFER (prev=%x new=%x)", pb, nb)
	}

	differing := "none by field comparison"
	if len(diffs) > 0 {
		differing = strings.Join(diffs, ",")
	}
	return fmt.Sprintf("differing IR fields: [%s]; %s; stored: rootRound=%d rootEpoch=%d seal=%X %s; received: rootRound=%d rootEpoch=%d seal=%X %s",
		differing, canonical,
		prevUC.GetRootRoundNumber(), prevUC.GetRootEpoch(), sealHash(prevUC), describeIR(p),
		newUC.GetRootRoundNumber(), newUC.GetRootEpoch(), sealHash(newUC), describeIR(n))
}

// describeIR renders an InputRecord for a log line. InputRecord.String omits Timestamp,
// which is one of the fields that can legitimately differ between two attempts at the
// same round, so it is spelled out here along with the nil/empty state of every byte
// field.
func describeIR(ir *types.InputRecord) string {
	return fmt.Sprintf("IR{v:%d round:%d epoch:%d ts:%d fees:%d H:%s Hprev:%s Bh:%s summary:%s ETh:%s}",
		ir.Version, ir.RoundNumber, ir.Epoch, ir.Timestamp, ir.SumOfEarnedFees,
		describeBytes(ir.Hash), describeBytes(ir.PreviousHash), describeBytes(ir.BlockHash),
		describeBytes(ir.SummaryValue), describeBytes(ir.ETHash))
}

// describeBytes distinguishes the three states a byte field can be in. "nil" and "empty"
// look identical in hex and encode differently; conflating them is the bug this whole
// diagnostic exists to expose.
func describeBytes(b []byte) string {
	if b == nil {
		return "nil"
	}
	if len(b) == 0 {
		return "empty"
	}
	return fmt.Sprintf("%X", b)
}

// sealHash is the certified Unicity Tree root of uc's seal, or nil if absent. It
// identifies which root-chain view a certificate came from without re-encoding it.
func sealHash(uc *types.UnicityCertificate) []byte {
	if uc.UnicitySeal == nil {
		return nil
	}
	return uc.UnicitySeal.Hash
}
