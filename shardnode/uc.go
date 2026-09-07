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
DescribeUCConflict renders the two certificates a failed ClassifyUC compared, field
by field, so a rejection carries its own evidence.

Motivation (F1 #9, review 5132493933): CI reproduced a shard node repeatedly logging
"equivocating UC, different input records for same partition round 4" and never
recovering, and the log said only that. Deciding whether that is two genuinely
conflicting quorum certificates, a stale response from a lagging root node, or a
local state bug requires knowing WHICH field differs and which root rounds the two
seals came from — none of which the error string carries. This does not change any
classification decision; it only makes the rejection explicable.

Marked with the differing fields so the reader does not have to diff two long lines
by eye.
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
	cmp("roundNumber", p.RoundNumber == n.RoundNumber)
	cmp("epoch", p.Epoch == n.Epoch)
	cmp("previousHash", bytes.Equal(p.PreviousHash, n.PreviousHash))
	cmp("hash", bytes.Equal(p.Hash, n.Hash))
	cmp("blockHash", bytes.Equal(p.BlockHash, n.BlockHash))
	cmp("summaryValue", bytes.Equal(p.SummaryValue, n.SummaryValue))
	cmp("timestamp", p.Timestamp == n.Timestamp)
	cmp("sumOfEarnedFees", p.SumOfEarnedFees == n.SumOfEarnedFees)
	cmp("etHash", bytes.Equal(p.ETHash, n.ETHash))

	differing := "none (input records are equal)"
	if len(diffs) > 0 {
		differing = strings.Join(diffs, ",")
	}
	return fmt.Sprintf("differing IR fields: [%s]; stored: rootRound=%d rootEpoch=%d seal=%X IR{%s}; received: rootRound=%d rootEpoch=%d seal=%X IR{%s}",
		differing,
		prevUC.GetRootRoundNumber(), prevUC.GetRootEpoch(), sealHash(prevUC), p.String(),
		newUC.GetRootRoundNumber(), newUC.GetRootEpoch(), sealHash(newUC), n.String())
}

// sealHash is the certified Unicity Tree root of uc's seal, or nil if absent. It
// identifies which root-chain view a certificate came from without re-encoding it.
func sealHash(uc *types.UnicityCertificate) []byte {
	if uc.UnicitySeal == nil {
		return nil
	}
	return uc.UnicitySeal.Hash
}
