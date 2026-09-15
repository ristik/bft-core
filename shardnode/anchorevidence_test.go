package shardnode

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	test "github.com/unicitynetwork/bft-core/internal/testutils"
	testcertificates "github.com/unicitynetwork/bft-core/internal/testutils/certificates"
	testtrustbase "github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

/*
Acceptance fixtures for the authenticated anchor-evidence predicate
(docs/design/f6b-quiet-tail-anchor-recovery.md §7).

Every certificate below is really signed and really verified against a trust base this "node"
configures itself — there is no stub for the authentication step, because authentication is the
property under test. The fixtures are deterministic: fixed hashes, fixed rounds, no clock, no
network.

The invariant they exist to pin: a bundle is accepted ONLY if every certificate in it authenticates
against the node's own configuration and trust base, AND the certificates form an unbroken chain by
ASSIGNED round from the block-naming source to the certificate the node already holds. Nothing
weaker — in particular state-root equality — may stand in for that chain.
*/

const evidencePartitionID types.PartitionID = 7

type evidenceFixture struct {
	t     *testing.T
	sign  abcrypto.Signer
	pdr   *types.PartitionDescriptionRecord
	trust stubTrustBaseStore
	conf  []byte
}

func newEvidenceFixture(t *testing.T) *evidenceFixture {
	t.Helper()
	signer, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	tb, ok := testtrustbase.NewTrustBase(t, signer).(*types.RootTrustBaseV1)
	require.True(t, ok)
	pdr := &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: evidencePartitionID}
	return &evidenceFixture{
		t: t, sign: signer, pdr: pdr,
		trust: stubTrustBaseStore{tb: tb},
		conf:  test.DoHash(t, pdr),
	}
}

// h32 is a deterministic 32-byte value; distinct tags give distinct, stable hashes.
func h32(tag byte) []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = tag
	}
	return b
}

// cert signs one certificate together with the technical record it commits to. assignedNext is what
// the root chain tells the shard to submit NEXT — the only round whose certificate may follow this
// one. It is deliberately never round+1 anywhere in these fixtures: certified partition rounds are
// not consecutive, and a predicate that assumed they were invalidated honest evidence on a real
// devnet (docs/design/f6b-quiet-uc-recovery.md §3.3.2).
func (f *evidenceFixture) cert(round, rootRound uint64, prev, state, block []byte, assignedNext uint64) EvidenceLink {
	f.t.Helper()
	return f.certAt(round, rootRound, prev, state, block, assignedNext, 0, 1)
}

// quietTail is the situation the whole design exists for: a block was certified in round 10, and
// every certified round since has been quiet at the state that block produced. A node that returned
// after round 10 holds the round-16 certificate and cannot name the block from it.
//
//	round 10  state A -> state B, block B   assigns 12
//	round 12  quiet at B                    assigns 16
//	round 16  quiet at B                    assigns 19   <- what the returning node holds
func (f *evidenceFixture) quietTail() (AnchorEvidence, AnchorEvidenceContext) {
	f.t.Helper()
	stateA, stateB, blockB := h32(0x0a), h32(0x0b), h32(0xbb)
	source := f.cert(10, 100, stateA, stateB, blockB, 12)
	mid := f.cert(12, 110, stateB, stateB, nil, 16)
	head := f.cert(16, 120, stateB, stateB, nil, 19)

	return AnchorEvidence{
		Source:          source.UC,
		SourceTechnical: source.Technical,
		Tail:            []EvidenceLink{mid, head},
	}, AnchorEvidenceContext{
		PartitionID:   evidencePartitionID,
		ShardID:       types.ShardID{},
		ShardConfHash: f.conf,
		TrustBases:    f.trust,
		Held:          head.UC,
	}
}

func verifyFixture(t *testing.T, ev AnchorEvidence, c AnchorEvidenceContext) (*ExecutionAnchor, error) {
	t.Helper()
	return VerifyAnchorEvidence(context.Background(), ev, c, DefaultAnchorEvidenceLimits)
}

// The case the measurement in docs/design/f1-baseline.md §5.7.3 could not resolve without new
// transactions: nothing is injected, no round after the source names any block, and the returning
// node still ends up with the block hash its executor is missing.
func TestAnchorEvidence_QuietTailRecoversWithoutNewTransactions(t *testing.T) {
	f := newEvidenceFixture(t)
	ev, c := f.quietTail()

	anchor, err := verifyFixture(t, ev, c)
	require.NoError(t, err)
	require.NotNil(t, anchor)
	require.Equal(t, Hash(h32(0xbb)), anchor.BlockHash)
	require.Equal(t, Hash(h32(0x0b)), anchor.StateRoot)
	require.EqualValues(t, 10, anchor.Round)
	require.False(t, anchor.fromGenesisRound, "round 10 builds on a certified predecessor")
}

func TestGenesisContinuity_InitialTimeoutsUseTheSameExactChainRules(t *testing.T) {
	f := newEvidenceFixture(t)
	state := h32(0x0a)
	source := f.cert(0, 100, state, state, nil, 2)
	// A root timeout repeats the exact input record and changes only the authenticated assignment.
	repeat := f.cert(0, 101, state, state, nil, 4)
	quiet := f.cert(4, 110, state, state, nil, 9)
	ev := AnchorEvidence{Source: source.UC, SourceTechnical: source.Technical,
		Tail: []EvidenceLink{repeat, quiet}}
	c := AnchorEvidenceContext{PartitionID: evidencePartitionID, ShardID: types.ShardID{},
		ShardConfHash: f.conf, TrustBases: f.trust, Held: quiet.UC}

	require.NoError(t, VerifyGenesisContinuity(context.Background(), ev, c, DefaultAnchorEvidenceLimits, state))
	err := VerifyGenesisContinuity(context.Background(), ev, c, DefaultAnchorEvidenceLimits, nil)
	require.ErrorIs(t, err, ErrEvidenceWrongContext, "an absent configured state never switches to ordinary-source semantics")
	_, err = VerifyAnchorEvidence(context.Background(), ev, c, DefaultAnchorEvidenceLimits)
	require.ErrorIs(t, err, ErrEvidenceSourceQuiet, "the ordinary block-source predicate stays unchanged")

	wrongTerminal := f.cert(4, 111, state, h32(0x0b), h32(0xbb), 9)
	c.Held = wrongTerminal.UC
	err = VerifyGenesisContinuity(context.Background(), ev, c, DefaultAnchorEvidenceLimits, state)
	require.ErrorIs(t, err, ErrEvidenceConflict, "same round and source state cannot replace terminal identity")

	err = VerifyGenesisContinuity(context.Background(), ev, c, DefaultAnchorEvidenceLimits, h32(0xff))
	require.ErrorIs(t, err, ErrEvidenceNotQuiet, "configuration, not the source certificate, supplies genesis state")
}

func TestAnchorEvidence_MiddleEvidenceMissingOrAltered(t *testing.T) {
	t.Run("a missing middle certificate is a gap, not a shortcut", func(t *testing.T) {
		f := newEvidenceFixture(t)
		ev, c := f.quietTail()
		// Drop round 12. What remains is two authentic certificates whose end state matches
		// exactly what this node holds — and it still must not be accepted, because round 16 is
		// not the round the source assigned.
		ev.Tail = ev.Tail[1:]
		_, err := verifyFixture(t, ev, c)
		require.ErrorIs(t, err, ErrEvidenceGap)
		require.ErrorContains(t, err, "round 16 arrived where 12 was assigned")
	})

	t.Run("an altered middle certificate no longer authenticates", func(t *testing.T) {
		f := newEvidenceFixture(t)
		ev, c := f.quietTail()
		// One field, still perfectly decodable; the signatures no longer cover it.
		ev.Tail[0].UC.InputRecord.Hash = h32(0x0c)
		_, err := verifyFixture(t, ev, c)
		require.ErrorIs(t, err, ErrEvidenceUnauthenticated)
	})

	t.Run("a technical record the certificate does not commit to is refused", func(t *testing.T) {
		f := newEvidenceFixture(t)
		ev, c := f.quietTail()
		// The assignment is what contiguity is judged against, so an unbound technical record
		// would let whoever serves the evidence choose the answer. It is bound by hash.
		ev.Tail[0].Technical = &certification.TechnicalRecord{
			Round: 99, Epoch: 0, Leader: "leader", StatHash: h32(0xa1), FeeHash: h32(0xa2),
		}
		_, err := verifyFixture(t, ev, c)
		require.ErrorIs(t, err, ErrEvidenceWrongContext)
		require.ErrorContains(t, err, "technical record is not the one this certificate commits to")
	})

	t.Run("a non-quiet certificate inside the tail is refused", func(t *testing.T) {
		f := newEvidenceFixture(t)
		stateA, stateB, stateC := h32(0x0a), h32(0x0b), h32(0x0c)
		source := f.cert(10, 100, stateA, stateB, h32(0xbb), 12)
		// Round 12 moved the state. The interval is then NOT quiet, so the source is not the last
		// certified block and cannot be the anchor.
		mid := f.cert(12, 110, stateB, stateC, h32(0xcc), 16)
		head := f.cert(16, 120, stateC, stateC, nil, 19)
		ev := AnchorEvidence{Source: source.UC, SourceTechnical: source.Technical, Tail: []EvidenceLink{mid, head}}
		c := AnchorEvidenceContext{PartitionID: evidencePartitionID, ShardConfHash: f.conf, TrustBases: f.trust, Held: head.UC}
		_, err := verifyFixture(t, ev, c)
		require.ErrorIs(t, err, ErrEvidenceNotQuiet)
	})

	t.Run("a source that names no block is refused", func(t *testing.T) {
		f := newEvidenceFixture(t)
		ev, c := f.quietTail()
		quiet := f.cert(10, 100, h32(0x0b), h32(0x0b), nil, 12)
		ev.Source, ev.SourceTechnical = quiet.UC, quiet.Technical
		_, err := verifyFixture(t, ev, c)
		require.ErrorIs(t, err, ErrEvidenceSourceQuiet)
	})
}

// Trust is the node's own configuration, never the evidence's claim about itself.
func TestAnchorEvidence_WrongPartitionShardConfigOrEpoch(t *testing.T) {
	t.Run("another partition", func(t *testing.T) {
		f := newEvidenceFixture(t)
		ev, c := f.quietTail()
		c.PartitionID = evidencePartitionID + 1
		_, err := verifyFixture(t, ev, c)
		require.ErrorIs(t, err, ErrEvidenceWrongContext)
		require.ErrorContains(t, err, "partition")
	})

	t.Run("another shard of this partition", func(t *testing.T) {
		f := newEvidenceFixture(t)
		ev, c := f.quietTail()
		left, _ := types.ShardID{}.Split()
		c.ShardID = left
		_, err := verifyFixture(t, ev, c)
		require.ErrorIs(t, err, ErrEvidenceWrongContext)
		require.ErrorContains(t, err, "shard")
	})

	t.Run("another shard configuration", func(t *testing.T) {
		f := newEvidenceFixture(t)
		ev, c := f.quietTail()
		c.ShardConfHash = h32(0xee)
		_, err := verifyFixture(t, ev, c)
		require.ErrorIs(t, err, ErrEvidenceWrongContext)
		require.ErrorContains(t, err, "configuration")
	})

	t.Run("a chain crossing a shard epoch boundary is unsupported, not guessed at", func(t *testing.T) {
		f := newEvidenceFixture(t)
		stateA, stateB := h32(0x0a), h32(0x0b)
		source := f.cert(10, 100, stateA, stateB, h32(0xbb), 12)
		// Genuinely signed in the next shard epoch, not tampered into it.
		mid := f.certAtEpoch(12, 110, stateB, stateB, nil, 16, 1)
		head := f.cert(16, 120, stateB, stateB, nil, 19)
		ev := AnchorEvidence{Source: source.UC, SourceTechnical: source.Technical, Tail: []EvidenceLink{mid, head}}
		c := AnchorEvidenceContext{PartitionID: evidencePartitionID, ShardConfHash: f.conf, TrustBases: f.trust, Held: head.UC}
		_, err := verifyFixture(t, ev, c)
		require.ErrorIs(t, err, ErrEvidenceEpochChange)
	})

	t.Run("an epoch with no configured trust base is refused, not adopted", func(t *testing.T) {
		f := newEvidenceFixture(t)
		ev, c := f.quietTail()
		c.TrustBases = stubTrustBaseStore{err: errUnknownEpoch}
		_, err := verifyFixture(t, ev, c)
		require.ErrorIs(t, err, ErrEvidenceUnauthenticated)
	})
}

// §3.3.1's counterexample, as evidence rather than as live observation: a missed non-quiet interval
// can return to the SAME state root behind a DIFFERENT block. State equality therefore proves
// nothing, and only the chain of assignments can be allowed to decide.
func TestAnchorEvidence_SameStateDifferentBlockIsNotHistory(t *testing.T) {
	f := newEvidenceFixture(t)
	_, c := f.quietTail()

	stateA, stateB := h32(0x0a), h32(0x0b)
	// A genuinely certified block that also produced state B, in a round the held tail never
	// followed. Its state root matches what the node holds, exactly; its block does not.
	rival := f.cert(11, 105, stateA, stateB, h32(0xdd), 13)
	mid := f.cert(12, 110, stateB, stateB, nil, 16)
	head := c.Held

	ev := AnchorEvidence{
		Source:          rival.UC,
		SourceTechnical: rival.Technical,
		Tail:            []EvidenceLink{mid, EvidenceLink{UC: head, Technical: mustTechnical(t, 19)}},
	}
	_, err := verifyFixture(t, ev, c)
	require.ErrorIs(t, err, ErrEvidenceGap, "state equality must not substitute for the assignment chain")
}

// §6.1: an older bundle is internally perfect forever. What stops it being replayed is that it does
// not reach where this node stands now.
func TestAnchorEvidence_ReplayOfAnOlderCompleteBundle(t *testing.T) {
	f := newEvidenceFixture(t)
	ev, c := f.quietTail()

	t.Run("a correct chain that stops short of the held certificate is refused", func(t *testing.T) {
		short := ev
		short.Tail = ev.Tail[:1] // ends at round 12; this node holds round 16
		_, err := verifyFixture(t, short, c)
		require.ErrorIs(t, err, ErrEvidenceUnconnected)
		require.ErrorContains(t, err, "chain reaches partition round 12")
	})

	t.Run("a repeat certificate for the held round is still the round the node holds", func(t *testing.T) {
		// The shard timed out and round 16 was re-certified at a later root round; this node holds
		// the repeat. The evidence ends on the ORIGINAL round-16 certificate, and that is honest
		// evidence for exactly the same claim, so it must be accepted.
		repeat := f.cert(16, 999, h32(0x0b), h32(0x0b), nil, 19)
		moved := c
		moved.Held = repeat.UC
		require.NotEqual(t, ev.Tail[1].UC.GetRootRoundNumber(), repeat.UC.GetRootRoundNumber())

		anchor, err := verifyFixture(t, ev, moved)
		require.NoError(t, err)
		require.Equal(t, Hash(h32(0xbb)), anchor.BlockHash)
	})

	t.Run("the same chain replayed after the node has moved on is refused", func(t *testing.T) {
		// Accepted once, at round 16.
		_, err := verifyFixture(t, ev, c)
		require.NoError(t, err)

		// The shard certified another block; this node now holds round 19 at state C. The old
		// bundle still verifies certificate by certificate and still must not be accepted.
		moved := f.cert(19, 130, h32(0x0b), h32(0x0c), h32(0xcc), 22)
		c.Held = moved.UC
		_, err = verifyFixture(t, ev, c)
		require.ErrorIs(t, err, ErrEvidenceUnconnected)
	})
}

// An unbounded chain is work chosen by whoever serves the evidence. Exceeding a bound is a named
// refusal — never a truncation, because a shortened chain proves nothing.
func TestAnchorEvidence_ExhaustedBounds(t *testing.T) {
	f := newEvidenceFixture(t)
	ev, c := f.quietTail()

	t.Run("too many certificates", func(t *testing.T) {
		_, err := VerifyAnchorEvidence(context.Background(), ev, c, AnchorEvidenceLimits{MaxCertificates: 2, MaxBytes: 1 << 20})
		require.ErrorIs(t, err, ErrEvidenceExhausted)
		require.ErrorContains(t, err, "3 certificates, limit 2")
	})

	t.Run("too many bytes", func(t *testing.T) {
		_, err := VerifyAnchorEvidence(context.Background(), ev, c, AnchorEvidenceLimits{MaxCertificates: 512, MaxBytes: 64})
		require.ErrorIs(t, err, ErrEvidenceExhausted)
	})

	t.Run("bounds are checked before any signature work", func(t *testing.T) {
		// Every certificate here is unauthenticated garbage; the refusal must still be the bound,
		// so that an oversized bundle costs no verification.
		big := ev
		big.Tail[0].UC.UnicitySeal.Signatures = nil
		_, err := VerifyAnchorEvidence(context.Background(), big, c, AnchorEvidenceLimits{MaxCertificates: 1, MaxBytes: 1 << 20})
		require.ErrorIs(t, err, ErrEvidenceExhausted)
	})
}

// Evidence retrieval and payload acquisition are separate decisions. The predicate answers only the
// first, so a node that cannot obtain the block body still holds a verified target and can retry
// acquisition without re-verifying anything or being pushed back to no-anchor.
func TestAnchorEvidence_VerifiedTargetSurvivesAnUnavailablePayload(t *testing.T) {
	f := newEvidenceFixture(t)
	ev, c := f.quietTail()

	anchor, err := verifyFixture(t, ev, c)
	require.NoError(t, err)

	// Acquisition of the payload for anchor.BlockHash fails; nothing here has a payload at all.
	// The verified target is unaffected, and re-verifying the same bundle is deterministic.
	again, err := verifyFixture(t, ev, c)
	require.NoError(t, err)
	require.Equal(t, *anchor, *again)
	require.Equal(t, Hash(h32(0xbb)), again.BlockHash)
}

// --- helpers used by single cases ------------------------------------------------------------

var errUnknownEpoch = errors.New("unknown epoch")

func mustTechnical(t *testing.T, assignedNext uint64) *certification.TechnicalRecord {
	t.Helper()
	return &certification.TechnicalRecord{
		Round: assignedNext, Epoch: 0, Leader: "leader", StatHash: h32(0xa1), FeeHash: h32(0xa2),
	}
}

// certAt is the general form: cert() with the shard epoch and the input-record timestamp chosen.
func (f *evidenceFixture) certAt(round, rootRound uint64, prev, state, block []byte, assignedNext, epoch, timestamp uint64) EvidenceLink {
	f.t.Helper()
	tr := &certification.TechnicalRecord{
		Round: assignedNext, Epoch: epoch, Leader: "leader",
		StatHash: h32(0xa1), FeeHash: h32(0xa2),
	}
	trHash, err := tr.Hash()
	require.NoError(f.t, err)
	ir := &types.InputRecord{
		Version: 1, RoundNumber: round, Epoch: epoch,
		PreviousHash: prev, Hash: state, BlockHash: block,
		SummaryValue: []byte{}, Timestamp: timestamp,
	}
	uc := testcertificates.CreateUnicityCertificate(f.t, f.sign, ir, f.pdr, rootRound, h32(0xb0), trHash)
	require.NotNil(f.t, uc)
	return EvidenceLink{UC: uc, Technical: tr}
}

// certAtEpoch is certAt() in a chosen shard epoch, for the epoch-transition fixtures.
func (f *evidenceFixture) certAtEpoch(round, rootRound uint64, prev, state, block []byte, assignedNext, epoch uint64) EvidenceLink {
	f.t.Helper()
	return f.certAt(round, rootRound, prev, state, block, assignedNext, epoch, 1)
}

/*
The terminal binding: the chain must end at THE certificate this node holds, not at "a certificate
with the same round number and state root".

Round-and-state equality was the first form of this check, and review reproduced two ways past it
with genuinely signed certificates. Both are here, plus the honest cases the check must not break.
*/
func TestAnchorEvidence_TerminalBindingToTheHeldCertificate(t *testing.T) {
	t.Run("a held certificate naming a block is a different statement about that round", func(t *testing.T) {
		f := newEvidenceFixture(t)
		ev, c := f.quietTail()
		// Round 16 again, genuinely signed, and it says round 16 CERTIFIED BLOCK dd, moving the
		// state to C. The evidence says round 16 was quiet at B. Accepting would hand back anchor
		// bb for a round this node's own certificate says produced a different block — and the
		// block hash is exactly what P-id gates signing on.
		c.Held = f.cert(16, 121, h32(0x0b), h32(0x0c), h32(0xdd), 19).UC
		_, err := verifyFixture(t, ev, c)
		require.ErrorIs(t, err, ErrEvidenceConflict)
		require.ErrorContains(t, err, "block dddd")
		require.False(t, Retryable(err), "no other provider can adjudicate this")
	})

	t.Run("a held certificate naming a block at an UNCHANGED state cannot exist", func(t *testing.T) {
		// The exact construction review used. It is refused, but on the earlier and stronger
		// ground: an input record whose state did not move may not name a block (bft-go-base
		// input_record.go), so no root chain would have signed it and it fails authentication.
		// Recorded so its reason is not mistaken for the conflict check above.
		f := newEvidenceFixture(t)
		ev, c := f.quietTail()
		c.Held = f.cert(16, 121, h32(0x0b), h32(0x0b), h32(0xdd), 19).UC
		_, err := verifyFixture(t, ev, c)
		require.ErrorIs(t, err, ErrEvidenceUnauthenticated)
		require.ErrorContains(t, err, "held certificate")
	})

	t.Run("a held certificate in another epoch fires the epoch contract", func(t *testing.T) {
		f := newEvidenceFixture(t)
		ev, c := f.quietTail()
		c.Held = f.certAtEpoch(16, 125, h32(0x0b), h32(0x0b), nil, 19, 1).UC
		_, err := verifyFixture(t, ev, c)
		require.ErrorIs(t, err, ErrEvidenceEpochChange)
	})

	t.Run("a held certificate differing only in a field the state does not show conflicts", func(t *testing.T) {
		// Same round, same state, same (nil) block, validly signed — and a different timestamp, so
		// it is a different signed statement about round 16. Comparing round and state would miss
		// it; comparing the canonical encoding the signatures cover does not, which is why the
		// comparison is that encoding rather than a hand-written list of fields.
		f := newEvidenceFixture(t)
		ev, c := f.quietTail()
		c.Held = f.certAt(16, 120, h32(0x0b), h32(0x0b), nil, 19, 0, 2).UC
		_, err := verifyFixture(t, ev, c)
		require.ErrorIs(t, err, ErrEvidenceConflict)
	})

	t.Run("a held certificate at a different state conflicts", func(t *testing.T) {
		f := newEvidenceFixture(t)
		ev, c := f.quietTail()
		c.Held = f.cert(16, 140, h32(0x0c), h32(0x0c), nil, 19).UC
		_, err := verifyFixture(t, ev, c)
		require.ErrorIs(t, err, ErrEvidenceConflict)
	})

	t.Run("a held certificate is authenticated against this node's own context", func(t *testing.T) {
		// "Held" means this node verified it on delivery. The recovery context is a different
		// question, and the cost of asking it again is one signature verification.
		f := newEvidenceFixture(t)
		ev, c := f.quietTail()
		forged := f.cert(16, 120, h32(0x0b), h32(0x0b), nil, 19)
		forged.UC.UnicitySeal.Signatures = nil
		c.Held = forged.UC
		_, err := verifyFixture(t, ev, c)
		require.ErrorIs(t, err, ErrEvidenceUnauthenticated)
		require.ErrorContains(t, err, "held certificate")
	})
}

/*
Repeat normalisation inside the tail.

A repeat certificate re-certifies a round the root chain already certified, at a later root round,
with the same input record and a NEW technical record — so a new assignment. It is the ordinary
product of a root-chain timeout, which means a literal transcript of what a provider observed
contains repeats, and a predicate that rejected them as a gap would make honest evidence
unrepresentable. Review reproduced exactly that.
*/
func TestAnchorEvidence_RepeatsInsideTheTail(t *testing.T) {
	t.Run("a repeat that updates the assignment is accepted", func(t *testing.T) {
		f := newEvidenceFixture(t)
		ev, c := f.quietTail()
		// Round 12 was certified assigning 16; a timeout re-certified it at root round 115
		// assigning 15 instead, then 15 came and assigned 16.
		repeat := f.cert(12, 115, h32(0x0b), h32(0x0b), nil, 15)
		quiet := f.cert(15, 118, h32(0x0b), h32(0x0b), nil, 16)
		ev.Tail = []EvidenceLink{ev.Tail[0], repeat, quiet, ev.Tail[1]}

		anchor, err := verifyFixture(t, ev, c)
		require.NoError(t, err)
		require.Equal(t, Hash(h32(0xbb)), anchor.BlockHash)
	})

	t.Run("a repeat must follow at a strictly later root round", func(t *testing.T) {
		f := newEvidenceFixture(t)
		ev, c := f.quietTail()
		// Root round 110 is the round-12 certificate's own; replaying it would let a provider
		// rewrite the assignment freely.
		replay := f.cert(12, 110, h32(0x0b), h32(0x0b), nil, 15)
		quiet := f.cert(15, 118, h32(0x0b), h32(0x0b), nil, 16)
		ev.Tail = []EvidenceLink{ev.Tail[0], replay, quiet, ev.Tail[1]}
		_, err := verifyFixture(t, ev, c)
		require.ErrorIs(t, err, ErrEvidenceGap)
		require.ErrorContains(t, err, "does not follow root round 110")
	})

	t.Run("two certificates for one round that disagree are a conflict, not a repeat", func(t *testing.T) {
		f := newEvidenceFixture(t)
		ev, c := f.quietTail()
		disagree := f.cert(12, 115, h32(0x0b), h32(0x0c), h32(0xdd), 15)
		ev.Tail = []EvidenceLink{ev.Tail[0], disagree, ev.Tail[1]}
		_, err := verifyFixture(t, ev, c)
		require.ErrorIs(t, err, ErrEvidenceCandidateSplit)
		// Both halves of the contradiction came from this provider. The bundle is refused, but
		// nothing about it says another provider cannot serve a consistent chain.
		require.True(t, Retryable(err))
	})
}

// countingTrustBaseStore records whether it was consulted, so a fixture can assert that a refusal
// happened before any cryptographic work was paid for.
type countingTrustBaseStore struct {
	inner stubTrustBaseStore
	calls int
}

func (s *countingTrustBaseStore) GetByEpoch(ctx context.Context, e uint64) (*types.RootTrustBaseV1, error) {
	s.calls++
	return s.inner.GetByEpoch(ctx, e)
}

func TestAnchorEvidence_BoundsCoverTheWholeBundle(t *testing.T) {
	t.Run("an oversized technical record is refused before any trust-base work", func(t *testing.T) {
		f := newEvidenceFixture(t)
		ev, c := f.quietTail()
		counting := &countingTrustBaseStore{inner: f.trust}
		c.TrustBases = counting

		// The certificate is small; the technical record travelling with it is a megabyte of
		// attacker-chosen leader identifier. Bounding only the certificates left tr.Hash() to be
		// handed this, after the certificate's signatures had already been verified.
		ev.Tail[0].Technical = &certification.TechnicalRecord{
			Round: 16, Epoch: 0, Leader: string(make([]byte, 1<<20)),
			StatHash: h32(0xa1), FeeHash: h32(0xa2),
		}
		_, err := VerifyAnchorEvidence(context.Background(), ev, c, DefaultAnchorEvidenceLimits)
		require.ErrorIs(t, err, ErrEvidenceExhausted)
		require.Zero(t, counting.calls, "the bound must be applied before any signature or hash work")
	})

	t.Run("the bound is measured over certificates and technical records together", func(t *testing.T) {
		f := newEvidenceFixture(t)
		ev, c := f.quietTail()
		encoded, err := types.Cbor.Marshal(ev)
		require.NoError(t, err)
		certsOnly := 0
		for _, uc := range []*types.UnicityCertificate{ev.Source, ev.Tail[0].UC, ev.Tail[1].UC} {
			b, err := types.Cbor.Marshal(uc)
			require.NoError(t, err)
			certsOnly += len(b)
		}
		require.Greater(t, len(encoded), certsOnly, "the bundle is larger than its certificates alone")

		// A limit that the certificates alone would satisfy must still refuse the whole bundle.
		_, err = VerifyAnchorEvidence(context.Background(), ev, c, AnchorEvidenceLimits{MaxCertificates: 512, MaxBytes: certsOnly})
		require.ErrorIs(t, err, ErrEvidenceExhausted)
	})

	t.Run("a missing bound is a refusal, not unlimited", func(t *testing.T) {
		f := newEvidenceFixture(t)
		ev, c := f.quietTail()
		for _, l := range []AnchorEvidenceLimits{{}, {MaxCertificates: 512}, {MaxBytes: 1 << 20}} {
			_, err := VerifyAnchorEvidence(context.Background(), ev, c, l)
			require.ErrorIs(t, err, ErrEvidenceLimitsInvalid)
			require.False(t, Retryable(err), "a caller bug is not fixed by asking another peer")
		}
	})
}

/*
Retry classification.

A refusal is a property of the bundle, and only a few kinds say something no other provider can
change. Getting this wrong in the strict direction is the expensive one: an Unconnected result is
the ordinary case of a peer holding less than the requester needs, and treating it as fatal would
let a single unhelpful peer end a recovery that its neighbour would have completed.
*/
func TestAnchorEvidence_RetryClassification(t *testing.T) {
	for _, tc := range []struct {
		err       error
		retryable bool
	}{
		{nil, false},
		{ErrEvidenceUnconnected, true},
		{ErrEvidenceGap, true},
		{ErrEvidenceNotQuiet, true},
		{ErrEvidenceSourceQuiet, true},
		{ErrEvidenceUnauthenticated, true},
		{ErrEvidenceWrongContext, true},
		{ErrEvidenceExhausted, true},
		{ErrEvidenceMalformed, true},
		{ErrEvidenceEpochChange, true},
		{ErrEvidenceCandidateSplit, true},
		{ErrEvidenceConflict, false},
		{ErrEvidenceLimitsInvalid, false},
	} {
		name := "nil"
		if tc.err != nil {
			name = tc.err.Error()
		}
		t.Run(name, func(t *testing.T) {
			if tc.err == nil {
				require.False(t, Retryable(nil))
				return
			}
			require.Equal(t, tc.retryable, Retryable(tc.err))
			// The classification must survive the wrapping every call site adds.
			require.Equal(t, tc.retryable, Retryable(fmt.Errorf("tail[3]: %w", tc.err)))
		})
	}
}

/*
A candidate is chosen by the provider, so a refusal decided from candidate content is a statement
about THAT CANDIDATE and never about what other providers hold.

Review reproduced the sharpest version: incrementing one UNSIGNED epoch byte of an otherwise valid
certificate returned EpochChange, which the caller treated as a conclusion about the shard's
history — so a provider could suppress every alternate provider with a byte it did not have to sign.
Both halves are fixed here: an altered certificate is reported as the forgery it is, and even a
GENUINE epoch-crossing candidate no longer terminates the attempt.
*/
func TestAnchorEvidence_ACandidateRefusalDoesNotEndTheAttempt(t *testing.T) {
	// attempt models what a caller does: try providers in turn, stopping only on success or on a
	// refusal that Retryable says no other provider can fix. It returns how many were consulted.
	attempt := func(t *testing.T, c AnchorEvidenceContext, bundles ...AnchorEvidence) (*ExecutionAnchor, error, int) {
		t.Helper()
		var err error
		for i, ev := range bundles {
			var anchor *ExecutionAnchor
			anchor, err = verifyFixture(t, ev, c)
			if err == nil {
				return anchor, nil, i + 1
			}
			if !Retryable(err) {
				return nil, err, i + 1
			}
		}
		return nil, err, len(bundles)
	}

	t.Run("a tampered epoch is a forgery, and the next provider is still consulted", func(t *testing.T) {
		f := newEvidenceFixture(t)
		good, c := f.quietTail()
		tampered, _ := f.quietTail()
		tampered.Tail[0].UC.InputRecord.Epoch++ // provider alteration, no new signature

		// On its own: reported as what it is.
		_, err := verifyFixture(t, tampered, c)
		require.ErrorIs(t, err, ErrEvidenceUnauthenticated)
		require.NotErrorIs(t, err, ErrEvidenceEpochChange, "an unsigned byte must not reach the epoch decision")

		anchor, err, tried := attempt(t, c, tampered, good)
		require.NoError(t, err)
		require.Equal(t, 2, tried, "the second provider must still be consulted")
		require.Equal(t, Hash(h32(0xbb)), anchor.BlockHash)
	})

	t.Run("a genuine epoch-crossing candidate does not prove every candidate crosses one", func(t *testing.T) {
		f := newEvidenceFixture(t)
		good, c := f.quietTail()

		// A real, correctly signed chain whose source is in an older shard epoch. It is genuinely
		// unsupported — and it is one provider's choice of source, not a fact about the shard.
		stateA, stateB := h32(0x0a), h32(0x0b)
		oldSource := f.certAtEpoch(10, 100, stateA, stateB, h32(0xbb), 12, 0)
		crossing := AnchorEvidence{
			Source:          oldSource.UC,
			SourceTechnical: oldSource.Technical,
			Tail: []EvidenceLink{
				f.certAtEpoch(12, 110, stateB, stateB, nil, 16, 1),
				f.certAtEpoch(16, 120, stateB, stateB, nil, 19, 1),
			},
		}
		_, err := verifyFixture(t, crossing, c)
		require.ErrorIs(t, err, ErrEvidenceEpochChange)
		require.True(t, Retryable(err), "the source is the provider's choice, not the shard's history")

		anchor, err, tried := attempt(t, c, crossing, good)
		require.NoError(t, err)
		require.Equal(t, 2, tried)
		require.Equal(t, Hash(h32(0xbb)), anchor.BlockHash)
	})

	t.Run("a terminal conflict with this node's own certificate does end the attempt", func(t *testing.T) {
		// The one contradiction where half the evidence is ours. No provider can adjudicate it, so
		// the loop must stop rather than shop for a provider that agrees — and it must stop even
		// though a "good" bundle is queued behind it.
		f := newEvidenceFixture(t)
		good, c := f.quietTail()
		c.Held = f.cert(16, 121, h32(0x0b), h32(0x0c), h32(0xdd), 19).UC

		_, err, tried := attempt(t, c, good, good)
		require.ErrorIs(t, err, ErrEvidenceConflict)
		require.Equal(t, 1, tried, "the attempt stops at the first provider")
	})
}
