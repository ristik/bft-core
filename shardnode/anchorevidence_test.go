package shardnode

import (
	"context"
	"errors"
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
	tr := &certification.TechnicalRecord{
		Round: assignedNext, Epoch: 0, Leader: "leader",
		StatHash: h32(0xa1), FeeHash: h32(0xa2),
	}
	trHash, err := tr.Hash()
	require.NoError(f.t, err)
	ir := &types.InputRecord{
		Version: 1, RoundNumber: round, Epoch: 0,
		PreviousHash: prev, Hash: state, BlockHash: block,
		SummaryValue: []byte{}, Timestamp: 1,
	}
	uc := testcertificates.CreateUnicityCertificate(f.t, f.sign, ir, f.pdr, rootRound, h32(0xb0), trHash)
	require.NotNil(f.t, uc)
	return EvidenceLink{UC: uc, Technical: tr}
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
		require.ErrorContains(t, err, "chain ends at partition round 12")
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

	t.Run("a chain ending at the held round but a different state is refused", func(t *testing.T) {
		// Both certificates authenticate and both are for round 16; they disagree about the state.
		// This is the check that stops the round test alone from being the whole answer.
		conflicting := f.cert(16, 140, h32(0x0c), h32(0x0c), nil, 19)
		moved := c
		moved.Held = conflicting.UC
		_, err := verifyFixture(t, ev, moved)
		require.ErrorIs(t, err, ErrEvidenceUnconnected)
		require.ErrorContains(t, err, "for round 16")
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
		_, err := VerifyAnchorEvidence(context.Background(), ev, c, AnchorEvidenceLimits{MaxCertificates: 2})
		require.ErrorIs(t, err, ErrEvidenceExhausted)
		require.ErrorContains(t, err, "3 certificates, limit 2")
	})

	t.Run("too many bytes", func(t *testing.T) {
		_, err := VerifyAnchorEvidence(context.Background(), ev, c, AnchorEvidenceLimits{MaxBytes: 64})
		require.ErrorIs(t, err, ErrEvidenceExhausted)
	})

	t.Run("bounds are checked before any signature work", func(t *testing.T) {
		// Every certificate here is unauthenticated garbage; the refusal must still be the bound,
		// so that an oversized bundle costs no verification.
		big := ev
		big.Tail[0].UC.UnicitySeal.Signatures = nil
		_, err := VerifyAnchorEvidence(context.Background(), big, c, AnchorEvidenceLimits{MaxCertificates: 1})
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

// certAtEpoch is cert() with the shard epoch chosen, for the epoch-transition fixture.
func (f *evidenceFixture) certAtEpoch(round, rootRound uint64, prev, state, block []byte, assignedNext, epoch uint64) EvidenceLink {
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
		SummaryValue: []byte{}, Timestamp: 1,
	}
	uc := testcertificates.CreateUnicityCertificate(f.t, f.sign, ir, f.pdr, rootRound, h32(0xb0), trHash)
	require.NotNil(f.t, uc)
	return EvidenceLink{UC: uc, Technical: tr}
}
