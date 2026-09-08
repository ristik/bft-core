package shardnode_test

import (
	"bytes"
	"crypto"
	"testing"

	"github.com/stretchr/testify/require"

	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"

	testcertificates "github.com/unicitynetwork/bft-core/internal/testutils/certificates"
	testtrustbase "github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
)

/*
TestContinuityCounterexample is the executable form of the counterexample review supplied against
F6b stage 2 (PR #95), in the same spirit as stage 1 (#94): establish the defect before anything is
built on the design that contains it.

The claim under test is about a PROPOSED PERSISTENCE FORMAT, not about code that runs today, so
this file changes no behaviour and wires into no runtime path. It implements both candidate rules as
local functions — an executable specification — and shows that one accepts a history in which the
node's execution anchor is wrong, and the other refuses it.

THE HISTORY. All four certificates below are genuinely signed by the test trust base. No forged
signature is involved, which is the whole point: the previous design could be defeated without
breaking any cryptography.

	round 10  source UC, NON-QUIET, binds block A, state S    <- retained in the checkpoint
	round 11  omitted from the checkpoint: state changes S -> T
	round 12  omitted from the checkpoint: binds a DIFFERENT block C, state returns to S
	round 13  latest UC, QUIET at S                            <- retained in the checkpoint

After this history the execution anchor is C, not A. A node that restores the checkpoint and votes
on the strength of block A is building on a block the root chain replaced.

WHAT EACH RULE DOES WITH IT:

  - continuityByArithmetic (the previous revision): retains the two endpoint certificates plus the
    unsigned integers continuityFromRound=10 and continuityRounds=3. Both certificates verify, the
    state roots agree, and 13-10 == 3. It ACCEPTS. That acceptance is the defect.

  - continuityByEvidence (the correction): requires the retained set to contain a verified QUIET
    certificate for every partition round in (10, 13]. Rounds 11 and 12 are absent, so it REFUSES.

A positive control is included, because a rule that refuses everything would pass the negative
trivially.
*/

// ---------------------------------------------------------------------------
// Executable specification. These mirror docs/design/f6b-quiet-uc-recovery.md §3.3 and exist to
// make the comparison checkable; they are deliberately not exported and not called by any
// production path.
// ---------------------------------------------------------------------------

// checkpoint is the restored-from-disk material. Only the certificates are signed; every other
// field is locally written and therefore attacker- or corruption-controlled.
type checkpoint struct {
	sourceUC *types.UnicityCertificate // the non-quiet certificate that established the anchor
	latestUC *types.UnicityCertificate // the most recent certificate observed
	evidence []*types.UnicityCertificate

	// Unsigned. Present only to model the previous revision's format.
	continuityFromRound uint64
	continuityRounds    uint64
}

// sameIR compares the canonical CBOR the signatures actually cover, never a field-by-field scan.
func sameIR(a, b *types.UnicityCertificate) bool {
	aBytes, err := a.InputRecord.Bytes()
	if err != nil {
		return false
	}
	bBytes, err := b.InputRecord.Bytes()
	if err != nil {
		return false
	}
	return bytes.Equal(aBytes, bBytes)
}

// verifyUC is the authentication both rules share: it is NOT the difference between them.
func verifyUC(t *testing.T, uc *types.UnicityCertificate, tb types.RootTrustBase, shardConfHash []byte) bool {
	t.Helper()
	return uc.Verify(tb, crypto.SHA256, 8, types.ShardID{}, shardConfHash) == nil
}

// continuityByArithmetic is the PREVIOUS revision's rule: authenticate the endpoints, compare state
// roots, and reconcile the interval with the stored counters.
func continuityByArithmetic(t *testing.T, cp checkpoint, tb types.RootTrustBase, shardConfHash []byte) bool {
	t.Helper()
	if !verifyUC(t, cp.sourceUC, tb, shardConfHash) || !verifyUC(t, cp.latestUC, tb, shardConfHash) {
		return false
	}
	// The anchor's state must be the state the latest certificate sits at.
	if !bytes.Equal(cp.sourceUC.InputRecord.Hash, cp.latestUC.InputRecord.Hash) {
		return false
	}
	if cp.sourceUC.InputRecord.RoundNumber != cp.continuityFromRound {
		return false
	}
	// The step count must reconcile the two endpoints. This is the unsound part.
	return cp.latestUC.InputRecord.RoundNumber-cp.continuityFromRound == cp.continuityRounds
}

// continuityByEvidence is the CORRECTED rule: the retained certificates must themselves prove every
// round in (r_a, r_n] was quiet at the anchor's state. Counters are not read at all.
// This counterexample model is not a production restore verifier: configured epoch selection,
// resource limits and independent signing authorization remain required by the design and the
// stage-3 fixture contract. A true result here grants no authority to resume voting.
func continuityByEvidence(t *testing.T, cp checkpoint, tb types.RootTrustBase, shardConfHash []byte) bool {
	t.Helper()
	if !verifyUC(t, cp.sourceUC, tb, shardConfHash) || !verifyUC(t, cp.latestUC, tb, shardConfHash) {
		return false
	}
	// §3.3.4 condition 3: the source must be non-quiet, or it is not an anchor.
	if len(cp.sourceUC.InputRecord.BlockHash) == 0 {
		return false
	}
	anchorState := cp.sourceUC.InputRecord.Hash
	first := cp.sourceUC.InputRecord.RoundNumber
	last := cp.latestUC.InputRecord.RoundNumber
	if last < first {
		return false // §3.3.3: no arithmetic before establishing r_n >= r_a
	}
	if last == first {
		// §3.3.4, the empty interval: the anchor was established by the most recent certificate
		// and no quiet round has followed it. Source and latest must be the SAME certificate and
		// the evidence set must be empty; conditions 4-6 do not apply.
		if len(cp.evidence) != 0 {
			return false
		}
		return sameIR(cp.sourceUC, cp.latestUC)
	}
	// §3.3.4 condition 5: exactly one certificate per round, contiguous, in order.
	if uint64(len(cp.evidence)) != last-first {
		return false
	}
	for i, uc := range cp.evidence {
		if !verifyUC(t, uc, tb, shardConfHash) {
			return false // condition 1
		}
		if uc.InputRecord.RoundNumber != first+uint64(i)+1 {
			return false // condition 5
		}
		// Condition 4: quiet means all three of — unchanged state, at the ANCHOR'S state, and an
		// EMPTY BlockHash. The last is not implied by the other two: a certificate claiming an
		// unchanged state root while carrying a block hash is malformed, not quiet.
		if len(uc.InputRecord.BlockHash) != 0 {
			return false
		}
		if !bytes.Equal(uc.InputRecord.PreviousHash, uc.InputRecord.Hash) {
			return false
		}
		if !bytes.Equal(uc.InputRecord.Hash, anchorState) {
			return false
		}
	}
	// Condition 6: the evidence must end at the latest certificate.
	return sameIR(cp.evidence[len(cp.evidence)-1], cp.latestUC)
}

// ---------------------------------------------------------------------------

func TestContinuityCounterexample(t *testing.T) {
	signer, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	tb := testtrustbase.NewTrustBase(t, signer)
	pdr := &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: 8}

	stateS := bytes.Repeat([]byte{0x51}, 32)
	stateT := bytes.Repeat([]byte{0x54}, 32)
	blockA := bytes.Repeat([]byte{0x0a}, 32)
	blockC := bytes.Repeat([]byte{0x0c}, 32)
	before := bytes.Repeat([]byte{0x00}, 32)

	// sign turns an input record into a genuinely signed certificate at the given root round.
	sign := func(ir *types.InputRecord, rootRound uint64) *types.UnicityCertificate {
		t.Helper()
		// A distinct 32-byte TR hash per round: the certificate is rejected outright without one,
		// and reusing a single value across rounds would make the fixtures less like real
		// certificates for no benefit.
		trHash := bytes.Repeat([]byte{byte(ir.RoundNumber)}, 32)
		uc := testcertificates.CreateUnicityCertificate(t, signer, ir, pdr, rootRound, make([]byte, 32), trHash)
		require.NoError(t, uc.Verify(tb, crypto.SHA256, 8, types.ShardID{}, uc.ShardConfHash),
			"every fixture certificate must be genuinely signed; a forged one would prove nothing")
		return uc
	}
	nonQuiet := func(round uint64, prev, hash, block []byte) *types.InputRecord {
		return &types.InputRecord{Version: 1, RoundNumber: round, Epoch: 0,
			PreviousHash: prev, Hash: hash, BlockHash: block, SummaryValue: []byte{1}, Timestamp: 1000}
	}
	quiet := func(round uint64, state []byte) *types.InputRecord {
		return &types.InputRecord{Version: 1, RoundNumber: round, Epoch: 0,
			PreviousHash: state, Hash: state, BlockHash: nil, SummaryValue: []byte{1}, Timestamp: 1000}
	}

	// The history from the review comment.
	uc10 := sign(nonQuiet(10, before, stateS, blockA), 20) // anchor: block A at state S
	uc11 := sign(nonQuiet(11, stateS, stateT, blockA), 21) // omitted: S -> T
	uc12 := sign(nonQuiet(12, stateT, stateS, blockC), 22) // omitted: different block C, back to S
	uc13 := sign(quiet(13, stateS), 23)                    // latest: quiet at S

	shardConfHash := uc10.ShardConfHash

	t.Run("the omitted interval really does move the anchor", func(t *testing.T) {
		// The premise, asserted rather than assumed: rounds 11 and 12 are state-changing, they
		// return to the same state root, and they leave a DIFFERENT block as the execution head.
		require.NotEqual(t, stateS, stateT, "round 11 must actually change state")
		require.Equal(t, stateS, []byte(uc12.InputRecord.Hash), "round 12 must return to the anchor's state root")
		require.NotEqual(t, blockA, blockC, "round 12 must bind a different block")
		require.Equal(t, blockC, []byte(uc12.InputRecord.BlockHash), "the true execution anchor after round 12 is C")
		require.NotEmpty(t, uc11.InputRecord.BlockHash, "a state-changing round carries a block hash")
	})

	// The checkpoint an attacker or a corrupted file can present: both endpoints genuine, the
	// state-changing interval simply not retained, counters set to whatever reconciles.
	forged := checkpoint{
		sourceUC:            uc10,
		latestUC:            uc13,
		evidence:            nil, // rounds 11 and 12 are not retained
		continuityFromRound: 10,
		continuityRounds:    3, // 13 - 10
	}

	t.Run("the previous revision ACCEPTS it — this is the defect", func(t *testing.T) {
		require.True(t, continuityByArithmetic(t, forged, tb, shardConfHash),
			"the arithmetic rule accepts a history whose real execution anchor is C, not A")
	})

	t.Run("the corrected rule REFUSES it", func(t *testing.T) {
		require.False(t, continuityByEvidence(t, forged, tb, shardConfHash),
			"rounds 11 and 12 are absent from the evidence, so continuity is not proven")
	})

	t.Run("editing the counters cannot rescue it", func(t *testing.T) {
		// Fixture 21 of the design's plan: every locally-writable value an implementation might be
		// tempted to keep, set to whatever would make arithmetic succeed. The corrected rule does
		// not read them, so the outcome is unchanged.
		for _, tc := range []struct {
			name             string
			fromRound, count uint64
		}{
			{"counters as the attacker would set them", 10, 3},
			{"count inflated", 10, 99},
			{"count zeroed", 10, 0},
			{"source round misreported", 12, 1},
		} {
			t.Run(tc.name, func(t *testing.T) {
				cp := forged
				cp.continuityFromRound, cp.continuityRounds = tc.fromRound, tc.count
				require.False(t, continuityByEvidence(t, cp, tb, shardConfHash))
			})
		}
	})

	t.Run("truncation is refused, not reconciled", func(t *testing.T) {
		// Fixture 22: a genuine but incomplete set. Retaining only the last quiet certificate and
		// letting the endpoints meet arithmetically is the same unsound construction.
		cp := forged
		cp.evidence = []*types.UnicityCertificate{uc13}
		require.False(t, continuityByEvidence(t, cp, tb, shardConfHash),
			"one certificate cannot cover a three-round interval")
	})

	t.Run("a non-quiet certificate inside the evidence is a contradiction", func(t *testing.T) {
		// §3.3.4 condition 4. Handing over the real rounds 11 and 12 does not help: they prove the
		// interval was NOT quiet, so the anchor is not carried forward.
		cp := forged
		cp.evidence = []*types.UnicityCertificate{uc11, uc12, uc13}
		require.False(t, continuityByEvidence(t, cp, tb, shardConfHash),
			"the complete true history must refuse the anchor, since the interval was not quiet")
	})

	t.Run("POSITIVE CONTROL: an intact quiet interval is accepted", func(t *testing.T) {
		// Without this the refusals above could all be passing because the rule refuses everything.
		q11 := sign(quiet(11, stateS), 21)
		q12 := sign(quiet(12, stateS), 22)
		intact := checkpoint{
			sourceUC: uc10,
			latestUC: uc13,
			evidence: []*types.UnicityCertificate{q11, q12, uc13},
		}
		require.True(t, continuityByEvidence(t, intact, tb, shardConfHash),
			"a complete, contiguous, correctly signed quiet run must establish continuity")
		// And the arithmetic rule agrees here — the two rules differ only on the unsound case,
		// which is what makes the counterexample the whole argument.
		intact.continuityFromRound, intact.continuityRounds = 10, 3
		require.True(t, continuityByArithmetic(t, intact, tb, shardConfHash))
	})

	t.Run("continuity is RELATIVE to the retained latest UC, and proves nothing about freshness", func(t *testing.T) {
		// Review's finding on the corrected design (5139012890), reproduced here because it is a
		// limit of the predicate rather than a bug in it.
		//
		// A checkpoint whose latest UC is q12 — with the shard in fact already at round 13 —
		// contains a complete, contiguous, correctly signed quiet run for (10, 12]. Every
		// condition holds and continuity is established, CORRECTLY: rounds 11 and 12 really were
		// quiet at S, so block A really is the execution anchor as of round 12.
		//
		// What it does NOT establish is that round 12 is where the shard is NOW. An older
		// checkpoint replays perfectly. So the round sequence supplies CONTINUITY, not
		// FRESHNESS, and restoring from it must not roll back anything that has to move in one
		// direction only — the observation cursor, and above all what this node has already
		// signed. That contract is separate, is not carried by these certificates, and belongs
		// to #14; see docs/design/f6b-quiet-uc-recovery.md §6.1.
		q11 := sign(quiet(11, stateS), 21)
		q12 := sign(quiet(12, stateS), 22)
		historical := checkpoint{
			sourceUC: uc10,
			latestUC: q12, // stale: the shard is at 13
			evidence: []*types.UnicityCertificate{q11, q12},
		}
		require.True(t, continuityByEvidence(t, historical, tb, shardConfHash),
			"an older but complete checkpoint satisfies continuity — this is the boundary, not a defect")

		// And the newer certificate the node has actually seen is not represented anywhere in
		// that file, which is precisely why the file cannot be the authority on how far this
		// node has got.
		require.Greater(t, uc13.InputRecord.RoundNumber, historical.latestUC.InputRecord.RoundNumber,
			"the shard is past the checkpoint, and nothing in the checkpoint can say so")
	})

	t.Run("POSITIVE CONTROL: a gap inside an otherwise quiet run is refused", func(t *testing.T) {
		// Round 12 missing: contiguity fails even though every retained certificate is quiet at S.
		q11 := sign(quiet(11, stateS), 21)
		cp := checkpoint{
			sourceUC: uc10,
			latestUC: uc13,
			evidence: []*types.UnicityCertificate{q11, uc13},
		}
		require.False(t, continuityByEvidence(t, cp, tb, shardConfHash),
			"a missing round is a gap, whatever the retained certificates say")
	})
}

// TestContinuityAlignment covers the two shapes the model has to state separately from the
// "contiguous quiet run" case, both raised in review of the corrected design.
func TestContinuityAlignment(t *testing.T) {
	signer, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	tb := testtrustbase.NewTrustBase(t, signer)
	pdr := &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: 8}

	stateS := bytes.Repeat([]byte{0x51}, 32)
	blockA := bytes.Repeat([]byte{0x0a}, 32)
	before := bytes.Repeat([]byte{0x00}, 32)

	sign := func(ir *types.InputRecord, rootRound uint64) *types.UnicityCertificate {
		t.Helper()
		trHash := bytes.Repeat([]byte{byte(ir.RoundNumber)}, 32)
		uc := testcertificates.CreateUnicityCertificate(t, signer, ir, pdr, rootRound, make([]byte, 32), trHash)
		require.NoError(t, uc.Verify(tb, crypto.SHA256, 8, types.ShardID{}, uc.ShardConfHash))
		return uc
	}

	anchor := sign(&types.InputRecord{Version: 1, RoundNumber: 10, PreviousHash: before,
		Hash: stateS, BlockHash: blockA, SummaryValue: []byte{1}, Timestamp: 1000}, 20)
	shardConfHash := anchor.ShardConfHash

	t.Run("the empty interval is valid: the anchor IS the latest certificate", func(t *testing.T) {
		// A shard that just certified a block and has seen no quiet round since. Ordinary, and the
		// listed conditions would reject it if they assumed at least one continuity certificate.
		cp := checkpoint{sourceUC: anchor, latestUC: anchor, evidence: nil}
		require.True(t, continuityByEvidence(t, cp, tb, shardConfHash))
	})

	t.Run("a reissued source record does not invent a quiet round", func(t *testing.T) {
		repeat := sign(anchor.InputRecord, 21)
		cp := checkpoint{sourceUC: anchor, latestUC: repeat, evidence: nil}
		require.True(t, continuityByEvidence(t, cp, tb, shardConfHash))
	})

	t.Run("empty interval with a non-empty evidence set is malformed", func(t *testing.T) {
		q := sign(&types.InputRecord{Version: 1, RoundNumber: 11, PreviousHash: stateS,
			Hash: stateS, BlockHash: nil, SummaryValue: []byte{1}, Timestamp: 1000}, 21)
		cp := checkpoint{sourceUC: anchor, latestUC: anchor, evidence: []*types.UnicityCertificate{q}}
		require.False(t, continuityByEvidence(t, cp, tb, shardConfHash))
	})

	t.Run("same round but a different certificate is rejected", func(t *testing.T) {
		other := sign(&types.InputRecord{Version: 1, RoundNumber: 10, PreviousHash: before,
			Hash: stateS, BlockHash: bytes.Repeat([]byte{0x0c}, 32), SummaryValue: []byte{1}, Timestamp: 1000}, 20)
		cp := checkpoint{sourceUC: anchor, latestUC: other, evidence: nil}
		require.False(t, continuityByEvidence(t, cp, tb, shardConfHash))
	})

	t.Run("a quiet certificate carrying a block hash cannot exist at all", func(t *testing.T) {
		// Condition 4 states the empty-BlockHash requirement explicitly, and it turns out to be
		// defence in depth rather than the only gate: InputRecord validation, which runs inside
		// UC.Verify, already refuses "state hash didn't change but block hash is not nil". So such
		// a certificate cannot be signed into existence, and condition 1 would exclude it even if
		// condition 4 did not.
		//
		// Both are kept. The restore path must not depend on a rule enforced somewhere else to
		// stay correct, and this test records WHY the clause looks redundant so nobody removes it
		// as dead weight.
		ir := &types.InputRecord{Version: 1, RoundNumber: 11, PreviousHash: stateS,
			Hash: stateS, BlockHash: bytes.Repeat([]byte{0xbb}, 32), SummaryValue: []byte{1}, Timestamp: 1000}
		trHash := bytes.Repeat([]byte{11}, 32)
		uc := testcertificates.CreateUnicityCertificate(t, signer, ir, pdr, 21, make([]byte, 32), trHash)
		err := uc.Verify(tb, crypto.SHA256, 8, types.ShardID{}, uc.ShardConfHash)
		require.ErrorContains(t, err, "state hash didn't change but block hash is not nil",
			"the contradiction is caught during verification, before continuity is ever considered")
	})
}
