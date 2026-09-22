package engineapi

// W5: F2c §10's remaining activation negatives, submitted at the adapter level — through
// Adapter.Build and Adapter.Verify, the call sites §10 calls "integration". Negatives 2, 4 and 4b
// are already submitted at the rootinput level in rootinput/wiring_contract_test.go; these make the
// adapter-level claim, which is stronger for 2 (the fabricable scalar no longer reaches the output,
// and the governing input cannot be forged) and is the realizable-consensus claim for 4 and 4b (two
// nodes over one fixture, given one block, reach opposite verdicts).
//
// Tests only: no production file changes with this unit.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/rootinput"
	"github.com/unicitynetwork/bft-core/shardnode"
)

// --- Negative 2 ---------------------------------------------------------------
//
// F2c §10.2: a fabricated RoundParams is structurally indistinguishable from a genuine one. After
// W4 the adapter reads neither p.SealHash nor p.Timestamp, so the adapter-level claim splits in two:
// the scalars a caller can fabricate must not reach the output, and the input that does govern —
// the certified authorization — must not be forgeable.

// TestAdapter_Build_FabricableScalarsDoNotReachTheOutput is §10.2's first half. Two RoundParams
// differing only in SealHash and Timestamp, both carrying the same genuine certificate and record,
// must drive Build to the same prevRandao, parentBeaconBlockRoot, timestamp and extraData
// commitment. v0 keyed the first two off SealHash and the timestamp off params.Timestamp and so
// would have produced two different blocks from these; v1 reads none of them. The assertions are on
// what Build actually sent to forkchoiceUpdatedWithSealV1, not on a locally recomputed copy.
func TestAdapter_Build_FabricableScalarsDoNotReachTheOutput(t *testing.T) {
	h := newSealHarness(t, CursorNotActivated(), samplePayload(), *sampleCompanion())
	defer h.close()
	ctx := context.Background()

	first := h.params
	second := h.params
	second.SealHash = shardnode.Hash(fixedHashBytes(0x11))
	second.Timestamp = first.Timestamp + 4242
	require.NotEqual(t, first.SealHash, second.SealHash, "premise: the fabricable scalars differ")
	require.NotEqual(t, first.Timestamp, second.Timestamp)

	_, err := h.adapter.Build(ctx, first)
	require.NoError(t, err)
	firstAttrs, firstInput := h.capture.attrs, h.capture.input

	_, err = h.adapter.Build(ctx, second)
	require.NoError(t, err)
	secondAttrs, secondInput := h.capture.attrs, h.capture.input
	require.Equal(t, 2, h.capture.calls, "both builds reached the seal sibling")

	require.Equal(t, firstAttrs.PrevRandao, secondAttrs.PrevRandao)
	require.Equal(t, firstAttrs.ParentBeaconBlockRoot, secondAttrs.ParentBeaconBlockRoot)
	require.Equal(t, firstAttrs.Timestamp, secondAttrs.Timestamp)
	require.Equal(t, firstAttrs.Commitment, secondAttrs.Commitment, "the extraData commitment the header must carry")
	require.Equal(t, firstInput.RootInput, secondInput.RootInput, "the canonical rootInput sent as sealBuildInput")
}

// TestAdapter_Build_RefusesACertificateTheTrustBaseDidNotSign is §10.2's second half: the value
// that does govern cannot be fabricated. A certificate carrying fewer than quorum signatures is
// refused by Build as a named rootinput class, not as an opaque failure.
func TestAdapter_Build_RefusesACertificateTheTrustBaseDidNotSign(t *testing.T) {
	f := newDerivationFixture(t)
	// One signature from a four-node trust base whose quorum is three: authentic-looking, and not a
	// verdict this trust base ever produced.
	forged, forgedTR := f.certWithPDR(t, f.pdr, 4, 5, 50, 1)
	a := NewAdapter(Config{
		EngineURL: "http://127.0.0.1:1", EthURL: "http://127.0.0.1:1", Secret: Secret{},
		Verifier: f.verifier(CursorNotActivated()),
	}, nil)

	_, err := a.Build(context.Background(), shardnode.RoundParams{
		Round: 5, Parent: shardnode.BlockRef{Hash: f.parent},
		AuthorizingCertificate: forged, AuthorizingTechnicalRecord: forgedTR,
	})
	require.ErrorIs(t, err, rootinput.ErrUnauthenticated,
		"an unauthenticated certificate must arrive as its own rootinput class")
}

// --- Negative 4 ---------------------------------------------------------------

// TestAdapter_Verify_ObservedMaximumRootRoundRefusesAGoodBlock is §10.4 at the adapter level: a GOOD
// block wrongly refused by substituting the highest observed root round for the committed cursor.
// The realizable history is committed cursor at 40, the block-bound authorization at 50, and a valid
// repeat at 60 observed but not applied. The symptom is a liveness failure and disagreement between
// honest nodes, which is why the test ends on the two nodes' opposite verdicts for one block.
//
// 4b below exercises the same comparison in the opposite direction; it is a separate test because
// what it claims is different (a refusal removed, a safety failure), not because the constant is
// smaller.
func TestAdapter_Verify_ObservedMaximumRootRoundRefusesAGoodBlock(t *testing.T) {
	ctx := context.Background()

	committed := newCompanionHarness(t, CommittedCursor(40))
	defer committed.close()
	// A second verifier context over the SAME fixture, pinning the highest observed root round (60)
	// instead of the committed one (40). It ignores its own fixture and takes committed.f's trust, so
	// both nodes authenticate against one trust base and differ only in the cursor.
	observed := newCompanionHarnessWithVerifier(t, func(*derivationFixture) *VerifierContext {
		return committed.f.verifier(CommittedCursor(60))
	})
	defer observed.close()

	bound, boundTR := committed.f.cert(t, 4, 5, 50) // the authorization the block binds
	repeat, _ := committed.f.cert(t, 4, 5, 60)      // observed, never applied
	require.EqualValues(t, 60, repeat.UnicitySeal.RootChainRoundNumber)
	require.Equal(t, bound.InputRecord.Hash, repeat.InputRecord.Hash, "a repeat certifies the same work")

	parent := shardnode.BlockRef{Number: 4, Hash: shardnode.Hash(fixedHashBytes(0x01))}
	params := paramsFor(parent, bound, boundTR)
	envelope, _ := companionEnvelope(t, committed.f, params, bound, boundTR)
	block := blockFromEnvelope(t, envelope)

	statusCommitted, err := committed.adapter.Verify(ctx, block, params)
	require.NoError(t, err)
	require.Equal(t, shardnode.StatusValid, statusCommitted,
		"a node at committed cursor 40 accepts the block bound at root round 50")
	require.Equal(t, 1, committed.sealCalls, "the accepted block reaches newPayloadWithSealV1")

	statusObserved, err := observed.adapter.Verify(ctx, block, params)
	require.ErrorIs(t, err, rootinput.ErrNotPinned,
		"substituting the observed maximum refuses the same good block as a named rootinput class")
	require.Equal(t, shardnode.StatusInvalid, statusObserved)
	require.Zero(t, observed.sealCalls, "the wrongly-refused block never reaches execution")

	// The consensus problem: one fixture, one block, opposite verdicts, decided only by which
	// quantity each node pinned.
	require.NotEqual(t, statusCommitted, statusObserved)
}

// --- Negative 4b --------------------------------------------------------------

// TestAdapter_Verify_ArbitraryLowCursorRemovesARefusal is §10.4b at the adapter level: committed
// state has moved past a binding and refuses it, and a lower cursor makes that refusal disappear.
// The bug it guards against is a node accepting a binding its committed state already moved past,
// and its symptom is a safety failure — the opposite direction from 4's liveness failure.
func TestAdapter_Verify_ArbitraryLowCursorRemovesARefusal(t *testing.T) {
	ctx := context.Background()

	committed := newCompanionHarness(t, CommittedCursor(60))
	defer committed.close()
	// The same fixture, with an arbitrarily low cursor. It ignores its own fixture and takes
	// committed.f's trust.
	low := newCompanionHarnessWithVerifier(t, func(*derivationFixture) *VerifierContext {
		return committed.f.verifier(CommittedCursor(40))
	})
	defer low.close()

	bound, boundTR := committed.f.cert(t, 4, 5, 50) // the binding committed state has moved past
	parent := shardnode.BlockRef{Number: 4, Hash: shardnode.Hash(fixedHashBytes(0x01))}
	params := paramsFor(parent, bound, boundTR)
	envelope, _ := companionEnvelope(t, committed.f, params, bound, boundTR)
	block := blockFromEnvelope(t, envelope)

	statusCommitted, err := committed.adapter.Verify(ctx, block, params)
	require.ErrorIs(t, err, rootinput.ErrNotPinned, "committed cursor 60 refuses the binding at 50")
	require.Equal(t, shardnode.StatusInvalid, statusCommitted)
	require.Zero(t, committed.sealCalls, "committed state does not execute what it has moved past")

	statusLow, err := low.adapter.Verify(ctx, block, params)
	require.NoError(t, err)
	require.Equal(t, shardnode.StatusValid, statusLow,
		"the low cursor makes that refusal disappear and the binding is accepted")
	require.Equal(t, 1, low.sealCalls, "and it reaches newPayloadWithSealV1")
}
