package engineapi

import (
	"fmt"

	"github.com/unicitynetwork/bft-core/evmroot"
)

// ParentHeader is the subset of the parent block's own header this
// derivation needs. Deliberately narrow: adapter.go is responsible for
// obtaining it (from its own bookkeeping, or an eth_getBlockByHash call —
// an I/O concern, not a derivation-logic one), and DeriveAttributes stays a
// pure function testable with golden vectors and no network.
type ParentHeader struct {
	Timestamp uint64
}

// DeriveAttributes is the one place this adapter turns an authenticated
// canonical root input into Ethereum block-building parameters. It is a pure
// function: same inputs, same outputs, on every validator, which is the entire
// reason followers can independently recompute and verify a leader's proposal
// (see C2.3 in the build plan) instead of trusting it.
//
// It takes the root input rootinput.Derive has already authenticated, not a
// shardnode.RoundParams. v0 keyed prevRandao and parentBeaconBlockRoot off
// RoundParams.SealHash, a value a caller can fabricate and which carries no
// quorum, no inclusion path and no trust base; v1 keys them off the certified
// (RootRound, Round) pair and derives the timestamp from the certified
// ReferenceTime. So the parameters are a function of data this node has
// authenticated rather than of a caller-supplied scalar. F2c §9 and §3; f2d
// §5.1 deletes v0.
//
// There is deliberately no failure mode and no guard. These are total functions
// of two certified integers, which is exactly why authentication cannot live in
// the derivation — rootinput/wiring_contract_test.go's
// TestWiring_TodaysRoundParamsCannotAuthenticate records that, and a guard here
// would contradict it.
func DeriveAttributes(ri evmroot.RootInput, parent ParentHeader) PayloadAttributesV3 {
	return deriveAttributes(ri.Origin.RootRound, ri.Round, ri.Origin.ReferenceTime, parent, [20]byte{})
}

func DeriveAttributesV2(ri evmroot.RootInputV2, parent ParentHeader, feeCollector [20]byte) PayloadAttributesV3 {
	return deriveAttributes(ri.Origin.RootRound, ri.Round, ri.Origin.ReferenceTime, parent, feeCollector)
}

func deriveAttributes(rootRound, round, referenceTime uint64, parent ParentHeader, feeCollector [20]byte) PayloadAttributesV3 {
	prevRandao := evmroot.DerivePrevRandao(rootRound, round)
	beaconRoot := evmroot.DeriveBeaconRoot(rootRound, round)
	ts := evmroot.DeriveTimestamp(referenceTime, parent.Timestamp)

	return PayloadAttributesV3{
		Timestamp:             quantity(ts),
		PrevRandao:            data32(prevRandao),
		SuggestedFeeRecipient: data20(feeCollector),
		Withdrawals:           []WithdrawalV1{},
		ParentBeaconBlockRoot: data32(beaconRoot),
	}
}

// Verify recomputes what the leader's attributes should have been from the
// authenticated root input and reports whether attrs matches — the follower-side
// check C2.3 requires. A leader that altered the timestamp or (if it were ever
// made round-dependent) the fee recipient is caught here, before its block is
// ever executed, not after.
//
// Compared field by field, not with a struct equality check: this is
// exactly the file the build plan singles out as the one whose failure
// message should name the diverging field, not just report "mismatch".
func Verify(ri evmroot.RootInput, parent ParentHeader, attrs PayloadAttributesV3) error {
	want := DeriveAttributes(ri, parent)
	switch {
	case want.Timestamp != attrs.Timestamp:
		return fmt.Errorf("engineapi: round %d timestamp diverges: got %d, want %d", ri.Round, attrs.Timestamp, want.Timestamp)
	case want.PrevRandao != attrs.PrevRandao:
		return fmt.Errorf("engineapi: round %d prevRandao diverges: got %x, want %x", ri.Round, attrs.PrevRandao, want.PrevRandao)
	case want.SuggestedFeeRecipient != attrs.SuggestedFeeRecipient:
		return fmt.Errorf("engineapi: round %d suggestedFeeRecipient diverges: got %x, want %x", ri.Round, attrs.SuggestedFeeRecipient, want.SuggestedFeeRecipient)
	case want.ParentBeaconBlockRoot != attrs.ParentBeaconBlockRoot:
		return fmt.Errorf("engineapi: round %d parentBeaconBlockRoot diverges: got %x, want %x", ri.Round, attrs.ParentBeaconBlockRoot, want.ParentBeaconBlockRoot)
	case len(attrs.Withdrawals) != 0:
		return fmt.Errorf("engineapi: round %d withdrawals must be empty, got %d", ri.Round, len(attrs.Withdrawals))
	}
	return nil
}

// PayloadFields is the subset of PayloadAttributesV3 that is actually
// recoverable from a sealed ExecutionPayloadV3 — everything except
// ParentBeaconBlockRoot, which is a newPayload *parameter*, never a field
// stored on the payload itself (confirmed against the Cancun spec: the
// payload has no such field). VerifyPayloadFields exists because of that
// asymmetry — Verify's full five-field comparison cannot be run against
// values extracted from a received block, only against a genuine
// PayloadAttributesV3 a caller already has in hand.
type PayloadFields struct {
	Timestamp             quantity
	PrevRandao            data32
	SuggestedFeeRecipient data20
	Withdrawals           []WithdrawalV1
}

// VerifyPayloadFields checks the fields a received ExecutionPayloadV3
// actually carries, against the authenticated root input, cheaply and locally.
// It intentionally says nothing about ParentBeaconBlockRoot: that value is
// verified implicitly, by the caller deriving its own copy (DeriveAttributes)
// and supplying it to newPayloadWithSealV1 directly — see Adapter.Verify. A
// leader that built against a different beacon root produces a block reth
// computes a different stateRoot/blockHash for, which newPayloadWithSealV1
// reports as INVALID; there is no separate field to compare it against ahead of
// that call.
func VerifyPayloadFields(ri evmroot.RootInput, parent ParentHeader, claimed PayloadFields) error {
	return verifyPayloadFields(ri.Round, DeriveAttributes(ri, parent), claimed)
}

func VerifyPayloadFieldsV2(ri evmroot.RootInputV2, parent ParentHeader, feeCollector [20]byte, claimed PayloadFields) error {
	return verifyPayloadFields(ri.Round, DeriveAttributesV2(ri, parent, feeCollector), claimed)
}

func verifyPayloadFields(round uint64, want PayloadAttributesV3, claimed PayloadFields) error {
	switch {
	case want.Timestamp != claimed.Timestamp:
		return fmt.Errorf("engineapi: round %d timestamp diverges: got %d, want %d", round, claimed.Timestamp, want.Timestamp)
	case want.PrevRandao != claimed.PrevRandao:
		return fmt.Errorf("engineapi: round %d prevRandao diverges: got %x, want %x", round, claimed.PrevRandao, want.PrevRandao)
	case want.SuggestedFeeRecipient != claimed.SuggestedFeeRecipient:
		return fmt.Errorf("engineapi: round %d suggestedFeeRecipient diverges: got %x, want %x", round, claimed.SuggestedFeeRecipient, want.SuggestedFeeRecipient)
	case len(claimed.Withdrawals) != 0:
		return fmt.Errorf("engineapi: round %d withdrawals must be empty, got %d", round, len(claimed.Withdrawals))
	}
	return nil
}
