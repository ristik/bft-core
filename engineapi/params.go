package engineapi

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-core/shardnode"
)

// ParentHeader is the subset of the parent block's own header this
// derivation needs. Deliberately narrow: adapter.go is responsible for
// obtaining it (from its own bookkeeping, or an eth_getBlockByHash call —
// an I/O concern, not a derivation-logic one), and DeriveAttributes stays a
// pure function testable with golden vectors and no network.
type ParentHeader struct {
	Timestamp uint64
}

// domain-separation prefixes for the two SHA256 derivations below. Two
// different one-byte constants so prevRandao and parentBeaconBlockRoot can
// never collide even though they're derived from the same (SealHash, round)
// pair — see docs/adr/0001-executor-boundary.md and the round-params
// derivation table in docs/engine-api-adapter-plan.md §6.
const (
	domainPrevRandao            = 0x01
	domainParentBeaconBlockRoot = 0x02
)

// ErrNoSealHash is returned when RoundParams.SealHash is empty — every
// round after genesis's sync UC must have one; a missing SealHash means the
// framework handed this Executor a RoundParams it should never construct.
var ErrNoSealHash = errors.New("engineapi: RoundParams.SealHash is empty")

// DeriveAttributes is the one place this adapter turns a Unicity Certificate
// into Ethereum block-building parameters. It is a pure function: same
// inputs, same outputs, on every validator, which is the entire reason
// followers can independently recompute and verify a leader's proposal
// (see C2.3 in the build plan) instead of trusting it.
func DeriveAttributes(p shardnode.RoundParams, parent ParentHeader) (PayloadAttributesV3, error) {
	if len(p.SealHash) == 0 {
		return PayloadAttributesV3{}, ErrNoSealHash
	}

	// Root time is seconds; BFT Core rounds run sub-second, so the seal's
	// own timestamp alone can repeat across consecutive rounds — but EVM
	// headers require strictly increasing timestamps. Take whichever is
	// later.
	ts := p.Timestamp
	if parent.Timestamp+1 > ts {
		ts = parent.Timestamp + 1
	}

	prevRandao := domainHash(domainPrevRandao, p.SealHash, p.Round)
	beaconRoot := domainHash(domainParentBeaconBlockRoot, p.SealHash, p.Round)

	return PayloadAttributesV3{
		Timestamp:             quantity(ts),
		PrevRandao:            data32(prevRandao),
		SuggestedFeeRecipient: data20{}, // zero address — see the build plan's derivation table
		Withdrawals:           []WithdrawalV1{},
		ParentBeaconBlockRoot: data32(beaconRoot),
	}, nil
}

// Verify recomputes what the leader's attributes should have been and
// reports whether attrs matches — the follower-side check C2.3 requires. A
// leader that altered the timestamp or (if it were ever made
// round-dependent) the fee recipient is caught here, before its block is
// ever executed, not after.
//
// Compared field by field, not with a struct equality check: this is
// exactly the file the build plan singles out as the one whose failure
// message should name the diverging field, not just report "mismatch".
func Verify(p shardnode.RoundParams, parent ParentHeader, attrs PayloadAttributesV3) error {
	want, err := DeriveAttributes(p, parent)
	if err != nil {
		return err
	}
	switch {
	case want.Timestamp != attrs.Timestamp:
		return fmt.Errorf("engineapi: round %d timestamp diverges: got %d, want %d", p.Round, attrs.Timestamp, want.Timestamp)
	case want.PrevRandao != attrs.PrevRandao:
		return fmt.Errorf("engineapi: round %d prevRandao diverges: got %x, want %x", p.Round, attrs.PrevRandao, want.PrevRandao)
	case want.SuggestedFeeRecipient != attrs.SuggestedFeeRecipient:
		return fmt.Errorf("engineapi: round %d suggestedFeeRecipient diverges: got %x, want %x", p.Round, attrs.SuggestedFeeRecipient, want.SuggestedFeeRecipient)
	case want.ParentBeaconBlockRoot != attrs.ParentBeaconBlockRoot:
		return fmt.Errorf("engineapi: round %d parentBeaconBlockRoot diverges: got %x, want %x", p.Round, attrs.ParentBeaconBlockRoot, want.ParentBeaconBlockRoot)
	case len(attrs.Withdrawals) != 0:
		return fmt.Errorf("engineapi: round %d withdrawals must be empty, got %d", p.Round, len(attrs.Withdrawals))
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
// actually carries, cheaply and locally. It intentionally says nothing
// about ParentBeaconBlockRoot: that value is verified implicitly, by the
// caller deriving its own copy (DeriveAttributes) and supplying it to
// newPayloadV3 directly — see Adapter.Verify. A leader that built against a
// different beacon root produces a block reth computes a different
// stateRoot/blockHash for, which newPayloadV3 reports as INVALID; there is
// no separate field to compare it against ahead of that call.
func VerifyPayloadFields(p shardnode.RoundParams, parent ParentHeader, claimed PayloadFields) error {
	want, err := DeriveAttributes(p, parent)
	if err != nil {
		return err
	}
	switch {
	case want.Timestamp != claimed.Timestamp:
		return fmt.Errorf("engineapi: round %d timestamp diverges: got %d, want %d", p.Round, claimed.Timestamp, want.Timestamp)
	case want.PrevRandao != claimed.PrevRandao:
		return fmt.Errorf("engineapi: round %d prevRandao diverges: got %x, want %x", p.Round, claimed.PrevRandao, want.PrevRandao)
	case want.SuggestedFeeRecipient != claimed.SuggestedFeeRecipient:
		return fmt.Errorf("engineapi: round %d suggestedFeeRecipient diverges: got %x, want %x", p.Round, claimed.SuggestedFeeRecipient, want.SuggestedFeeRecipient)
	case len(claimed.Withdrawals) != 0:
		return fmt.Errorf("engineapi: round %d withdrawals must be empty, got %d", p.Round, len(claimed.Withdrawals))
	}
	return nil
}

func domainHash(prefix byte, sealHash shardnode.Hash, round uint64) [32]byte {
	h := sha256.New()
	h.Write([]byte{prefix})
	h.Write(sealHash)
	var roundBuf [8]byte
	binary.BigEndian.PutUint64(roundBuf[:], round)
	h.Write(roundBuf[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}
