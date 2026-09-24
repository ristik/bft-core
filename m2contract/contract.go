// Package m2contract defines inert M2 trust and execution identity contracts.
// Runtime admission and store migration are deliberately separate review work.
package m2contract

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-core/evmroot"
	bfttypes "github.com/unicitynetwork/bft-go-base/types"
)

const ExecutionConfigVersion = 2
const executionDomain = "UNICITY_EXECUTION_CONFIG_V2"
const intervalDomain = "UNICITY_ACTIVATED_TRUST_INTERVAL"
const IntervalVersion = 1

var (
	ErrLegacyConfig             = errors.New("m2contract: missing legacy execution config identity")
	ErrFeeProfile               = errors.New("m2contract: unsupported fee profile")
	ErrAnchor                   = errors.New("m2contract: invalid v1 anchor interval")
	ErrBody                     = errors.New("m2contract: invalid v2 body")
	ErrContext                  = errors.New("m2contract: network context mismatch")
	ErrEpochGap                 = errors.New("m2contract: nonconsecutive epoch")
	ErrPredecessor              = errors.New("m2contract: predecessor mismatch")
	ErrNonUnitWeight            = errors.New("m2contract: non-unit PoA weight")
	ErrActivationBody           = errors.New("m2contract: activation body mismatch")
	ErrMissingCommit            = errors.New("m2contract: missing activation commit ID")
	ErrActivationBeforeEarliest = errors.New("m2contract: activation before earliest bound")
	ErrReordered                = errors.New("m2contract: activated intervals reordered")
	ErrIntervalBounds           = errors.New("m2contract: invalid or noncontiguous interval")
	ErrRoundOutsideHistory      = errors.New("m2contract: round outside authenticated history")
)

// FeeProfile mirrors the five consensus-relevant BlockProfile fields in ureth.
type FeeProfile struct {
	MaxGas, SystemGas, BaseFeeFloor, Elasticity, ChangeDenominator uint64
}

// ExecutionConfigV2 extends the legacy chain/fork configuration identity with
// every fee rule and the exact 20-byte collector configured for execution.
type ExecutionConfigV2 struct {
	LegacyConfigIdentity [32]byte
	Fee                  FeeProfile
	Collector            [20]byte
}

func (c ExecutionConfigV2) Validate() error {
	if c.LegacyConfigIdentity == ([32]byte{}) {
		return ErrLegacyConfig
	}
	f := c.Fee
	if f.MaxGas == 0 || f.SystemGas == 0 || f.SystemGas >= f.MaxGas || f.BaseFeeFloor == 0 || f.BaseFeeFloor > 1<<62 || f.Elasticity != 2 || f.ChangeDenominator == 0 || (f.MaxGas-f.SystemGas)%f.Elasticity != 0 {
		return ErrFeeProfile
	}
	return nil
}

func (c ExecutionConfigV2) Encode() ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return bfttypes.Cbor.Marshal([]any{executionDomain, uint64(ExecutionConfigVersion), c.LegacyConfigIdentity[:], c.Fee.MaxGas, c.Fee.SystemGas, c.Fee.BaseFeeFloor, c.Fee.Elasticity, c.Fee.ChangeDenominator, c.Collector[:]})
}

func (c ExecutionConfigV2) Identity() ([32]byte, error) {
	b, err := c.Encode()
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(b), nil
}

// TrustInterval is [A*, End). End == 0 means an open-ended current interval.
// Only the final interval in a history may be open-ended.
type TrustInterval struct {
	Body       evmroot.TrustBaseBodyV2
	Activation evmroot.ActivatedTrustBase
	End        uint64
}

// Encode freezes the durable activated-interval record. It excludes the body,
// which is identified by BodyIdentity and stored separately. CBOR null marks
// an open-ended current interval; a finite end is an unsigned integer.
func (in TrustInterval) Encode() ([]byte, error) {
	if err := in.validateActivation(); err != nil {
		return nil, err
	}
	var end any
	if in.End != 0 {
		end = in.End
	}
	return bfttypes.Cbor.Marshal([]any{intervalDomain, uint64(IntervalVersion), in.Activation.BodyIdentity, in.Activation.EpochStart, in.Activation.ActivationCommitID, end})
}

func (in TrustInterval) validateActivation() error {
	id := in.Body.Identity()
	if !bytes.Equal(in.Activation.BodyIdentity, id[:]) {
		return ErrActivationBody
	}
	if len(in.Activation.ActivationCommitID) != 32 {
		return ErrMissingCommit
	}
	if in.Activation.EpochStart < in.Body.EarliestActivation {
		return ErrActivationBeforeEarliest
	}
	if in.End != 0 && in.Activation.EpochStart >= in.End {
		return ErrIntervalBounds
	}
	return nil
}

// TrustHistory is a contiguous, single-network lineage from a v1 anchor.
// AnchorStart/AnchorEnd describe the authenticated v1 active interval.
type TrustHistory struct {
	Anchor                 evmroot.V1Anchor
	AnchorStart, AnchorEnd uint64
	Intervals              []TrustInterval
}

func (h TrustHistory) Validate() error {
	if h.Anchor.Version != 1 || len(h.Anchor.HashIncludingSigs) != 32 || h.AnchorStart >= h.AnchorEnd {
		return ErrAnchor
	}
	predecessor, err := evmroot.FirstV2PredecessorHash(h.Anchor)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrAnchor, err)
	}
	priorEpoch, priorEnd := h.Anchor.Epoch, h.AnchorEnd
	for i := 1; i < len(h.Intervals); i++ {
		if h.Intervals[i].Activation.EpochStart < h.Intervals[i-1].Activation.EpochStart {
			return ErrReordered
		}
	}
	for i, in := range h.Intervals {
		b := in.Body
		if err := b.Validate(); err != nil {
			return fmt.Errorf("%w: interval %d: %w", ErrBody, i, err)
		}
		if b.NetworkID != h.Anchor.NetworkID {
			return fmt.Errorf("%w: interval %d", ErrContext, i)
		}
		if b.Epoch != priorEpoch+1 {
			return fmt.Errorf("%w: interval %d", ErrEpochGap, i)
		}
		if !bytes.Equal(b.PredecessorHash, predecessor) {
			return fmt.Errorf("%w: interval %d", ErrPredecessor, i)
		}
		for _, member := range b.Members {
			if member.Weight != 1 {
				return fmt.Errorf("%w: interval %d", ErrNonUnitWeight, i)
			}
		}
		if err := in.validateActivation(); err != nil {
			return fmt.Errorf("interval %d: %w", i, err)
		}
		if in.Activation.EpochStart != priorEnd || (in.End == 0 && i != len(h.Intervals)-1) {
			return fmt.Errorf("%w: interval %d", ErrIntervalBounds, i)
		}
		id := b.Identity()
		predecessor, priorEpoch, priorEnd = id[:], b.Epoch, in.End
	}
	return nil
}

// At requires the complete validated lineage. It never authorizes a round
// from an unvalidated, partial, overlapping, or reordered history.
func (h TrustHistory) At(round uint64) (uint64, error) {
	if err := h.Validate(); err != nil {
		return 0, err
	}
	if round >= h.AnchorStart && round < h.AnchorEnd {
		return h.Anchor.Epoch, nil
	}
	for _, in := range h.Intervals {
		if round >= in.Activation.EpochStart && (in.End == 0 || round < in.End) {
			return in.Body.Epoch, nil
		}
	}
	return 0, ErrRoundOutsideHistory
}
