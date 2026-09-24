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
		return errors.New("m2contract: missing legacy execution config identity")
	}
	f := c.Fee
	if f.MaxGas == 0 || f.SystemGas == 0 || f.SystemGas >= f.MaxGas || f.BaseFeeFloor == 0 || f.BaseFeeFloor > 1<<62 || f.Elasticity != 2 || f.ChangeDenominator == 0 || (f.MaxGas-f.SystemGas)%f.Elasticity != 0 {
		return errors.New("m2contract: unsupported fee profile")
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

// TrustInterval is [Start, End). Start is the authenticated actual activation
// A*, never the body's earliest permissible activation A_min.
type TrustInterval struct {
	Body       evmroot.TrustBaseBodyV2
	Activation evmroot.ActivatedTrustBase
	End        uint64
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
		return errors.New("m2contract: invalid v1 anchor interval")
	}
	predecessor, err := evmroot.FirstV2PredecessorHash(h.Anchor)
	if err != nil {
		return err
	}
	priorEpoch, priorEnd := h.Anchor.Epoch, h.AnchorEnd
	for i, in := range h.Intervals {
		b, a := in.Body, in.Activation
		if err := b.Validate(); err != nil {
			return fmt.Errorf("m2contract: interval %d body: %w", i, err)
		}
		if b.NetworkID != h.Anchor.NetworkID || b.Epoch != priorEpoch+1 || !bytes.Equal(b.PredecessorHash, predecessor) {
			return fmt.Errorf("m2contract: interval %d context or predecessor mismatch", i)
		}
		for _, member := range b.Members {
			if member.Weight != 1 {
				return fmt.Errorf("m2contract: interval %d requires unit weights", i)
			}
		}
		id := b.Identity()
		if !bytes.Equal(a.BodyIdentity, id[:]) || len(a.ActivationCommitID) != 32 || a.EpochStart < b.EarliestActivation || a.EpochStart != priorEnd || a.EpochStart >= in.End {
			return fmt.Errorf("m2contract: interval %d activation or bounds invalid", i)
		}
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
		if round >= in.Activation.EpochStart && round < in.End {
			return in.Body.Epoch, nil
		}
	}
	return 0, errors.New("m2contract: round outside authenticated history")
}
