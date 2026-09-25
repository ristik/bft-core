package engineapi

import (
	"context"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/unicitynetwork/bft-core/m2contract"
)

var (
	ErrSealConfigUnavailable = errors.New("engineapi: checked companion seal configuration unavailable")
	ErrSealConfigVersion     = errors.New("engineapi: unsupported companion seal configuration version")
	ErrSealConfigCollector   = errors.New("engineapi: companion fee collector mismatch")
	ErrUnsetCollector        = errors.New("engineapi: fee collector is unset")
	ErrSealConfigProfile     = errors.New("engineapi: companion fee profile invalid")
	ErrSealConfigIdentity    = errors.New("engineapi: companion execution identity changed")
)

// sealConfigWire is returned by ureth from the same node-owned configuration
// its payload builder and importer use. It is read on the JWT Engine endpoint.
type sealConfigWire struct {
	Version           uint64 `json:"version"`
	MaxGas            uint64 `json:"maxGas"`
	SystemGas         uint64 `json:"systemGas"`
	BaseFeeFloor      uint64 `json:"baseFeeFloor"`
	Elasticity        uint64 `json:"elasticity"`
	ChangeDenominator uint64 `json:"changeDenominator"`
	FeeCollector      string `json:"feeCollector"`
}

// CheckedExecutionConfigIdentity binds the checked companion settings to the
// legacy chain/fork identity and pins them for this adapter. Every later Engine
// call rechecks the pin before proceeding, including after an HTTP reconnect.
// The configured collector must match; no local fee-profile copy is consulted.
func (a *Adapter) CheckedExecutionConfigIdentity(ctx context.Context, legacy [32]byte) ([32]byte, error) {
	id, err := a.readExecutionConfigIdentity(ctx, legacy)
	if err != nil {
		return [32]byte{}, err
	}
	a.sealPinMu.Lock()
	defer a.sealPinMu.Unlock()
	if a.sealPinned {
		if id != a.sealID {
			return [32]byte{}, ErrSealConfigIdentity
		}
		return id, nil
	}
	a.sealID = id
	a.sealPinned = true
	a.engine.setBeforeCall(func(ctx context.Context) error {
		current, err := a.readExecutionConfigIdentity(ctx, legacy)
		if err != nil {
			return err
		}
		if current != id {
			return ErrSealConfigIdentity
		}
		return nil
	})
	return id, nil
}

func (a *Adapter) readExecutionConfigIdentity(ctx context.Context, legacy [32]byte) ([32]byte, error) {
	if a.feeCollector == ([20]byte{}) {
		return [32]byte{}, ErrUnsetCollector
	}
	var got sealConfigWire
	if err := a.engine.call(ctx, "engine_sealConfigV1", []any{}, &got); err != nil {
		return [32]byte{}, fmt.Errorf("%w: %v", ErrSealConfigUnavailable, err)
	}
	if got.Version != 1 {
		return [32]byte{}, ErrSealConfigVersion
	}
	if !common.IsHexAddress(got.FeeCollector) {
		return [32]byte{}, ErrSealConfigCollector
	}
	actual := [20]byte(common.HexToAddress(got.FeeCollector))
	if actual == ([20]byte{}) {
		return [32]byte{}, ErrUnsetCollector
	}
	if actual != a.feeCollector {
		return [32]byte{}, ErrSealConfigCollector
	}
	c := m2contract.ExecutionConfigV2{LegacyConfigIdentity: legacy, Fee: m2contract.FeeProfile{MaxGas: got.MaxGas, SystemGas: got.SystemGas, BaseFeeFloor: got.BaseFeeFloor, Elasticity: got.Elasticity, ChangeDenominator: got.ChangeDenominator}, Collector: actual}
	id, err := c.Identity()
	if err != nil {
		if errors.Is(err, m2contract.ErrFeeProfile) {
			return [32]byte{}, fmt.Errorf("%w: %w", ErrSealConfigProfile, err)
		}
		return [32]byte{}, err
	}
	return id, nil
}
