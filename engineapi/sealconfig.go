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
	pairConfigWire
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
	c, err := a.readExecutionConfig(ctx, legacy)
	if err != nil {
		return [32]byte{}, err
	}
	return c.Identity()
}

// CheckedExecutionConfigBytes returns the complete versioned archive subject.
// The identity is pinned before the bytes are read and checked again afterward.
func (a *Adapter) CheckedExecutionConfigBytes(ctx context.Context, legacy [32]byte) ([]byte, error) {
	pinned, err := a.CheckedExecutionConfigIdentity(ctx, legacy)
	if err != nil {
		return nil, err
	}
	c, err := a.readExecutionConfig(ctx, legacy)
	if err != nil {
		return nil, err
	}
	b, err := c.Encode()
	if err != nil {
		return nil, err
	}
	id, err := c.Identity()
	if err != nil {
		return nil, err
	}
	if id != pinned {
		return nil, ErrSealConfigIdentity
	}
	return b, nil
}

func (a *Adapter) readExecutionConfig(ctx context.Context, legacy [32]byte) (m2contract.ExecutionConfigV2, error) {
	if a.feeCollector == ([20]byte{}) {
		return m2contract.ExecutionConfigV2{}, ErrUnsetCollector
	}
	var got sealConfigWire
	if err := a.engine.call(ctx, "engine_sealConfigV1", []any{}, &got); err != nil {
		return m2contract.ExecutionConfigV2{}, fmt.Errorf("%w: %v", ErrSealConfigUnavailable, err)
	}
	if got.Version != 1 {
		return m2contract.ExecutionConfigV2{}, ErrSealConfigVersion
	}
	if err := a.pair.checkPins(got.pairConfigWire); err != nil {
		return m2contract.ExecutionConfigV2{}, err
	}
	if !common.IsHexAddress(got.FeeCollector) {
		return m2contract.ExecutionConfigV2{}, ErrSealConfigCollector
	}
	actual := [20]byte(common.HexToAddress(got.FeeCollector))
	if actual == ([20]byte{}) {
		return m2contract.ExecutionConfigV2{}, ErrUnsetCollector
	}
	if actual != a.feeCollector {
		return m2contract.ExecutionConfigV2{}, ErrSealConfigCollector
	}
	c := m2contract.ExecutionConfigV2{LegacyConfigIdentity: legacy, Fee: m2contract.FeeProfile{MaxGas: got.MaxGas, SystemGas: got.SystemGas, BaseFeeFloor: got.BaseFeeFloor, Elasticity: got.Elasticity, ChangeDenominator: got.ChangeDenominator}, Collector: actual}
	if err := c.Validate(); err != nil {
		if errors.Is(err, m2contract.ErrFeeProfile) {
			return m2contract.ExecutionConfigV2{}, fmt.Errorf("%w: %w", ErrSealConfigProfile, err)
		}
		return m2contract.ExecutionConfigV2{}, err
	}
	return c, nil
}
