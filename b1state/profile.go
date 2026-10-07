package b1state

import (
	"crypto/sha256"
	"math"
)

// Profile binds the complete execution envelope. Runtime/compiler hashes and
// RestGas must come from PR3's bounded runtime analysis, never calibration or
// a guessed production budget. Zero pins deliberately fail validation.
type Profile struct {
	Network                                        uint16
	RootGenesisID                                  [32]byte
	ExecutionChainID                               uint64
	RuntimeHash, CompilerHash                      [32]byte
	WCert, DeltaEV, DeltaHold                      uint64
	SystemGas, ForcedGas, MaxGas, OrdinaryCapacity uint64
	RestGas                                        uint64
	CompanionBytes                                 uint64 // space for Update alongside other admitted fields
	OtherCompanionBytes                            uint64
}

func (p Profile) Bounds() (k, c, t uint64, err error) {
	if p.WCert == math.MaxUint64 {
		return 0, 0, 0, ErrOverflow
	}
	k = p.WCert + 1
	if k > (math.MaxUint64-4096)/MaxEntryBytes || k > (math.MaxUint64-32)/266 || k > (math.MaxUint64-6)/524 {
		return 0, 0, 0, ErrOverflow
	}
	return k, 4096 + MaxEntryBytes*k, 32 + 266*k, nil
}
func (p Profile) RequiredSystemGas() (uint64, error) {
	k, _, _, err := p.Bounds()
	if err != nil {
		return 0, err
	}
	// Admission + rectangular gross write allowance + the pinned rest bound.
	if p.RestGas > math.MaxUint64-155936 || k > (math.MaxUint64-155936-p.RestGas)/15626944 {
		return 0, ErrOverflow
	}
	return 155936 + 15626944*k + p.RestGas, nil
}
func (p Profile) Validate() error {
	if p.Network == 0 || p.RootGenesisID == ([32]byte{}) || p.ExecutionChainID == 0 || p.RuntimeHash == ([32]byte{}) || p.CompilerHash == ([32]byte{}) || p.RestGas == 0 || p.WCert > p.DeltaEV || p.DeltaEV >= p.DeltaHold {
		return ErrProfile
	}
	_, c, _, err := p.Bounds()
	if err != nil {
		return err
	}
	required, err := p.RequiredSystemGas()
	if err != nil {
		return err
	}
	if p.SystemGas < required || p.OrdinaryCapacity == 0 || p.SystemGas > p.MaxGas || p.ForcedGas > p.MaxGas-p.SystemGas || p.OrdinaryCapacity != p.MaxGas-p.SystemGas-p.ForcedGas {
		return ErrProfile
	}
	if p.OtherCompanionBytes > p.CompanionBytes || c > p.CompanionBytes-p.OtherCompanionBytes {
		return ErrProfile
	}
	return nil
}
func (p Profile) Hash() ([32]byte, error) {
	if err := p.Validate(); err != nil {
		return [32]byte{}, err
	}
	k, c, t, _ := p.Bounds()
	// All frozen bounds and prices are committed, including caller metering and
	// the supported signing and quorum policies, rather than inferred locally.
	b := array(nil, 28)
	b = textValue(b, "UNICITY_B1_PROFILE")
	for _, v := range []uint64{uint64(p.Network), p.WCert, p.DeltaEV, p.DeltaHold, p.SystemGas, p.ForcedGas, p.MaxGas, p.OrdinaryCapacity, p.RestGas, p.CompanionBytes, p.OtherCompanionBytes, k, c, t} {
		b = uintValue(b, v)
	}
	b = bytesValue(b, p.RootGenesisID[:])
	b = uintValue(b, p.ExecutionChainID)
	for _, h := range [][32]byte{p.RuntimeHash, p.CompilerHash} {
		b = bytesValue(b, h[:])
	}
	for _, v := range []uint64{64, 128, 16384, 16, 262144, 24576, 32768} {
		b = uintValue(b, v)
	}
	b = textValue(b, "scan=2000+16C;members=1000T;UC=60000+16B+64000+6000S+2000N+250P+1117700;RSMT=2000+16B+250(1+popcount);I=22100;D=7100")
	b = textValue(b, "native-body=1,2,3;signing=1,2;quorum=total-(total-1)/3;claims=8;signatures=64/512;shard=33/256;path=32;summary=256;RSMT=4096/256/12392")
	return sha256.Sum256(b), nil
}

// SystemGas charges gross open/finalize usage. Refunds are intentionally absent.
func SystemGas(budget, admit, open, finalize uint64) (uint64, error) {
	if admit > budget || open > budget-admit || finalize > budget-admit-open {
		return 0, ErrBudget
	}
	return admit + open + finalize, nil
}
