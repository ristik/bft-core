package b1state

import (
	"crypto/sha256"
	"math"
)

// Profile binds the complete execution envelope. Runtime/compiler hashes and
// RestGas must come from PR3's bounded runtime analysis, never calibration or
// a guessed production budget. Zero pins deliberately fail validation.
type Profile struct {
	Network                   uint16
	RootGenesisID             [32]byte
	ExecutionChainID          uint64
	RuntimeHash, CompilerHash [32]byte
	DeltaEV, DeltaHold        uint64
	// MaxEpochsPerUpdate is B: the most validator-epoch entries one execution block may install, across all update calls. The registry keeps
	// every installed entry forever (no window, no pruning), so this bounds work per block, not history.
	MaxEpochsPerUpdate                             uint64
	SystemGas, ForcedGas, MaxGas, OrdinaryCapacity uint64
	RestGas                                        uint64
	CompanionBytes                                 uint64 // space for Update alongside other admitted fields
	OtherCompanionBytes                            uint64
	// GenesisUCTime is the pinned UC time the registry's records.ucTime holds before any import: the lower bound of every imported
	// record's anchor time. It is part of the profile hash, so a node cannot run with another one.
	GenesisUCTime uint64
	// RecordsCustody is the custody contract the mandatory records hook applies the imported root records to after EIP-4788,
	// HRecords the most records one block's hook applies (briefs/p85-pr1c-control-records.md section 6, step 1) and HookRecordGas the
	// gross gas the profile reserves for applying one record. All three are zero for a chain without custody (no hook), and all three
	// are part of the profile hash.
	RecordsCustody [20]byte
	HRecords       uint32
	HookRecordGas  uint64
	// ElectionContract is the ElectionPolicy module whose elect(origin) the hook calls after the records are applied (step 4), and
	// ElectGas the gross gas the profile reserves for that one call: sized for the profile's worst case on a threshold block, so a
	// call that exceeds it invalidates the block (there is no runtime truncation). Both are zero for a chain without the election hook;
	// when set they are part of the profile hash and the hook needs RecordsCustody. A profile without them hashes exactly as before.
	ElectionContract [20]byte
	ElectGas         uint64
}

// HookReadsGas reserves the gate reads of the records hook: custody.recordCursor, registry.recordCount and recordTargetCount, and
// custody.limits (H must fit its maxBatch) before the call, custody.recordCursor after it. Each is a cold staticcall of a few thousand gas; the figure is a price with a wide margin.
const HookReadsGas uint64 = 150_000

// HookMaxRecords is the most records one hook call may apply: custody's own maxBatch ceiling.
const HookMaxRecords = 32

// HookEnabled reports whether the profile carries the records hook.
func (p Profile) HookEnabled() bool { return p.RecordsCustody != ([20]byte{}) }

// ElectionEnabled reports whether the profile carries the election hook.
func (p Profile) ElectionEnabled() bool { return p.ElectionContract != ([20]byte{}) }

// HookEnvelopeGas is the gross gas the profile reserves for the hooks: the gate reads, HRecords applied records and the election call.
func (p Profile) HookEnvelopeGas() (uint64, error) {
	if !p.HookEnabled() {
		return 0, nil
	}
	if p.HookRecordGas != 0 && uint64(p.HRecords) > (math.MaxUint64-HookReadsGas)/p.HookRecordGas {
		return 0, ErrOverflow
	}
	records := HookReadsGas + uint64(p.HRecords)*p.HookRecordGas
	if p.ElectGas > math.MaxUint64-records {
		return 0, ErrOverflow
	}
	return records + p.ElectGas, nil
}

func (p Profile) validHook() bool {
	if p.ElectionEnabled() != (p.ElectGas != 0) || (p.ElectionEnabled() && !p.HookEnabled()) {
		return false
	}
	if !p.HookEnabled() {
		return p.HRecords == 0 && p.HookRecordGas == 0
	}
	return p.HRecords >= 1 && p.HRecords <= HookMaxRecords && p.HookRecordGas != 0
}

// The root-record import envelope (briefs/p85-pr1c-control-records.md section 6): the largest admission charge (2000 + 16*16384 bytes
// + 1000*32 entries) and a bound on the gross gas of the privileged importRootRecords call for 32 maximal entries. The bound is
// measured against the pinned runtime by ureth (b1_tests::import::the_maximal_import_stays_inside_the_envelope_bound: 11,169,634 gross
// for 32 maximal entries) with the same 3/2 safety factor the registry's own G_rest uses; it is a price, not a proof.
const (
	ImportAdmissionMaxGas uint64 = 2000 + 16*16384 + 1000*32
	ImportExecutionGas    uint64 = 18_000_000
	ImportEnvelopeGas            = ImportAdmissionMaxGas + ImportExecutionGas
)

// MinEpochsPerUpdate is the least B a profile may carry: the acknowledgement block of a supersession installs every epoch the root moved past the
// frozen parent, and the root refuses a longer unacknowledged chain than handoff.MaxSupersessionSpan (=2). package handoff asserts at build time
// that this is not below that span, and the ureth registry carries the same check, so raising the span without B cannot strand an acknowledgement.
const MinEpochsPerUpdate uint64 = 2

// Per-block admission and write work of the permanent registry (briefs/b1-any-age-by-signatures.md section 2). Conservative prices, not runtime
// measurements; the exact system bound and RestGas are frozen with the preload codec.
const (
	// UpdateGasBase is the fixed admission and finalize reservation of a B1 update.
	UpdateGasBase uint64 = 155936
	// EpochGasFixed and EpochGasPerMember price one installed epoch: admission (scan, member debit, authentication) plus the full-entry write
	// (11 + 8N words and the C_e cache word) and the closure of the predecessor and cursor writes. There is no deletion term.
	EpochGasFixed     uint64 = 527344
	EpochGasPerMember uint64 = 177800
)

// Bounds returns B, the companion byte ceiling of an update (4096 + 16384 per entry) and its member/entry-count limit units.
func (p Profile) Bounds() (b, c, t uint64, err error) {
	b = p.MaxEpochsPerUpdate
	if b == 0 || b > (math.MaxUint64-4096)/MaxEntryBytes || b > (math.MaxUint64-32)/266 {
		return 0, 0, 0, ErrOverflow
	}
	return b, 4096 + MaxEntryBytes*b, 32 + 266*b, nil
}

// PerEpochGas is the reservation of one installed entry at the member ceiling.
func PerEpochGas() uint64 { return EpochGasFixed + EpochGasPerMember*MaxMembers }
func (p Profile) RequiredSystemGas() (uint64, error) {
	k, _, _, err := p.Bounds()
	if err != nil {
		return 0, err
	}
	// Admission + per-epoch gross write allowance + the pinned rest bound + the root-record import envelope + the records hook.
	hook, err := p.HookEnvelopeGas()
	if err != nil {
		return 0, err
	}
	if p.RestGas > math.MaxUint64-UpdateGasBase-ImportEnvelopeGas-hook || k > (math.MaxUint64-UpdateGasBase-p.RestGas-ImportEnvelopeGas-hook)/PerEpochGas() {
		return 0, ErrOverflow
	}
	return UpdateGasBase + PerEpochGas()*k + p.RestGas + ImportEnvelopeGas + hook, nil
}
func (p Profile) Validate() error {
	if p.Network == 0 || p.RootGenesisID == ([32]byte{}) || p.ExecutionChainID == 0 || p.RuntimeHash == ([32]byte{}) || p.CompilerHash == ([32]byte{}) || p.RestGas == 0 || p.GenesisUCTime == 0 || !p.validHook() || p.DeltaEV >= p.DeltaHold || p.MaxEpochsPerUpdate < MinEpochsPerUpdate {
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
	// A profile without the election hook hashes exactly as it did before the hook existed; one with it commits three more items.
	items := uint64(35)
	if p.ElectionEnabled() {
		items += 3
	}
	b := array(nil, items)
	b = textValue(b, "UNICITY_B1_PROFILE")
	for _, v := range []uint64{uint64(p.Network), p.MaxEpochsPerUpdate, p.DeltaEV, p.DeltaHold, p.SystemGas, p.ForcedGas, p.MaxGas, p.OrdinaryCapacity, p.RestGas, p.CompanionBytes, p.OtherCompanionBytes, k, c, t, p.GenesisUCTime} {
		b = uintValue(b, v)
	}
	b = bytesValue(b, p.RootGenesisID[:])
	b = uintValue(b, p.ExecutionChainID)
	b = bytesValue(b, p.RecordsCustody[:])
	b = uintValue(b, uint64(p.HRecords))
	b = uintValue(b, p.HookRecordGas)
	if p.ElectionEnabled() {
		b = bytesValue(b, p.ElectionContract[:])
		b = uintValue(b, p.ElectGas)
	}
	for _, h := range [][32]byte{p.RuntimeHash, p.CompilerHash} {
		b = bytesValue(b, h[:])
	}
	for _, v := range []uint64{16, 128, 16384, 16, 262144, 24576, 32768} {
		b = uintValue(b, v)
	}
	b = textValue(b, "scan=2000+16C;members=1000T;UC=60000+16B+16000+6000S+2000N+250P+14700;RSMT=2000+16B+250(1+popcount);I=22100;D=7100")
	b = textValue(b, "P85-import=scan 2000+16C_R;entries 1000N;C_R<=16384;N<=32;outcome=[system,G_pre,1,'',SHA256(rootInput)];G_pre=admit+open+import")
	b = textValue(b, "P85-hook=after EIP-4788: one custody.applyRootRecords(min(H,available)) iff the registry holds more records than custody; reads recordCursor,recordCount,recordTargetCount,limits,recordCursor; G_hooks excluded from the outcome, included in the system total")
	if p.ElectionEnabled() {
		b = textValue(b, "P85-election=after the records hook: one ElectionPolicy.elect(origin) from the system caller, origin = the identity of the block's authenticated root origin, within ElectGas; it never reverts for a chain-state reason (a failed election is a stored NoCandidate); a call that errors, reverts or exhausts ElectGas invalidates the block; activation (step 3) has no module and makes no call")
	}
	b = textValue(b, "registry=2;permanent-entries;append-only;no-window;B=per-block-epochs;origin=separate-from-imported-tip")
	b = textValue(b, "native-body=1,2,3;signing=1,2;quorum=total-(total-1)/3;claims=8;signatures=64/512;shard=33/256;path=32;summary=256;RSMT=4096/256/12392")
	return sha256.Sum256(b), nil
}

// SystemGas charges gross open/finalize usage. Refunds are intentionally absent.
//
// With the root-record import the combined total is G_pre + G_finalize + G_hooks, where G_pre = G_admit + G_open + G_import is the
// figure the outcome commitment carries; finalize and the hooks come after it and are excluded from it.
func SystemGas(budget, admit, open, imp, finalize, hooks uint64) (uint64, error) {
	if admit > budget || open > budget-admit || imp > budget-admit-open || finalize > budget-admit-open-imp || hooks > budget-admit-open-imp-finalize {
		return 0, ErrBudget
	}
	return admit + open + imp + finalize + hooks, nil
}
