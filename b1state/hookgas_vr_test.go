package b1state

import (
	"encoding/json"
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	testVR       = [20]byte{0xff, 19: 0x03}
	testVRCode   = VRBuildPoA.RegistryCodeHash
	testPoACode  = [32]byte{0x52}
	reviewedH32  = VRHookMeasurement{Invariant: VRSingleLiveOutput, H: 32, Registry: testVR, RegistryCodeHash: testVRCode, ModuleCodeHash: testPoACode, Caps: VRCaps, Ceilings: VRLimits, Records: 52_262_738, Boundary: 17_977_590, Elect: 7_981_443, Source: "test"}
	reviewedMixd = []VRCombined{{"mixed-first", 32, 0}, {"mixed-middle", 32, 0}, {"mixed-last", 32, 0}}
)

// astra's three combined fixtures (urethhook r2): a 16-member, 64 KiB switching output, its Ack and 30 ordinary records, the switch at
// the start, middle or end, every callback at its maximum advertised cap. All three reproduced their full-budget state within the
// records-only reservation R32 + B = 70,240,328; their figures here are that reservation (the r2 probe established "succeeds at", not the
// exact threshold), so they must sit at or below M_H. They are permanent acceptance cases of the VR batch check.
func reviewed() VRHookMeasurement {
	m := reviewedH32
	m.Combined = append([]VRCombined(nil), reviewedMixd...)
	for i := range m.Combined {
		m.Combined[i].Reservation = 70_240_328
	}
	return m
}

func vrProfile(h uint32, perRecord, elect uint64) Profile {
	return Profile{RecordsCustody: testVR, ElectionContract: testVR, HRecords: h, HookRecordGas: perRecord, ElectGas: elect}
}

// The reviewed H = 32 pins (astra urethhook r2): M32 = 70,240,328, the allowance ceil(5 M32/4) = 87,800,410, encoded as 2,743,763 per
// record (87,800,416), ElectGas 9,976,804, and a total hook envelope of 97,927,220.
func TestTheVRBatchRuleGivesTheReviewedPins(t *testing.T) {
	m := reviewed()
	mh, err := m.BatchRequirement()
	require.NoError(t, err)
	require.EqualValues(t, 70_240_328, mh)
	allowance, per, err := VRRecordsAllowance(m)
	require.NoError(t, err)
	require.EqualValues(t, 87_800_410, allowance)
	require.EqualValues(t, 2_743_763, per)
	elect, err := PinElectGas(m.Elect)
	require.NoError(t, err)
	require.EqualValues(t, 9_976_804, elect)
	p := vrProfile(32, per, elect)
	require.NoError(t, CheckVRHookGas(p, testVRCode, testPoACode, m))
	env, err := p.HookEnvelopeGas()
	require.NoError(t, err)
	require.EqualValues(t, 97_927_220, env)

	require.ErrorIs(t, CheckVRHookGas(vrProfile(32, per-1, elect), testVRCode, testPoACode, m), ErrVRHookGas, "32 x 2,743,762 = 87,800,384 < 87,800,410")
	require.ErrorIs(t, CheckVRHookGas(vrProfile(32, per, elect-1), testVRCode, testPoACode, m), ErrVRHookGas)
	require.ErrorIs(t, CheckVRHookGas(vrProfile(16, per, elect), testVRCode, testPoACode, m), ErrVRHookGas, "never lower H while keeping the rate")
	require.ErrorIs(t, CheckVRHookGas(vrProfile(32, 17_977_590*5/4+1, elect), testVRCode, testPoACode, func() VRHookMeasurement { m := m; m.H = 31; return m }()), ErrVRHookMeasurement, "the combined fixtures are H-record calls")
}

// The P85 rule would reject the reviewed rate: it prices each record at the worst single record (a switching Boundary of 17,977,590,
// pinned 22,471,988). Its semantics are kept for P85 and simply not applied to a VR profile.
func TestTheP85RuleIsUnchangedAndWouldRefuseTheVREncoding(t *testing.T) {
	p := Profile{RecordsCustody: testVR, HRecords: 32, HookRecordGas: 2_743_763}
	caps := ElectCaps{VMax: 16, LMax: 1, NMax: 16}
	require.ErrorIs(t, CheckHookRecordGas(p, caps, HookMeasurement{V: 16, L: 1, C: 16, Gas: 17_977_590, Kind: "boundary"}), ErrHookGas)
}

// A combined fixture that needs more than R_H + B raises M_H (the genesis rule: rerun the complete path, raise M_H if exceeded).
func TestACombinedFixtureAboveRPlusBRaisesTheRequirement(t *testing.T) {
	m := reviewed()
	m.Combined[1].Reservation = 70_240_329
	mh, err := m.BatchRequirement()
	require.NoError(t, err)
	require.EqualValues(t, 70_240_329, mh)
	allowance, per, err := VRRecordsAllowance(m)
	require.NoError(t, err)
	require.EqualValues(t, 87_800_412, allowance)
	require.EqualValues(t, 2_743_763, per, "87,800,416 still covers it")
	m.Combined[2].Reservation = 70_240_335 // ceil(5*70,240,335/4) = 87,800,419 > 87,800,416
	require.ErrorIs(t, CheckVRHookGas(vrProfile(32, 2_743_763, 9_976_804), testVRCode, testPoACode, m), ErrVRHookGas)
	_, per, err = VRRecordsAllowance(m)
	require.NoError(t, err)
	require.EqualValues(t, 2_743_764, per)
	require.NoError(t, CheckVRHookGas(vrProfile(32, per, 9_976_804), testVRCode, testPoACode, m))
}

// The measurement binds the deployment: the registry the hooks call, its code, the module, VR's caps, the schema ceilings, the
// invariant and the three combined fixtures.
func TestTheVRMeasurementIsBoundToTheDeployment(t *testing.T) {
	p := vrProfile(32, 2_743_763, 9_976_804)
	require.NoError(t, CheckVRHookGas(p, testVRCode, testPoACode, reviewed()))
	require.ErrorIs(t, CheckVRHookGas(p, [32]byte{0x99}, testPoACode, reviewed()), ErrVRHookGas, "other VR code")
	require.ErrorIs(t, CheckVRHookGas(p, testVRCode, [32]byte{0x99}, reviewed()), ErrVRHookGas, "another module")
	other := p
	other.ElectionContract = [20]byte{0xee}
	require.ErrorIs(t, CheckVRHookGas(other, testVRCode, testPoACode, reviewed()), ErrVRHookGas, "election not on VR")
	other = p
	other.ElectionContract, other.ElectGas = [20]byte{}, 0
	require.ErrorIs(t, CheckVRHookGas(other, testVRCode, testPoACode, reviewed()), ErrVRHookGas, "no election hook")
	for name, edit := range map[string]func(*VRHookMeasurement){
		"invariant":        func(m *VRHookMeasurement) { m.Invariant = "multi-output" },
		"H zero":           func(m *VRHookMeasurement) { m.H = 0 },
		"H above 32":       func(m *VRHookMeasurement) { m.H = 33 },
		"caps":             func(m *VRHookMeasurement) { m.Caps.Record = 900_000 },
		"ceilings":         func(m *VRHookMeasurement) { m.Ceilings.BoundPayload = 16 * 1024 },
		"no records":       func(m *VRHookMeasurement) { m.Records = 0 },
		"no boundary":      func(m *VRHookMeasurement) { m.Boundary = 0 },
		"no election":      func(m *VRHookMeasurement) { m.Elect = 0 },
		"no registry":      func(m *VRHookMeasurement) { m.Registry = [20]byte{} },
		"two combined":     func(m *VRHookMeasurement) { m.Combined = m.Combined[:2] },
		"renamed combined": func(m *VRHookMeasurement) { m.Combined[0].Name = "mixed-start" },
		"reordered":        func(m *VRHookMeasurement) { m.Combined[0], m.Combined[2] = m.Combined[2], m.Combined[0] },
		"short combined":   func(m *VRHookMeasurement) { m.Combined[1].Records = 31 },
		"zero combined":    func(m *VRHookMeasurement) { m.Combined[1].Reservation = 0 },
	} {
		m := reviewed()
		edit(&m)
		require.ErrorIs(t, CheckVRHookGas(p, testVRCode, testPoACode, m), ErrVRHookMeasurement, name)
	}
}

func TestTheVRCheckRefusesOverflow(t *testing.T) {
	m := reviewed()
	m.Boundary = math.MaxUint64
	_, err := m.BatchRequirement()
	require.ErrorIs(t, err, ErrOverflow)
	m = reviewed()
	m.Records, m.Boundary = math.MaxUint64-1, 1
	_, _, err = VRRecordsAllowance(m)
	require.ErrorIs(t, err, ErrOverflow, "ceil(5 M/4) overflows")
	require.ErrorIs(t, CheckVRHookGas(vrProfile(32, math.MaxUint64/16, 9_976_804), testVRCode, testPoACode, reviewed()), ErrOverflow, "H x rate overflows")
}

// The genesis re-check: a fresh measurement that needs more than the pins is refused, whatever was recorded.
func TestTheFreshVRMeasurementIsHeldToTheSameRule(t *testing.T) {
	p := vrProfile(32, 2_743_763, 9_976_804)
	rec := reviewed()
	require.NoError(t, CheckVRHookGasFresh(p, testVRCode, testPoACode, rec, rec))
	fresh := reviewed()
	fresh.Records += 6 // M = 70,240,334: ceil(5M/4) = 87,800,418 > 87,800,416
	require.ErrorIs(t, CheckVRHookGasFresh(p, testVRCode, testPoACode, rec, fresh), ErrVRHookGas, "the contracts grew past the margin")
	fresh = reviewed()
	fresh.Elect = 7_981_444
	require.ErrorIs(t, CheckVRHookGasFresh(p, testVRCode, testPoACode, rec, fresh), ErrVRHookGas)
	fresh = reviewed()
	fresh.RegistryCodeHash = [32]byte{0x77}
	require.ErrorIs(t, CheckVRHookGasFresh(p, testVRCode, testPoACode, rec, fresh), ErrVRHookMeasurement, "a fresh measurement of an unreviewed core is refused")
	fresh.RegistryCodeHash = posRegistryCode
	fresh.Caps = VRCapsPos
	require.ErrorIs(t, CheckVRHookGasFresh(p, testVRCode, testPoACode, rec, fresh), ErrVRHookGas, "a fresh measurement of the other reviewed build proves nothing")
}

func TestTheVRMeasurementJSONIsStrict(t *testing.T) {
	m := reviewed()
	b, err := json.Marshal(m)
	require.NoError(t, err)
	var back VRHookMeasurement
	require.NoError(t, json.Unmarshal(b, &back))
	require.Equal(t, m, back)
	var raw map[string]any
	require.NoError(t, json.Unmarshal(b, &raw))
	require.Equal(t, "0xff00000000000000000000000000000000000003", raw["registry"])
	raw["extra"] = 1
	b2, _ := json.Marshal(raw)
	require.ErrorIs(t, json.Unmarshal(b2, &back), ErrVRHookMeasurement)
	delete(raw, "extra")
	raw["registry"] = "0xFF00000000000000000000000000000000000003"
	b2, _ = json.Marshal(raw)
	require.ErrorIs(t, json.Unmarshal(b2, &back), ErrVRHookMeasurement)
}

// ---- the PoS-capable VR build (VT-04b, astra's caps ruling) ----------------------------------------------------------------------------
//
// Caps 5.0 / 1.5 / 2.5 M. H = 16 (at H = 32 the record callbacks alone reach 80 M and the margin takes the batch to 100 M before VR's own
// work). The figures are ureth's complete-path measurement on the PoS-capable build (tests/vr_hook.rs, VR_HOOK_BUILD=pos) over the fixture
// test/vr/fixtures/vr-hook-pos.json: R_16 = 43,320,364 (batch of 16 at the 2.5 M record cap), B = 18,993,473 (the worst switching Boundary),
// E = 9,529,439, so
//
//	M_16 = R_16 + B = 62,313,837, allowance ceil(5 M_16 / 4) = 77,892,297, HookRecordGas ceil(allowance / 16) = 4,868,269 (16 x = 77,892,304),
//	ElectGas ceil(5 E / 4) = 11,911,799, envelope 150,000 + 77,892,304 + 11,911,799 = 89,954,103.
var (
	posRegistryCode = VRBuildPos.RegistryCodeHash
	posModuleCode   = [32]byte{0x61}
)

func reviewedPos() VRHookMeasurement {
	m := VRHookMeasurement{Invariant: VRSingleLiveOutput, H: 16, Registry: testVR, RegistryCodeHash: posRegistryCode, ModuleCodeHash: posModuleCode, Caps: VRCapsPos, Ceilings: VRLimits,
		Records: 43_320_364, Boundary: 18_993_473, Elect: 9_529_439, Source: "test"}
	// the three combined fixtures at their measured reservations (all within R_16 + B)
	m.Combined = []VRCombined{{"mixed-first", 16, 58_720_265}, {"mixed-middle", 16, 58_151_399}, {"mixed-last", 16, 57_636_205}}
	return m
}

func TestThePoSBuildGivesTheDerivedPins(t *testing.T) {
	m := reviewedPos()
	mh, err := m.BatchRequirement()
	require.NoError(t, err)
	require.EqualValues(t, 62_313_837, mh, "R_16 + B; no combined fixture exceeds it")
	allowance, per, err := VRRecordsAllowance(m)
	require.NoError(t, err)
	require.EqualValues(t, 77_892_297, allowance)
	require.EqualValues(t, 4_868_269, per)
	elect, err := PinElectGas(m.Elect)
	require.NoError(t, err)
	require.EqualValues(t, 11_911_799, elect)
	p := vrProfile(16, per, elect)
	require.NoError(t, CheckVRHookGas(p, posRegistryCode, posModuleCode, m))
	env, err := p.HookEnvelopeGas()
	require.NoError(t, err)
	require.EqualValues(t, 89_954_103, env, "below the PoA build's 97,927,220")

	require.ErrorIs(t, CheckVRHookGas(vrProfile(16, per-1, elect), posRegistryCode, posModuleCode, m), ErrVRHookGas, "16 x 4,868,268 = 77,892,288 < 77,892,297")
	require.ErrorIs(t, CheckVRHookGas(vrProfile(16, per, elect-1), posRegistryCode, posModuleCode, m), ErrVRHookGas)
	require.ErrorIs(t, CheckVRHookGas(vrProfile(32, per, elect), posRegistryCode, posModuleCode, m), ErrVRHookGas, "never raise H while keeping the rate")
	require.ErrorIs(t, CheckVRHookGas(vrProfile(8, per, elect), posRegistryCode, posModuleCode, m), ErrVRHookGas, "never lower H while keeping the rate")
	// the measured H must carry the combined fixtures' record count
	bad := m
	bad.H = 32
	require.ErrorIs(t, CheckVRHookGas(vrProfile(32, per, elect), posRegistryCode, posModuleCode, bad), ErrVRHookMeasurement)
}

// A full system derivation at H = 16: SystemGas covers the non-hook work plus the envelope, and the ordinary capacity the profile asks for
// stays whole (MaxGas = SystemGas + ForcedGas + ordinary capacity; RequiredSystemGas adds exactly the hook envelope).
func TestThePoSEnvelopeIsWhatTheSystemGasAdds(t *testing.T) {
	m := reviewedPos()
	_, per, _ := VRRecordsAllowance(m)
	elect, _ := PinElectGas(m.Elect)
	p := Profile{MaxEpochsPerUpdate: 2, RestGas: 1_000_000, RecordsCustody: testVR, ElectionContract: testVR, HRecords: 16, HookRecordGas: per, ElectGas: elect}
	with, err := p.RequiredSystemGas()
	require.NoError(t, err)
	p.RecordsCustody, p.HRecords, p.HookRecordGas, p.ElectionContract, p.ElectGas = [20]byte{}, 0, 0, [20]byte{}, 0
	without, err := p.RequiredSystemGas()
	require.NoError(t, err)
	require.EqualValues(t, 89_954_103, with-without, "SystemGas = non-hook requirement + the hook envelope")
}

// The cap tuple is bound to the build whose code enforces it: the PoS-capable runtime carries the PoS caps and only them, any other runtime
// keeps the PoA mapping (the PoA build and its pins are unchanged).
func TestTheCapTupleIsBoundToTheVRBuild(t *testing.T) {
	require.Len(t, VRBuilds, 2)
	pos, ok := VRBuildFor(posRegistryCode)
	require.True(t, ok)
	require.Equal(t, VRCapsPos, pos.Caps)
	poa, ok := VRBuildFor(testVRCode)
	require.True(t, ok)
	require.Equal(t, VRCaps, poa.Caps)
	require.Equal(t, VRCallbackCaps{Elect: 5_000_000, Output: 1_500_000, Record: 2_500_000, Resolved: 500_000, Attach: 3_000_000, Detach: 500_000, Gov: 1_000_000, Adopt: 1_000_000}, VRCapsPos)
	require.Equal(t, VRCallbackCaps{Elect: 4_000_000, Output: 1_000_000, Record: 1_500_000, Resolved: 500_000, Attach: 3_000_000, Detach: 500_000, Gov: 1_000_000, Adopt: 1_000_000}, VRCaps)
	require.Equal(t, poa.RepairFacet, pos.RepairFacet, "the repair facet is byte-identical across builds")
	require.NotEqual(t, poa.GovernanceFacet, pos.GovernanceFacet)
	require.NotEqual(t, poa.RecordsFacet, pos.RecordsFacet)

	// an unknown core is refused, never defaulted to the PoA caps
	_, ok = VRBuildFor([32]byte{0x51})
	require.False(t, ok)
	m := reviewed()
	m.RegistryCodeHash = [32]byte{0x51}
	require.ErrorIs(t, m.Valid(), ErrVRHookMeasurement)

	m = reviewedPos()
	m.Caps = VRCaps
	require.ErrorIs(t, m.Valid(), ErrVRHookMeasurement, "the PoS runtime measured at the PoA caps")
	m = reviewed()
	m.Caps = VRCapsPos
	require.ErrorIs(t, m.Valid(), ErrVRHookMeasurement, "the PoA runtime measured at the PoS caps")
	m = reviewedPos()
	m.RegistryCodeHash = testVRCode // the PoA core claims the PoS tuple
	require.ErrorIs(t, m.Valid(), ErrVRHookMeasurement)

	// the allocation: the plan selects its build, the facets are the build's, an unknown core or a swapped facet is refused
	require.NoError(t, CheckVRBuildRoles(pos.RegistryCodeHash, pos.GovernanceFacet, pos.RepairFacet, pos.RecordsFacet, true))
	require.NoError(t, CheckVRBuildRoles(poa.RegistryCodeHash, poa.GovernanceFacet, poa.RepairFacet, poa.RecordsFacet, false))
	require.ErrorIs(t, CheckVRBuildRoles(pos.RegistryCodeHash, pos.GovernanceFacet, pos.RepairFacet, pos.RecordsFacet, false), ErrVRHookMeasurement, "a PoA plan on the PoS build")
	require.ErrorIs(t, CheckVRBuildRoles(poa.RegistryCodeHash, poa.GovernanceFacet, poa.RepairFacet, poa.RecordsFacet, true), ErrVRHookMeasurement, "a PoS plan on the PoA build")
	require.ErrorIs(t, CheckVRBuildRoles([32]byte{0x51}, poa.GovernanceFacet, poa.RepairFacet, poa.RecordsFacet, false), ErrVRHookMeasurement)
	require.ErrorIs(t, CheckVRBuildRoles(pos.RegistryCodeHash, poa.GovernanceFacet, pos.RepairFacet, pos.RecordsFacet, true), ErrVRHookMeasurement, "the PoA governance facet under the PoS core")
}

// The PoA pins stay what the reviewed derivation gave (byte for byte): the PoS build adds a mapping, it changes none.
func TestThePoAPinsAreUntouchedByThePoSBuild(t *testing.T) {
	m := reviewed()
	_, per, err := VRRecordsAllowance(m)
	require.NoError(t, err)
	require.EqualValues(t, 2_743_763, per)
	require.NoError(t, CheckVRHookGas(vrProfile(32, per, 9_976_804), testVRCode, testPoACode, m))
}

// RequiredSystemGas and MaxGas never wrap (astra #1217 r1): a hook envelope that is representable but leaves no room for the other terms,
// a rest bound at the edge, and an epoch count whose product overflows are all ErrOverflow; the largest sum that fits is accepted.
func TestSystemGasAndMaxGasAreChecked(t *testing.T) {
	base := Profile{MaxEpochsPerUpdate: 2, RestGas: 1_000_000, RecordsCustody: testVR, HRecords: 1, HookRecordGas: 1}
	_, err := base.RequiredSystemGas()
	require.NoError(t, err)

	big := base
	big.HookRecordGas = math.MaxUint64 // H x rate fits only at H = 1: hook = reads + rate wraps
	_, err = big.RequiredSystemGas()
	require.ErrorIs(t, err, ErrOverflow)

	edge := base
	edge.HookRecordGas = math.MaxUint64 - HookReadsGas - UpdateGasBase // the hook itself fits, the other terms do not
	_, err = edge.RequiredSystemGas()
	require.ErrorIs(t, err, ErrOverflow)

	rest := base
	rest.RestGas = math.MaxUint64 - UpdateGasBase - ImportEnvelopeGas - 1_000
	_, err = rest.RequiredSystemGas()
	require.ErrorIs(t, err, ErrOverflow, "epochs and the hook push it over")

	epochs := base
	epochs.MaxEpochsPerUpdate = math.MaxUint64 / PerEpochGas() * 2
	_, err = epochs.RequiredSystemGas()
	require.Error(t, err)

	g, err := MaxGasFor(116_756_271, 0, 60_000_000)
	require.NoError(t, err)
	require.EqualValues(t, 176_756_271, g)
	g, err = MaxGasFor(math.MaxUint64-5, 0, 5)
	require.NoError(t, err)
	require.EqualValues(t, uint64(math.MaxUint64), g)
	_, err = MaxGasFor(math.MaxUint64-5, 0, 6)
	require.ErrorIs(t, err, ErrOverflow)
	_, err = MaxGasFor(math.MaxUint64, 1, 0)
	require.ErrorIs(t, err, ErrOverflow)
	_, err = MaxGasFor(1, math.MaxUint64, 0)
	require.ErrorIs(t, err, ErrOverflow)
}
