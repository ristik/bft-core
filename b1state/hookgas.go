package b1state

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
)

// The records hook's per-record reservation is not a hand-typed number either. The largest record the hook applies is the RecoveryAck that
// also applies a pending closure (it derives K, an exposure per incumbent member, and closes J): its cost grows with the committee (nMax members
// of lMax lots), so a reservation that covers a small committee does not cover the committee the caps admit, and a block whose hook cannot apply
// its record within the reservation is invalid (the shard halts: P85 contracts#32). The reservation is therefore checked against a COLD
// measurement of the worst committee the deployment's caps admit (unicity-pos-contracts `script/measure-hook-gas.sh V L C`), with the margin
// the election's price carries, at profile generation (`b1-profile --hook-measurement`) and again against a fresh measurement
// (`check-hook-gas`).

var (
	// ErrHookMeasurement reports a measurement that cannot be a worst-case record of a profile.
	ErrHookMeasurement = errors.New("b1state: invalid hook-gas measurement")
	// ErrHookGas reports a pinned HookRecordGas below the measured worst case with the margin.
	ErrHookGas = errors.New("b1state: the per-record hook gas does not cover the measured worst case")
)

// HookMeasurement is the largest COLD gas of one applied record (ack, the staging of J's closure, the closure of an Active J, the RecoveryAck
// with a pending closure) for the worst committee of the caps: V identities, committees of C members of L lots each. Kind names the record it is.
type HookMeasurement struct {
	V    uint32 `json:"v"`
	L    uint32 `json:"l"`
	C    uint32 `json:"c"`
	Gas  uint64 `json:"gas"`
	Kind string `json:"kind"`
}

// Valid checks the measurement is within the profile ceilings the measurement script accepts.
func (m HookMeasurement) Valid() error {
	if (ElectMeasurement{V: m.V, L: m.L, C: m.C, Gas: m.Gas}).Valid() != nil || m.Kind == "" {
		return ErrHookMeasurement
	}
	return nil
}

// AtCaps reports whether the measurement was taken at exactly the deployment's caps.
func (m HookMeasurement) AtCaps(c ElectCaps) bool {
	return ElectMeasurement{V: m.V, L: m.L, C: m.C}.AtCaps(c)
}

// MinHookRecordGas is the lowest per-record reservation a measurement admits: the measured worst case plus a quarter, rounded up (the
// election's margin).
func MinHookRecordGas(m HookMeasurement) (uint64, error) {
	if err := m.Valid(); err != nil {
		return 0, err
	}
	return PinElectGas(m.Gas)
}

// CheckHookRecordGas is the profile check: the measurement is valid and taken at exactly the deployed caps, and the profile's per-record
// reservation is at least the measured worst case with the margin.
func CheckHookRecordGas(p Profile, caps ElectCaps, m HookMeasurement) error {
	if !p.HookEnabled() {
		return ErrHookGas
	}
	if err := caps.Valid(); err != nil {
		return err
	}
	min, err := MinHookRecordGas(m)
	if err != nil {
		return err
	}
	if !m.AtCaps(caps) {
		return errors.Join(ErrHookGas, errors.New("the measurement is not at the deployed caps (vMax, lMax, nMax)"))
	}
	if p.HookRecordGas < min {
		return errors.Join(ErrHookGas, errors.New("the reservation is below the measured worst case with the margin"))
	}
	return nil
}

// CheckHookGas is the genesis re-check: the recorded measurement passes CheckHookRecordGas, and so does a fresh measurement of the same caps.
// A fresh measurement of other caps proves nothing about the deployed contracts and is refused.
func CheckHookGas(p Profile, caps ElectCaps, recorded, fresh HookMeasurement) error {
	if err := CheckHookRecordGas(p, caps, recorded); err != nil {
		return err
	}
	return CheckHookRecordGas(p, caps, fresh)
}

// ---- the ValidatorRegistry (VR) records batch (VT-14, ristik/bft-core#1158) -------------------------------------------------------------
//
// A VR generation pins its hooks differently. CheckHookRecordGas above prices one P85 record and multiplies it by H; for VR that rule is
// wrong in both directions (astra, urethhook r2, briefs/astra-review-urethhook-r2-answer.md): the worst record (a switching Boundary of
// 17,977,590 at VR's caps) times 32 overprices the batch fivefold, while the ordinary records' module allowance is a batch property that a
// per-record figure does not bound. The VR rule is a FIXED allowance for one records call of H records:
//
//	M_H = max(R_H + B, every combined fixture)      R_H: the full H-record delivery at VR's maximum callback caps
//	                                                B:   the complete worst switching Boundary (adoption, detach, attach, 16 installed)
//	H * HookRecordGas >= ceil(5 * M_H / 4)          HookRecordGas is the amortized encoding of the allowance, never a per-record price
//	ElectGas          >= ceil(5 * E / 4)            E:   the maximum compound election
//
// It rests on VR's single-live-output invariant: one records call finalizes at most one nonterminal output and switches the pointer at
// most once, and the (at most two) onRecords segments of a switch sum to at most H records. The measurement names that invariant, the
// code it was taken at (VR's runtime hash, which covers its three facets through immutables, and the active module's), VR's callback caps
// and the schema ceilings; a measurement of other code, caps or ceilings proves nothing about the deployment and is refused. A protocol
// that permits more than one live output must replace this rule and remeasure.

// VRSingleLiveOutput names the invariant the VR batch rule rests on (schema v1: at most one live output, marked outputs included).
const VRSingleLiveOutput = "vr-v1-single-live-output"

// VRCallbackCaps are VR's immutable per-call caps (unicity-pos-contracts src/vr/VRShared.sol CAP_*): a module's caps are min(its
// gasBounds, these), so a measurement at these caps covers every module VR can activate.
type VRCallbackCaps struct {
	Elect    uint64 `json:"elect"`
	Output   uint64 `json:"output"`
	Record   uint64 `json:"record"`
	Resolved uint64 `json:"resolved"`
	Attach   uint64 `json:"attach"`
	Detach   uint64 `json:"detach"`
	Gov      uint64 `json:"gov"`
	Adopt    uint64 `json:"adopt"`
}

// VRCaps are the caps of the VR v1 bytecode (the PoA build).
var VRCaps = VRCallbackCaps{Elect: 4_000_000, Output: 1_000_000, Record: 1_500_000, Resolved: 500_000, Attach: 3_000_000, Detach: 500_000, Gov: 1_000_000, Adopt: 1_000_000}

// VRCapsPos are the caps of the PoS-capable VR build (unicity-pos-contracts src/vr/pos/build/VRSharedPos.sol, generated by
// script/gen-vr-pos-build.py; VT-04, astra's caps ruling): CAP_ELECT 5.0 M, CAP_OUTPUT 1.5 M and CAP_RECORD 2.5 M per record.
var VRCapsPos = VRCallbackCaps{Elect: 5_000_000, Output: 1_500_000, Record: 2_500_000, Resolved: 500_000, Attach: 3_000_000, Detach: 500_000, Gov: 1_000_000, Adopt: 1_000_000}

// VRCapsPos16 raises the election stipend for the compact-custody generation.
var VRCapsPos16 = VRCallbackCaps{Elect: 7_000_000, Output: 1_500_000, Record: 2_500_000, Resolved: 500_000, Attach: 3_000_000, Detach: 500_000, Gov: 1_000_000, Adopt: 1_000_000}

// VRBuild binds a cap tuple to the code that enforces it: the compile-time constants of a VR build live in its core and its three facets, so a
// tuple is only meaningful for exactly those runtimes (astra's ruling, item 3; #1217 r1 item 4). The hashes are the runtimes at the genesis
// addresses 0xff..03 to 0xff..06 (the VR hook fixtures of unicity-pos-contracts, test/vr/fixtures/vr-hook*.json).
type VRBuild struct {
	Name             string
	Caps             VRCallbackCaps
	RegistryCodeHash [32]byte
	GovernanceFacet  [32]byte
	RepairFacet      [32]byte
	RecordsFacet     [32]byte
}

// The recognized builds. A VR core that is in neither is refused: the caps are compile-time constants of the core and facets, and an
// agreement among a PDR, an allocation and a measurement identifies the deployed bytes without establishing their callback ceilings.
var (
	VRBuildPoA = VRBuild{
		Name: "poa", Caps: VRCaps,
		RegistryCodeHash: mustHash32("3abfd37f4f7c1f3e7af8b0a449a4c0b509ec49a1bfdfb7e669855f9c557c7b39"),
		GovernanceFacet:  mustHash32("9bab91fbab48ab8099d5992975bbc613f2e685f249907d09181b9d5986270db1"),
		RepairFacet:      mustHash32("f6ca6bba00e97a6736334b0c3f77bb4515ab7a816cb93a5995964e261d532418"),
		RecordsFacet:     mustHash32("b4a2d13c53a52d0b0a994ff414528442e21718cff1c1278008ad53bb9b07c1aa"),
	}
	VRBuildPos = VRBuild{
		Name: "pos", Caps: VRCapsPos,
		RegistryCodeHash: mustHash32("b0c89f13324f81cf743578ac2180661d9fbd69f1f291d19fd3967b4f8adfd4f8"),
		GovernanceFacet:  mustHash32("43e7dedbae009bbb1caa1dc58e191877e35869e72f4fc80d73e85e086e7728b7"),
		RepairFacet:      mustHash32("f6ca6bba00e97a6736334b0c3f77bb4515ab7a816cb93a5995964e261d532418"),
		RecordsFacet:     mustHash32("46a2a1b9f58fe9955ddc9bf6cfa20612dd5ba566ab91c527a33a083fb0d04743"),
	}
	VRBuildPos16 = VRBuild{
		Name: "pos16", Caps: VRCapsPos16,
		RegistryCodeHash: mustHash32("e1a8cc6bae5801ef7b2d9f87154fbe65094a428961cf1e082134dd12ec78f39a"),
		GovernanceFacet:  mustHash32("a9479510a1a78aff1c589fbe6b6c95904e61609d27debab1c4966e65e58069f9"),
		RepairFacet:      mustHash32("f6ca6bba00e97a6736334b0c3f77bb4515ab7a816cb93a5995964e261d532418"),
		RecordsFacet:     mustHash32("d5cef299a9c6f678b8a992710a4942077fd3f0c6de9598278e258e75e1b90362"),
	}
	// VRBuilds enumerates every recognized build.
	VRBuilds = []VRBuild{VRBuildPoA, VRBuildPos, VRBuildPos16}
)

func mustHash32(s string) (h [32]byte) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		panic("b1state: bad pinned hash " + s)
	}
	copy(h[:], b)
	return h
}

// VRBuildFor is the reviewed build whose core runtime this is; ok is false for any other core (never a default).
func VRBuildFor(registryCodeHash [32]byte) (VRBuild, bool) {
	for _, b := range VRBuilds {
		if b.RegistryCodeHash == registryCodeHash {
			return b, true
		}
	}
	return VRBuild{}, false
}

// CheckVRBuildRoles is the allocation check: the three facets are exactly the reviewed build's, and the build is the one the plan selects
// (pos true for a PoS-prototype plan).
func CheckVRBuildRoles(registryCodeHash, governance, repair, records [32]byte, pos bool) error {
	b, ok := VRBuildFor(registryCodeHash)
	if !ok {
		return errors.Join(ErrVRHookMeasurement, errors.New("the VR core is not a reviewed build"))
	}
	if (b.Name == VRBuildPos.Name || b.Name == VRBuildPos16.Name) != pos {
		return errors.Join(ErrVRHookMeasurement, fmt.Errorf("the plan is %s but the allocated VR core is the %s build", map[bool]string{true: "a PoS plan", false: "a PoA plan"}[pos], b.Name))
	}
	if governance != b.GovernanceFacet || repair != b.RepairFacet || records != b.RecordsFacet {
		return errors.Join(ErrVRHookMeasurement, fmt.Errorf("the allocated facets are not the %s build's", b.Name))
	}
	return nil
}

// VRCeilings are the legal bounds the worst cases were built at (schema v1 section 1; design section 3.5.4 and 10).
type VRCeilings struct {
	Committee      uint32 `json:"committee"`      // installed and captured members
	BoundChanges   uint32 `json:"boundChanges"`   // changes bound to one output
	BoundPayload   uint32 `json:"boundPayload"`   // their payload bytes
	ChangePayload  uint32 `json:"changePayload"`  // one change's payload bytes (a SetModule's initData lives in it)
	PendingChanges uint32 `json:"pendingChanges"` // changes pending at once
	Activations    uint32 `json:"activations"`    // the activation table
}

// VRLimits are the ceilings of schema v1.
var VRLimits = VRCeilings{Committee: 16, BoundChanges: 16, BoundPayload: 64 * 1024, ChangePayload: 16 * 1024, PendingChanges: 32, Activations: 64}

// VRCombined is one combined fixture: a switching Boundary and ordinary records in one H-record call (astra's three: the switch at the
// start, middle or end of 30 ordinary records), with the smallest records reservation at which the hook still lands on the reference state.
type VRCombined struct {
	Name        string `json:"name"`
	Records     uint32 `json:"records"`
	Reservation uint64 `json:"reservation"`
}

// VRHookMeasurement is the complete-path measurement of a VR generation's hooks: every figure is the smallest RESERVATION at which the
// hook still reproduces the reference state (below it a contained step is BudgetShort or VR runs out of gas), not the gas spent. It is
// taken by ureth's real block path over VR bytecode (ureth crates/unicity/execution/tests/vr_hook.rs, VR_HOOK_MEASUREMENT).
type VRHookMeasurement struct {
	Invariant        string         `json:"invariant"`
	H                uint32         `json:"h"`
	Registry         [20]byte       `json:"-"`
	RegistryCodeHash [32]byte       `json:"-"`
	ModuleCodeHash   [32]byte       `json:"-"`
	Caps             VRCallbackCaps `json:"caps"`
	Ceilings         VRCeilings     `json:"ceilings"`
	Records          uint64         `json:"records"`  // R_H
	Boundary         uint64         `json:"boundary"` // B
	Combined         []VRCombined   `json:"combined"`
	Elect            uint64         `json:"elect"` // E
	Source           string         `json:"source"`
}

var (
	// ErrVRHookMeasurement reports a measurement that is not a complete VR batch measurement of the deployment.
	ErrVRHookMeasurement = errors.New("b1state: invalid VR hook measurement")
	// ErrVRHookGas reports a VR profile whose fixed records allowance or election price does not cover the measurement with the margin.
	ErrVRHookGas = errors.New("b1state: the VR hook envelope does not cover the measured complete path")
)

// VRCombinedFixtures are the combined fixtures every VR measurement must carry (permanent acceptance cases; astra urethhook r2).
var VRCombinedFixtures = []string{"mixed-first", "mixed-middle", "mixed-last"}

// Valid checks the measurement is complete and taken at VR v1's caps, ceilings and invariant.
func (m VRHookMeasurement) Valid() error {
	switch {
	case m.Invariant != VRSingleLiveOutput:
		return errors.Join(ErrVRHookMeasurement, errors.New("not measured under the single-live-output invariant"))
	case m.H < 1 || m.H > HookMaxRecords:
		return errors.Join(ErrVRHookMeasurement, errors.New("H outside 1..32"))
	case m.Registry == ([20]byte{}) || m.RegistryCodeHash == ([32]byte{}) || m.ModuleCodeHash == ([32]byte{}):
		return errors.Join(ErrVRHookMeasurement, errors.New("no registry, registry code hash or module code hash"))
	case !m.knownBuild():
		return errors.Join(ErrVRHookMeasurement, errors.New("the measured VR core is not a reviewed build"))
	case m.Caps != mustBuild(m.RegistryCodeHash).Caps:
		return errors.Join(ErrVRHookMeasurement, errors.New("not measured at the callback caps of the VR build whose runtime it names"))
	case m.Ceilings != VRLimits:
		return errors.Join(ErrVRHookMeasurement, errors.New("not measured at the schema ceilings"))
	case m.Records == 0 || m.Boundary == 0 || m.Elect == 0:
		return errors.Join(ErrVRHookMeasurement, errors.New("a zero requirement"))
	}
	if len(m.Combined) != len(VRCombinedFixtures) {
		return errors.Join(ErrVRHookMeasurement, errors.New("the combined fixtures are not exactly "+strings.Join(VRCombinedFixtures, ", ")))
	}
	for i, c := range m.Combined {
		if c.Name != VRCombinedFixtures[i] || c.Records != m.H || c.Reservation == 0 {
			return errors.Join(ErrVRHookMeasurement, fmt.Errorf("combined fixture %d is not %s over H records with a reservation", i, VRCombinedFixtures[i]))
		}
	}
	return nil
}

// BatchRequirement is M_H: R_H + B, raised to any combined fixture that needs more.
func (m VRHookMeasurement) BatchRequirement() (uint64, error) {
	if err := m.Valid(); err != nil {
		return 0, err
	}
	if m.Boundary > math.MaxUint64-m.Records {
		return 0, ErrOverflow
	}
	mh := m.Records + m.Boundary
	for _, c := range m.Combined {
		mh = max(mh, c.Reservation)
	}
	return mh, nil
}

// VRRecordsAllowance is the fixed records allowance a measurement requires, ceil(5*M_H/4), and the smallest HookRecordGas that encodes
// it at H, ceil(allowance/H).
func VRRecordsAllowance(m VRHookMeasurement) (allowance, perRecord uint64, err error) {
	mh, err := m.BatchRequirement()
	if err != nil {
		return 0, 0, err
	}
	if allowance, err = PinElectGas(mh); err != nil {
		return 0, 0, err
	}
	h := uint64(m.H)
	return allowance, allowance/h + min(allowance%h, 1), nil
}

// CheckVRHookGas is the VR profile check: both hooks are on VR at the measured address, H is the measured H, the measurement is of the
// pinned VR code and the module the generation activates, H*HookRecordGas covers ceil(5*M_H/4) (checked without overflow), and
// ElectGas covers ceil(5*E/4). The P85 per-record rule (CheckHookRecordGas) is not applied to a VR profile and stays unchanged for P85.
func CheckVRHookGas(p Profile, registryCodeHash, moduleCodeHash [32]byte, m VRHookMeasurement) error {
	allowance, _, err := VRRecordsAllowance(m)
	if err != nil {
		return err
	}
	switch {
	case !p.HookEnabled() || !p.ElectionEnabled():
		return errors.Join(ErrVRHookGas, errors.New("a VR profile carries both hooks"))
	case p.RecordsCustody != m.Registry || p.ElectionContract != m.Registry:
		return errors.Join(ErrVRHookGas, errors.New("the hooks are not on the measured registry"))
	case p.HRecords != m.H:
		return errors.Join(ErrVRHookGas, fmt.Errorf("the profile's H %d is not the measured H %d (never lower H while keeping the rate)", p.HRecords, m.H))
	case registryCodeHash != m.RegistryCodeHash:
		return errors.Join(ErrVRHookGas, errors.New("the measurement is of other VR code than the generation pins"))
	case moduleCodeHash != m.ModuleCodeHash:
		return errors.Join(ErrVRHookGas, errors.New("the measurement is of another module than the generation activates"))
	case p.HookRecordGas == 0 || uint64(p.HRecords) > math.MaxUint64/p.HookRecordGas:
		return ErrOverflow
	case uint64(p.HRecords)*p.HookRecordGas < allowance:
		return errors.Join(ErrVRHookGas, fmt.Errorf("H x HookRecordGas = %d is below ceil(5 x M_H / 4) = %d", uint64(p.HRecords)*p.HookRecordGas, allowance))
	}
	elect, err := PinElectGas(m.Elect)
	if err != nil {
		return err
	}
	if p.ElectGas < elect {
		return errors.Join(ErrVRHookGas, fmt.Errorf("ElectGas %d is below ceil(5 x E / 4) = %d", p.ElectGas, elect))
	}
	return nil
}

// CheckVRHookGasFresh is the genesis re-check: the recorded measurement passes CheckVRHookGas, and so does a fresh complete-path
// measurement of the same code at the final addresses. A fresh measurement that needs more than the recorded one fails here; the remedy
// is to record the fresh one (raising M_H) and derive the profile again, never to keep the old pins.
func CheckVRHookGasFresh(p Profile, registryCodeHash, moduleCodeHash [32]byte, recorded, fresh VRHookMeasurement) error {
	if err := CheckVRHookGas(p, registryCodeHash, moduleCodeHash, recorded); err != nil {
		return err
	}
	return CheckVRHookGas(p, registryCodeHash, moduleCodeHash, fresh)
}

type vrHookMeasurementWire struct {
	Invariant        string         `json:"invariant"`
	H                uint32         `json:"h"`
	Registry         string         `json:"registry"`
	RegistryCodeHash string         `json:"registryCodeHash"`
	ModuleCodeHash   string         `json:"moduleCodeHash"`
	Caps             VRCallbackCaps `json:"caps"`
	Ceilings         VRCeilings     `json:"ceilings"`
	Records          uint64         `json:"records"`
	Boundary         uint64         `json:"boundary"`
	Combined         []VRCombined   `json:"combined"`
	Elect            uint64         `json:"elect"`
	Source           string         `json:"source"`
}

// MarshalJSON writes the addresses and hashes as lowercase 0x-prefixed hex.
func (m VRHookMeasurement) MarshalJSON() ([]byte, error) {
	return json.Marshal(vrHookMeasurementWire{
		Invariant: m.Invariant, H: m.H, Registry: "0x" + hex.EncodeToString(m.Registry[:]),
		RegistryCodeHash: "0x" + hex.EncodeToString(m.RegistryCodeHash[:]), ModuleCodeHash: "0x" + hex.EncodeToString(m.ModuleCodeHash[:]),
		Caps: m.Caps, Ceilings: m.Ceilings, Records: m.Records, Boundary: m.Boundary, Combined: m.Combined, Elect: m.Elect, Source: m.Source,
	})
}

// UnmarshalJSON reads exactly the fields MarshalJSON writes: unknown fields and non-canonical hex are refused.
func (m *VRHookMeasurement) UnmarshalJSON(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var w vrHookMeasurementWire
	if err := dec.Decode(&w); err != nil {
		return errors.Join(ErrVRHookMeasurement, err)
	}
	out := VRHookMeasurement{Invariant: w.Invariant, H: w.H, Caps: w.Caps, Ceilings: w.Ceilings, Records: w.Records, Boundary: w.Boundary,
		Combined: w.Combined, Elect: w.Elect, Source: w.Source}
	for _, f := range []struct {
		s   string
		out []byte
	}{{w.Registry, out.Registry[:]}, {w.RegistryCodeHash, out.RegistryCodeHash[:]}, {w.ModuleCodeHash, out.ModuleCodeHash[:]}} {
		if len(f.s) != 2+2*len(f.out) || f.s[:2] != "0x" || strings.ToLower(f.s) != f.s {
			return errors.Join(ErrVRHookMeasurement, fmt.Errorf("%q is not lowercase 0x-prefixed hex of %d bytes", f.s, len(f.out)))
		}
		if _, err := hex.Decode(f.out, []byte(f.s[2:])); err != nil {
			return errors.Join(ErrVRHookMeasurement, err)
		}
	}
	*m = out
	return nil
}

func (m VRHookMeasurement) knownBuild() bool {
	_, ok := VRBuildFor(m.RegistryCodeHash)
	return ok
}

func mustBuild(h [32]byte) VRBuild {
	b, _ := VRBuildFor(h)
	return b
}
