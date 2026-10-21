package cmd

// B1 activation of a paired deployment (docs/design B1 PR4, DN-B): the single fresh-genesis profile that enables the B1 registry layout,
// the pair-side Update admission and the ureth bindings. One profile file is the source of all three: `ubft engine-api b1-profile` derives
// it from the root trust base and the shard configuration, `engine-api genesis --b1-profile` allocates the registry from it, and
// `shard-node run --b1-profile` admits Updates under it. Nothing here is a second source of authority: the profile is checked against the
// trust base's own history and against the registry words the paired client proves.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	libp2ppeer "github.com/libp2p/go-libp2p/core/peer"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/spf13/cobra"
	"github.com/unicitynetwork/bft-core/b1paired"
	"github.com/unicitynetwork/bft-core/b1registry"
	"github.com/unicitynetwork/bft-core/b1state"
	"github.com/unicitynetwork/bft-core/bridgeprofile"
	"github.com/unicitynetwork/bft-core/q3active"
	"github.com/unicitynetwork/bft-core/q3format"
	"github.com/unicitynetwork/bft-core/recordsfeed"
	"github.com/unicitynetwork/bft-core/registrygenesis"
	"github.com/unicitynetwork/bft-core/registryproof"
	"github.com/unicitynetwork/bft-core/registrywitness"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/zkverifier"
	"github.com/unicitynetwork/bft-go-base/types"
)

// b1RegistryLayout is the layout selector of a B1 deployment: the one fresh-genesis registry (registryproof.FreshB1).
const b1RegistryLayout = registryproof.FreshB1

var (
	// ErrB1Profile is returned for a profile file that does not describe this deployment's trust base, shard configuration or pinned registry.
	ErrB1Profile = errors.New("b1 profile does not describe this deployment")
	// ErrB1Proof is returned when the paired client's proof response is not the one asked for.
	ErrB1Proof = errors.New("b1 registry proof response does not match the request")
)

// b1ProfileFile is the JSON form of b1state.Profile: hashes are 0x-prefixed hex, never arrays of numbers.
type b1ProfileFile struct {
	Network             uint16      `json:"network"`
	RootGenesisID       common.Hash `json:"rootGenesisId"`
	ExecutionChainID    uint64      `json:"executionChainId"`
	RuntimeHash         common.Hash `json:"runtimeHash"`
	CompilerHash        common.Hash `json:"compilerHash"`
	MaxEpochsPerUpdate  uint64      `json:"maxEpochsPerUpdate"`
	DeltaEV             uint64      `json:"deltaEv"`
	DeltaHold           uint64      `json:"deltaHold"`
	SystemGas           uint64      `json:"systemGas"`
	ForcedGas           uint64      `json:"forcedGas"`
	MaxGas              uint64      `json:"maxGas"`
	OrdinaryCapacity    uint64      `json:"ordinaryCapacity"`
	RestGas             uint64      `json:"restGas"`
	CompanionBytes      uint64      `json:"companionBytes"`
	OtherCompanionBytes uint64      `json:"otherCompanionBytes"`
	GenesisUCTime       uint64      `json:"genesisUcTime"`

	// The mandatory hooks (all omitted for a chain without custody). ElectGas is never typed in: it is the pinned margin over
	// ElectMeasurement, which the file records beside it (b1state.ElectGasFor); readB1Profile refuses a price that is not exactly that.
	RecordsCustody   *common.Address           `json:"recordsCustody,omitempty"`
	HRecords         uint32                    `json:"hRecords,omitempty"`
	HookRecordGas    uint64                    `json:"hookRecordGas,omitempty"`
	ElectionContract *common.Address           `json:"electionContract,omitempty"`
	ElectGas         uint64                    `json:"electGas,omitempty"`
	ElectMeasurement *b1state.ElectMeasurement `json:"electMeasurement,omitempty"`
	// ElectCaps are the deployed contracts' ceilings (manifest limits.vMax / limits.lMax, election nMax) the measurement is taken at.
	ElectCaps *b1state.ElectCaps `json:"electCaps,omitempty"`
	// HookMeasurement is the largest cold per-record gas measured at HookCaps (b1state.HookMeasurement); HookRecordGas is refused below it with the margin.
	HookMeasurement *b1state.HookMeasurement `json:"hookMeasurement,omitempty"`
	// HookCaps are the deployed contracts' ceilings the hook measurement is taken at (the same values as ElectCaps when the election is pinned too).
	HookCaps *b1state.ElectCaps `json:"hookCaps,omitempty"`
}

func (f b1ProfileFile) profile() b1state.Profile {
	return b1state.Profile{
		Network: f.Network, RootGenesisID: [32]byte(f.RootGenesisID), ExecutionChainID: f.ExecutionChainID,
		RuntimeHash: [32]byte(f.RuntimeHash), CompilerHash: [32]byte(f.CompilerHash),
		MaxEpochsPerUpdate: f.MaxEpochsPerUpdate, DeltaEV: f.DeltaEV, DeltaHold: f.DeltaHold,
		SystemGas: f.SystemGas, ForcedGas: f.ForcedGas, MaxGas: f.MaxGas, OrdinaryCapacity: f.OrdinaryCapacity,
		RestGas: f.RestGas, CompanionBytes: f.CompanionBytes, OtherCompanionBytes: f.OtherCompanionBytes, GenesisUCTime: f.GenesisUCTime,
		RecordsCustody: addressOrZero(f.RecordsCustody), HRecords: f.HRecords, HookRecordGas: f.HookRecordGas,
		ElectionContract: addressOrZero(f.ElectionContract), ElectGas: f.ElectGas,
	}
}

func addressOrZero(a *common.Address) (out [20]byte) {
	if a != nil {
		out = *a
	}
	return out
}

func addressPtr(a [20]byte) *common.Address {
	if a == ([20]byte{}) {
		return nil
	}
	x := common.Address(a)
	return &x
}

func b1ProfileFileOf(p b1state.Profile) b1ProfileFile {
	return b1ProfileFile{
		RecordsCustody: addressPtr(p.RecordsCustody), HRecords: p.HRecords, HookRecordGas: p.HookRecordGas,
		ElectionContract: addressPtr(p.ElectionContract), ElectGas: p.ElectGas,
		Network: p.Network, RootGenesisID: common.Hash(p.RootGenesisID), ExecutionChainID: p.ExecutionChainID,
		RuntimeHash: common.Hash(p.RuntimeHash), CompilerHash: common.Hash(p.CompilerHash),
		MaxEpochsPerUpdate: p.MaxEpochsPerUpdate, DeltaEV: p.DeltaEV, DeltaHold: p.DeltaHold,
		SystemGas: p.SystemGas, ForcedGas: p.ForcedGas, MaxGas: p.MaxGas, OrdinaryCapacity: p.OrdinaryCapacity,
		RestGas: p.RestGas, CompanionBytes: p.CompanionBytes, OtherCompanionBytes: p.OtherCompanionBytes, GenesisUCTime: p.GenesisUCTime,
	}
}

// readB1Profile reads a profile file strictly (unknown fields are refused) and validates it against the pinned registry.
func readB1Profile(path string) (b1state.Profile, error) {
	p, _, err := readB1ProfileFile(path)
	return p, err
}

// readB1ProfileFile is readB1Profile that also returns the decoded file (the recorded measurement and caps).
func readB1ProfileFile(path string) (b1state.Profile, b1ProfileFile, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- operator-supplied config path, same trust level as --shard-conf
	if err != nil {
		return b1state.Profile{}, b1ProfileFile{}, fmt.Errorf("reading the b1 profile %q: %w", path, err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var f b1ProfileFile
	if err := dec.Decode(&f); err != nil {
		return b1state.Profile{}, b1ProfileFile{}, fmt.Errorf("decoding the b1 profile %q: %w", path, err)
	}
	if dec.More() {
		return b1state.Profile{}, b1ProfileFile{}, fmt.Errorf("decoding the b1 profile %q: trailing data", path)
	}
	p := f.profile()
	if err := checkRecordedElectGas(f); err != nil {
		return b1state.Profile{}, b1ProfileFile{}, fmt.Errorf("%w: %v", ErrB1Profile, err)
	}
	if err := checkRecordedHookGas(f, p); err != nil {
		return b1state.Profile{}, b1ProfileFile{}, fmt.Errorf("%w: %v", ErrB1Profile, err)
	}
	if err := b1registry.ValidateProfile(p); err != nil {
		return b1state.Profile{}, b1ProfileFile{}, fmt.Errorf("%w: %v", ErrB1Profile, err)
	}
	return p, f, nil
}

// checkRecordedElectGas refuses an election price that is not exactly the recorded measurement pinned with the margin, and a recorded
// measurement without an election hook to price: the price is derived from a measurement, never a hand-typed constant.
func checkRecordedElectGas(f b1ProfileFile) error {
	if f.ElectionContract == nil {
		if f.ElectGas != 0 || f.ElectMeasurement != nil || f.ElectCaps != nil {
			return errors.New("an election price, measurement or caps without an election contract")
		}
		return nil
	}
	if f.ElectMeasurement == nil {
		return errors.New("the election price has no recorded measurement (it is derived, never typed)")
	}
	if f.ElectCaps == nil {
		return errors.New("the election price has no recorded deployment caps (vMax, lMax, nMax)")
	}
	if err := f.ElectCaps.Valid(); err != nil {
		return fmt.Errorf("the recorded election caps: %w", err)
	}
	if !f.ElectMeasurement.AtCaps(*f.ElectCaps) {
		return fmt.Errorf("the recorded measurement (V=%d L=%d C=%d) is not at the deployed caps (vMax=%d lMax=%d nMax=%d)",
			f.ElectMeasurement.V, f.ElectMeasurement.L, f.ElectMeasurement.C, f.ElectCaps.VMax, f.ElectCaps.LMax, f.ElectCaps.NMax)
	}
	want, err := b1state.ElectGasFor(*f.ElectMeasurement)
	if err != nil {
		return fmt.Errorf("the recorded election measurement: %w", err)
	}
	if f.ElectGas != want {
		return fmt.Errorf("the election price %d is not the recorded measurement %d pinned with the margin (%d)", f.ElectGas, f.ElectMeasurement.Gas, want)
	}
	return nil
}

// checkRecordedHookGas refuses a records hook whose per-record reservation is not covered by the recorded cold measurement of the worst committee the
// deployment's caps admit (with the margin), a hook without such a measurement, and a measurement without a hook.
func checkRecordedHookGas(f b1ProfileFile, p b1state.Profile) error {
	if f.RecordsCustody == nil {
		if f.HookMeasurement != nil || f.HookCaps != nil {
			return errors.New("a hook measurement or caps without a records hook")
		}
		return nil
	}
	if f.HookMeasurement == nil || f.HookCaps == nil {
		return errors.New("the records hook has no recorded cold measurement of its worst record or no deployment caps (--hook-measurement)")
	}
	if err := b1state.CheckHookRecordGas(p, *f.HookCaps, *f.HookMeasurement); err != nil {
		return fmt.Errorf("hookRecordGas %d against the measured %s record %d at V=%d L=%d C=%d: %w", p.HookRecordGas, f.HookMeasurement.Kind,
			f.HookMeasurement.Gas, f.HookMeasurement.V, f.HookMeasurement.L, f.HookMeasurement.C, err)
	}
	return nil
}

// bindB1Profile checks that the profile is this deployment's: the root history, network and chain it names are the trust base's and the
// shard configuration's. It returns the verified history the registry genesis and the Update admission are derived from.
func bindB1Profile(p b1state.Profile, tb *types.RootTrustBaseV1, conf *types.PartitionDescriptionRecord) (*q3format.History, error) {
	h, err := q3format.NewHistory(tb)
	if err != nil {
		return nil, fmt.Errorf("%w: the root trust base has no verifiable history: %v", ErrB1Profile, err)
	}
	if h.Genesis() != p.RootGenesisID || h.Network() != uint64(p.Network) || uint64(conf.NetworkID) != uint64(p.Network) {
		return nil, fmt.Errorf("%w: root genesis %x / network %d against the trust base (%x / %d) and the shard configuration's network %d",
			ErrB1Profile, p.RootGenesisID, p.Network, h.Genesis(), h.Network(), conf.NetworkID)
	}
	chainID, ok := zkverifier.ParseChainIDFromParams(conf.PartitionParams)
	if !ok || chainID != p.ExecutionChainID {
		return nil, fmt.Errorf("%w: execution chain %d against the shard configuration's chain_id (%d, present=%v)", ErrB1Profile, p.ExecutionChainID, chainID, ok)
	}
	return h, nil
}

// deriveB1Profile builds the profile of this deployment with the oracle's frozen envelope for the certificate window.
func deriveB1Profile(tb *types.RootTrustBaseV1, conf *types.PartitionDescriptionRecord, maxEpochs, deltaEV, deltaHold, ordinaryCapacity, genesisUCTime uint64, hooks ...b1Hooks) (b1state.Profile, error) {
	h, err := q3format.NewHistory(tb)
	if err != nil {
		return b1state.Profile{}, fmt.Errorf("the root trust base has no verifiable history: %w", err)
	}
	chainID, ok := zkverifier.ParseChainIDFromParams(conf.PartitionParams)
	if !ok {
		return b1state.Profile{}, fmt.Errorf("shard conf has no chain_id partition param")
	}
	p := b1state.Profile{
		Network: uint16(conf.NetworkID), RootGenesisID: h.Genesis(), ExecutionChainID: chainID,
		RuntimeHash: [32]byte(common.HexToHash(b1registry.CodeHashHex)), CompilerHash: b1registry.CompilerHash(),
		MaxEpochsPerUpdate: maxEpochs, DeltaEV: deltaEV, DeltaHold: deltaHold,
		RestGas: b1registry.MinRestGas(maxEpochs), CompanionBytes: 1 << 20, OtherCompanionBytes: 65536, OrdinaryCapacity: ordinaryCapacity, GenesisUCTime: genesisUCTime,
	}
	for _, h := range hooks {
		p.RecordsCustody, p.HRecords, p.HookRecordGas = h.RecordsCustody, h.HRecords, h.HookRecordGas
		if p.HookEnabled() {
			if h.HookMeasurement == nil || h.HookCaps == nil {
				return b1state.Profile{}, errors.New("the records hook needs the cold measurement of its worst record (--hook-measurement) and the deployment caps (--elect-caps)")
			}
			if err := b1state.CheckHookRecordGas(p, *h.HookCaps, *h.HookMeasurement); err != nil {
				min, _ := b1state.MinHookRecordGas(*h.HookMeasurement)
				return b1state.Profile{}, fmt.Errorf("--hook-record-gas %d: the measured cold %s record at V=%d L=%d C=%d is %d; the reservation needs at least %d (x1.25): %w",
					p.HookRecordGas, h.HookMeasurement.Kind, h.HookMeasurement.V, h.HookMeasurement.L, h.HookMeasurement.C, h.HookMeasurement.Gas, min, err)
			}
		}
		p.ElectionContract = h.ElectionContract
		if p.ElectionContract != ([20]byte{}) {
			if h.Measurement == nil {
				return b1state.Profile{}, errors.New("the election hook needs a worst-case measurement (--elect-measurement): its price is derived, never typed")
			}
			if p.ElectGas, err = b1state.ElectGasFor(*h.Measurement); err != nil {
				return b1state.Profile{}, err
			}
		}
	}
	if p.SystemGas, err = p.RequiredSystemGas(); err != nil {
		return b1state.Profile{}, err
	}
	p.MaxGas = p.SystemGas + p.OrdinaryCapacity
	if err := b1registry.ValidateProfile(p); err != nil {
		return b1state.Profile{}, err
	}
	return p, nil
}

// b1Hooks are the mandatory-hook pins of a derived profile.
type b1Hooks struct {
	RecordsCustody   [20]byte
	HRecords         uint32
	HookRecordGas    uint64
	ElectionContract [20]byte
	Measurement      *b1state.ElectMeasurement
	Caps             *b1state.ElectCaps
	HookMeasurement  *b1state.HookMeasurement
	HookCaps         *b1state.ElectCaps
}

// readElectMeasurement reads a measurement file strictly.
func readElectMeasurement(path string) (b1state.ElectMeasurement, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- operator-supplied config path
	if err != nil {
		return b1state.ElectMeasurement{}, fmt.Errorf("reading the election measurement %q: %w", path, err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var m b1state.ElectMeasurement
	if err := dec.Decode(&m); err != nil || dec.More() {
		return b1state.ElectMeasurement{}, fmt.Errorf("decoding the election measurement %q: %v", path, err)
	}
	if err := m.Valid(); err != nil {
		return b1state.ElectMeasurement{}, fmt.Errorf("%q: %w", path, err)
	}
	return m, nil
}

// parseElectCaps reads "vMax,lMax,nMax".
func parseElectCaps(s string) (b1state.ElectCaps, error) {
	var c b1state.ElectCaps
	parts := strings.Split(s, ",")
	if len(parts) != 3 {
		return c, fmt.Errorf("--elect-caps %q: want vMax,lMax,nMax", s)
	}
	var v [3]uint32
	for i, p := range parts {
		n, err := strconv.ParseUint(strings.TrimSpace(p), 10, 32)
		if err != nil {
			return c, fmt.Errorf("--elect-caps %q: %w", s, err)
		}
		v[i] = uint32(n)
	}
	c = b1state.ElectCaps{VMax: v[0], LMax: v[1], NMax: v[2]}
	return c, c.Valid()
}

func parseB1Hooks(custody string, h uint32, recordGas uint64, election, measurement, caps, hookMeasurement string) (b1Hooks, error) {
	var out b1Hooks
	if custody == "" {
		if h != 0 || recordGas != 0 || election != "" || measurement != "" || caps != "" || hookMeasurement != "" {
			return out, errors.New("hook pins without --records-custody")
		}
		return out, nil
	}
	if !common.IsHexAddress(custody) {
		return out, fmt.Errorf("--records-custody %q is not an address", custody)
	}
	out.RecordsCustody, out.HRecords, out.HookRecordGas = common.HexToAddress(custody), h, recordGas
	// The records hook's reservation is checked against the cold measurement of its worst record at the deployment's caps, whatever else is pinned.
	if hookMeasurement == "" || caps == "" {
		return out, errors.New("--records-custody needs --hook-measurement (script/measure-hook-gas.sh at the deployment's caps) and --elect-caps (vMax,lMax,nMax)")
	}
	hc, err := parseElectCaps(caps)
	if err != nil {
		return out, err
	}
	hm, err := readHookMeasurement(hookMeasurement)
	if err != nil {
		return out, err
	}
	if !hm.AtCaps(hc) {
		return out, fmt.Errorf("the hook measurement (V=%d L=%d C=%d) is not at the deployed caps (vMax=%d lMax=%d nMax=%d): measure at the caps the manifest is set to",
			hm.V, hm.L, hm.C, hc.VMax, hc.LMax, hc.NMax)
	}
	out.HookMeasurement, out.HookCaps = &hm, &hc
	switch {
	case election == "" && measurement == "":
		// no election: --elect-caps still names the deployment's caps for the records hook's measurement
	case election == "" || measurement == "":
		return out, errors.New("--election and --elect-measurement go together (and need --elect-caps)")
	case !common.IsHexAddress(election):
		return out, fmt.Errorf("--election %q is not an address", election)
	default:
		m, err := readElectMeasurement(measurement)
		if err != nil {
			return out, err
		}
		c, err := parseElectCaps(caps)
		if err != nil {
			return out, err
		}
		if !m.AtCaps(c) {
			return out, fmt.Errorf("the measurement (V=%d L=%d C=%d) is not at the deployed caps (vMax=%d lMax=%d nMax=%d): measure at the caps the manifest is set to",
				m.V, m.L, m.C, c.VMax, c.LMax, c.NMax)
		}
		out.ElectionContract, out.Measurement, out.Caps = common.HexToAddress(election), &m, &c
	}
	return out, nil
}

// readHookMeasurement reads the JSON lines of unicity-pos-contracts script/measure-hook-gas.sh ({"kind","v","l","c","cold_gas"}) and reduces them to the largest cold
// record. The record kinds that scale with the committee (ack, stage, closure, recovery) must all be present, so a partial file cannot hide the largest; the
// election kinds are not records and are ignored; every line must be at the same (V, L, C).
func readHookMeasurement(path string) (b1state.HookMeasurement, error) {
	var best b1state.HookMeasurement
	raw, err := os.ReadFile(path) // #nosec G304 -- operator-supplied config path
	if err != nil {
		return best, fmt.Errorf("reading the hook measurement %q: %w", path, err)
	}
	need := map[string]bool{"ack": false, "stage": false, "closure": false, "recovery": false}
	var first *b1state.HookMeasurement
	for i, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		dec := json.NewDecoder(strings.NewReader(line))
		dec.DisallowUnknownFields()
		var l struct {
			Kind    string `json:"kind"`
			V       uint32 `json:"v"`
			L       uint32 `json:"l"`
			C       uint32 `json:"c"`
			ColdGas uint64 `json:"cold_gas"`
			Error   string `json:"error"`
		}
		if err := dec.Decode(&l); err != nil || dec.More() {
			return best, fmt.Errorf("the hook measurement %q line %d: %v", path, i+1, err)
		}
		if l.Error != "" || l.ColdGas == 0 {
			return best, fmt.Errorf("the hook measurement %q line %d (%s) is not a measurement: %q", path, i+1, l.Kind, l.Error)
		}
		if _, record := need[l.Kind]; !record {
			continue // elect, elect-heavy
		}
		need[l.Kind] = true
		m := b1state.HookMeasurement{V: l.V, L: l.L, C: l.C, Gas: l.ColdGas, Kind: l.Kind}
		if err := m.Valid(); err != nil {
			return best, fmt.Errorf("the hook measurement %q line %d: %w", path, i+1, err)
		}
		if first == nil {
			first = &m
		} else if m.V != first.V || m.L != first.L || m.C != first.C {
			return best, fmt.Errorf("the hook measurement %q mixes caps (V=%d L=%d C=%d and V=%d L=%d C=%d)", path, first.V, first.L, first.C, m.V, m.L, m.C)
		}
		if m.Gas > best.Gas {
			best = m
		}
	}
	for _, k := range []string{"ack", "stage", "closure", "recovery"} {
		if !need[k] {
			return best, fmt.Errorf("the hook measurement %q has no %q record: all four kinds are needed so the largest cannot be left out", path, k)
		}
	}
	return best, nil
}

func engineAPICheckHookGasCmd() *cobra.Command {
	var profilePath, freshPath string
	cmd := &cobra.Command{
		Use:   "check-hook-gas",
		Short: "Refuse a profile whose per-record hook gas is below a fresh cold measurement of its worst record, with the margin",
		Long: `The genesis check of the records hook's reservation: the profile must carry the cold measurement of its worst record, taken at exactly the deployed
caps (the manifest's vMax and lMax, the election's nMax), and hookRecordGas must be at least that measurement with the margin (x1.25, rounded up); the same
must hold for a fresh measurement at those caps (unicity-pos-contracts script/measure-hook-gas.sh V L C). A fresh measurement of other caps is refused.
Run it before genesis and whenever the contracts change.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if profilePath == "" || freshPath == "" {
				return errors.New("--b1-profile and --measurement are required")
			}
			p, f, err := readB1ProfileFile(profilePath)
			if err != nil {
				return err
			}
			if f.HookMeasurement == nil || f.HookCaps == nil {
				return fmt.Errorf("%w: the profile has no hook measurement or deployment caps", ErrB1Profile)
			}
			fresh, err := readHookMeasurement(freshPath)
			if err != nil {
				return err
			}
			if err := b1state.CheckHookGas(p, *f.HookCaps, *f.HookMeasurement, fresh); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "hook record gas %d covers the fresh %s record %d x1.25 (recorded %d for V=%d L=%d C=%d)\n",
				p.HookRecordGas, fresh.Kind, fresh.Gas, f.HookMeasurement.Gas, f.HookMeasurement.V, f.HookMeasurement.L, f.HookMeasurement.C)
			return nil
		},
	}
	cmd.Flags().StringVar(&profilePath, "b1-profile", "", "the profile file (required)")
	cmd.Flags().StringVar(&freshPath, "measurement", "", "a fresh measurement (the JSON lines of measure-hook-gas.sh) (required)")
	return cmd
}

func engineAPICheckElectGasCmd() *cobra.Command {
	var profilePath, freshPath string
	cmd := &cobra.Command{
		Use:   "check-elect-gas",
		Short: "Refuse a profile whose pinned election price is below a fresh worst-case measurement",
		Long: `The genesis check of the election hook's price: the profile must carry the measurement its price was pinned from (x1.25, rounded
up), the measurement must have been taken at exactly the deployed caps (the manifest's vMax and lMax, the election's nMax) and the price
must still cover a fresh measurement at those same caps (unicity-pos-contracts script/measure-elect.sh V L C). A fresh measurement of any
other (V, L, C) is refused. Run it before genesis and whenever the contracts change.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if profilePath == "" || freshPath == "" {
				return errors.New("--b1-profile and --measurement are required")
			}
			p, f, err := readB1ProfileFile(profilePath)
			if err != nil {
				return err
			}
			if f.ElectMeasurement == nil || f.ElectCaps == nil {
				return fmt.Errorf("%w: the profile has no election measurement or deployment caps", ErrB1Profile)
			}
			fresh, err := readElectMeasurement(freshPath)
			if err != nil {
				return err
			}
			if err := b1state.CheckElectGas(p, *f.ElectCaps, *f.ElectMeasurement, fresh); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "election price %d covers the fresh measurement %d (recorded %d for V=%d L=%d C=%d, margin x1.25)\n",
				p.ElectGas, fresh.Gas, f.ElectMeasurement.Gas, f.ElectMeasurement.V, f.ElectMeasurement.L, f.ElectMeasurement.C)
			return nil
		},
	}
	cmd.Flags().StringVar(&profilePath, "b1-profile", "", "the profile file (required)")
	cmd.Flags().StringVar(&freshPath, "measurement", "", "a fresh measurement JSON (required)")
	return cmd
}

func engineAPIB1ProfileCmd(baseFlags *baseFlags) *cobra.Command {
	var trustBasePath, out string
	var maxEpochs, deltaEV, deltaHold, capacity, genesisUCTime uint64
	var recordsCustody, electionContract, electMeasurementPath, electCapsFlag, hookMeasurementPath string
	var hRecords uint32
	var hookRecordGas uint64
	flags := &shardConfFlags{}
	cmd := &cobra.Command{
		Use:   "b1-profile",
		Short: "Derive the B1 execution profile of a deployment from its root trust base and shard configuration",
		Long: `Writes the one profile file the B1 deployment shares: ` + "`engine-api genesis --b1-profile`" + ` allocates the registry from it,
` + "`shard-node run --b1-profile`" + ` admits Updates under it, and the printed ureth flags pin the paired client to it. The root genesis
identity comes from the trust base's own history; the gas envelope is the frozen oracle envelope for the certificate window.

The mandatory hooks are pinned with --records-custody/--h-records/--hook-record-gas and --election. The election's price is never typed: it is
the margin (x1.25, rounded up) over --elect-measurement, the worst-case election measured for the chosen (V, L, C) by
unicity-pos-contracts script/measure-elect.sh, and the profile file records the measurement beside the price.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if trustBasePath == "" || out == "" {
				return fmt.Errorf("--trust-base and --out are required")
			}
			confs, err := flags.loadShardConfs(baseFlags)
			if err != nil {
				return fmt.Errorf("loading shard conf: %w", err)
			}
			if len(confs) != 1 {
				return fmt.Errorf("b1-profile requires exactly one --shard-conf, got %d", len(confs))
			}
			tb, err := readTrustBase(trustBasePath)
			if err != nil {
				return err
			}
			hooks, err := parseB1Hooks(recordsCustody, hRecords, hookRecordGas, electionContract, electMeasurementPath, electCapsFlag, hookMeasurementPath)
			if err != nil {
				return err
			}
			p, err := deriveB1Profile(tb, confs[0], maxEpochs, deltaEV, deltaHold, capacity, genesisUCTime, hooks)
			if err != nil {
				return err
			}
			file := b1ProfileFileOf(p)
			file.ElectMeasurement, file.ElectCaps = hooks.Measurement, hooks.Caps
			file.HookMeasurement, file.HookCaps = hooks.HookMeasurement, hooks.HookCaps
			enc, err := json.MarshalIndent(file, "", "  ")
			if err != nil {
				return err
			}
			if err := os.WriteFile(out, append(enc, '\n'), 0o644); err != nil { // #nosec G306 -- public configuration
				return fmt.Errorf("writing %q: %w", out, err)
			}
			hash, _ := p.Hash()
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "wrote %s\n", out)
			fmt.Fprintf(w, "profile hash:    %s\n", hexutil.Encode(hash[:]))
			fmt.Fprintf(w, "ureth flags:     %s\n", urethFlags(p, hash))
			return nil
		},
	}
	flags.addShardConfFlags(cmd, false)
	cmd.Flags().StringVar(&trustBasePath, "trust-base", "", "the signed root trust base JSON (required)")
	cmd.Flags().StringVar(&out, "out", "", "output path for the profile JSON (required)")
	cmd.Flags().Uint64Var(&maxEpochs, "max-epochs-per-update", b1state.MinEpochsPerUpdate, "B: validator epochs one block may install (at least the supersession span); the registry keeps every epoch forever")
	cmd.Flags().Uint64Var(&deltaEV, "delta-ev", 31, "P85 evidence window in rounds (DeltaEV); independent of certificate age, which no longer expires")
	cmd.Flags().Uint64Var(&deltaHold, "delta-hold", 32, "P85 hold window in rounds (DeltaHold); must exceed --delta-ev")
	cmd.Flags().Uint64Var(&capacity, "ordinary-capacity", 30_000_000, "ordinary transaction gas capacity of a block (the block gas limit is this plus the system reservation); one transaction may use all of it")
	cmd.Flags().StringVar(&recordsCustody, "records-custody", "", "the custody contract the mandatory records hook applies root records to (0x-hex address)")
	cmd.Flags().Uint32Var(&hRecords, "h-records", 0, "most records one block's hook applies (1..32; needs --records-custody)")
	cmd.Flags().Uint64Var(&hookRecordGas, "hook-record-gas", 0, "gross gas reserved per applied record (needs --records-custody)")
	cmd.Flags().StringVar(&electionContract, "election", "", "the ElectionPolicy module whose elect(origin) the hook calls (needs the records hook and --elect-measurement)")
	cmd.Flags().StringVar(&electMeasurementPath, "elect-measurement", "", "the worst-case election measurement JSON from unicity-pos-contracts script/measure-elect.sh; pins ElectGas = ceil(gas x 1.25)")
	cmd.Flags().StringVar(&hookMeasurementPath, "hook-measurement", "", "the cold measurement of the records hook's worst record: the JSON lines of unicity-pos-contracts script/measure-hook-gas.sh V L C at the deployment's caps (required with --records-custody); --hook-record-gas is refused below the largest figure x1.25")
	cmd.Flags().StringVar(&electCapsFlag, "elect-caps", "", "vMax,lMax,nMax the contracts manifest is deployed with (limits.vMax, limits.lMax, election nMax); the measurement must be taken at exactly these caps. Devnet/testnet: 16,2,8")
	cmd.Flags().Uint64Var(&genesisUCTime, "genesis-uc-time", 1000, "the pinned genesis UC time recorded in the registry (records.ucTime) before any import; a DEV value")
	return cmd
}

// ---- pair-side admission -------------------------------------------------------------------------------------------------------------------

// b1MaxProofKeys bounds one proof request: the six common words plus the widest admitted ring (registryproof.Snapshot.VerifyWords).
const b1MaxProofKeys = 6 + 524*16

// b1ProofFetcher returns the untrusted storage-proof source of the pair's Update admission: eth_getProof of the registry for the named
// verified parent, by block hash. The caller verifies every node against the parent's authenticated storage root; this function cannot
// grant authority, only fail to supply it.
func b1ProofFetcher(rpc registrywitness.Caller) func(context.Context, registryproof.Snapshot, []common.Hash) ([][][]byte, error) {
	return func(ctx context.Context, parent registryproof.Snapshot, keys []common.Hash) ([][][]byte, error) {
		if !parent.Valid() || len(keys) == 0 || len(keys) > b1MaxProofKeys {
			return nil, ErrB1Proof
		}
		raw, err := rpc.Call(ctx, "eth_getProof", []any{registryproof.RegistryAddress, keys, map[string]any{"blockHash": parent.ParentHash()}})
		if err != nil {
			return nil, fmt.Errorf("eth_getProof for the registry at %s: %w", parent.ParentHash(), err)
		}
		var res registryproof.GetProofResult
		if err := json.Unmarshal(raw, &res); err != nil {
			return nil, fmt.Errorf("%w: undecodable result: %v", ErrB1Proof, err)
		}
		if res.Address != registryproof.RegistryAddress || len(res.StorageProof) != len(keys) {
			return nil, fmt.Errorf("%w: %d proofs for %d keys at %s", ErrB1Proof, len(res.StorageProof), len(keys), res.Address)
		}
		out := make([][][]byte, len(keys))
		for i, sp := range res.StorageProof {
			if common.HexToHash(sp.Key) != keys[i] {
				return nil, fmt.Errorf("%w: proof %d is for key %s, not %s", ErrB1Proof, i, sp.Key, keys[i])
			}
			out[i] = make([][]byte, len(sp.Proof))
			for j, node := range sp.Proof {
				out[i][j] = []byte(node)
			}
		}
		return out, nil
	}
}

// newB1PairConfig is the pair's Update admission configuration: the profile, the authority of the node's own verified root history, and
// the proof source of its paired client. The root-record source is attached by attachRecordsFeed (the authenticated feed from the root nodes);
// the config deliberately carries none until then.
func newB1PairConfig(p b1state.Profile, rt *q3active.Runtime, ethURL string, timeout time.Duration) (*b1paired.Config, error) {
	if rt == nil {
		return nil, fmt.Errorf("%w: no verified root history", ErrB1Profile)
	}
	return &b1paired.Config{Profile: p, Authority: rt.B1Authority(), Proofs: b1ProofFetcher(registrywitness.NewHTTPCaller(ethURL, timeout))}, nil
}

// attachRecordsFeed gives the pair its authenticated route to the root's record log: one remote per root the node knows, asked in turn.
// What a root serves is believed only after it verified against the unicity tree root of the certificate the pair holds, so the roots
// are not trusted and any of them will do.
func attachRecordsFeed(cfg *b1paired.Config, host recordsfeed.Libp2p, roots []libp2ppeer.AddrInfo) {
	remotes := make([]recordsfeed.Remote, 0, len(roots))
	for _, r := range roots {
		remotes = append(remotes, recordsfeed.P2PRemote{Opener: recordsfeed.FromLibp2p(host), Roots: []libp2ppeer.ID{r.ID}})
	}
	cfg.Records = recordsfeed.NewSource(remotes...)
}

// b1IdentitiesFile is the genesis tool's identity document the vault deployment is checked against
// (unicity-pos-contracts script/BridgeGenesisBinding.sol): every hash 0x-prefixed.
type b1IdentitiesFile struct {
	RootGenesisID    string            `json:"rootGenesisId"`
	EVMGenesisHash   string            `json:"evmGenesisHash"`
	ProfileHash      string            `json:"profileHash"`
	ExecutionChainID uint64            `json:"executionChainId"`
	RegistryCodeHash string            `json:"registryCodeHash"`
	RegistryWords    map[string]string `json:"registryWords"`
}

func newB1Identities(p b1state.Profile, evmGenesisHash common.Hash, words map[common.Hash]common.Hash) ([]byte, error) {
	hash, err := p.Hash()
	if err != nil {
		return nil, err
	}
	doc := b1IdentitiesFile{
		RootGenesisID: hexutil.Encode(p.RootGenesisID[:]), EVMGenesisHash: evmGenesisHash.Hex(), ProfileHash: hexutil.Encode(hash[:]),
		ExecutionChainID: p.ExecutionChainID, RegistryCodeHash: hexutil.Encode(p.RuntimeHash[:]), RegistryWords: map[string]string{},
	}
	keys := make([]common.Hash, 0, len(words))
	for k := range words {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return bytes.Compare(keys[i][:], keys[j][:]) < 0 })
	for _, k := range keys {
		doc.RegistryWords[k.Hex()] = words[k].Hex()
	}
	enc, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(enc, '\n'), nil
}

// loadB1GenesisOrigin validates the finalized genesis of a B1 deployment against the full shard configuration, the profile and the trust
// base's own history, and returns the origin and the block-0 snapshot the first derivation takes as its parent.
func loadB1GenesisOrigin(full *types.PartitionDescriptionRecord, p b1state.Profile, h *q3format.History, genesisPath, expectedIdentity string) (registrygenesis.GenesisOrigin, registryproof.Snapshot, error) {
	finalized, err := os.ReadFile(genesisPath) // #nosec G304 -- operator-supplied config path, same trust level as --shard-conf
	if err != nil {
		return registrygenesis.GenesisOrigin{}, registryproof.Snapshot{}, fmt.Errorf("reading the finalized genesis %q: %w", genesisPath, err)
	}
	var expected *common.Hash
	if expectedIdentity != "" {
		id, err := parseHash32(expectedIdentity)
		if err != nil {
			return registrygenesis.GenesisOrigin{}, registryproof.Snapshot{}, fmt.Errorf("parsing --expected-origin-identity: %w", err)
		}
		expected = &id
	}
	origin, err := registrygenesis.B1Origin(full, p, h, finalized, expected, registrygenesis.DefaultGenesisJSONLimits())
	if err != nil {
		return registrygenesis.GenesisOrigin{}, registryproof.Snapshot{}, fmt.Errorf("validating the finalized B1 genesis against the full shard configuration: %w", err)
	}
	bootstrap, err := registryproof.Verify(origin.ProofContext(), origin.BlockHash(), origin.Evidence())
	if err != nil {
		return registrygenesis.GenesisOrigin{}, registryproof.Snapshot{}, fmt.Errorf("verifying the configured bootstrap snapshot: %w", err)
	}
	if !bootstrap.Valid() || !bootstrap.Genesis() || bootstrap.Number() != 0 || bootstrap.StateRoot() != origin.StateRoot() {
		return registrygenesis.GenesisOrigin{}, registryproof.Snapshot{}, fmt.Errorf("the configured bootstrap snapshot is not block 0 of the configured genesis origin")
	}
	return origin, bootstrap, nil
}

// loadB1Deployment reads the profile and binds it to the node's own pinned trust base and full shard configuration.
func loadB1Deployment(path string, tb *types.RootTrustBaseV1, conf *types.PartitionDescriptionRecord) (b1state.Profile, *q3format.History, error) {
	p, err := readB1Profile(path)
	if err != nil {
		return b1state.Profile{}, nil, err
	}
	h, err := bindB1Profile(p, tb, conf)
	if err != nil {
		return b1state.Profile{}, nil, err
	}
	return p, h, nil
}

// validateB1RunFlags refuses a --b1-profile that lacks what its checks need, and registry layout 3 without the profile that defines it.
func validateB1RunFlags(flags *shardNodeRunFlags) error {
	if flags.B1Profile != "" {
		if flags.RegistryLayout != 1 && flags.RegistryLayout != b1RegistryLayout {
			return fmt.Errorf("--b1-profile selects registry layout %d; --registry-layout %d contradicts it", b1RegistryLayout, flags.RegistryLayout)
		}
		flags.RegistryLayout = b1RegistryLayout
		if flags.Executor != "engine-api" || flags.GenesisFile == "" || flags.ExecutionJournal == "" || !flags.TrustHistoryProfile2 {
			return errors.New("--b1-profile requires --executor=engine-api, --genesis, --execution-journal and --trust-history-profile-2")
		}
		return nil
	}
	if flags.RegistryLayout == b1RegistryLayout {
		return errors.New("registry layout 3 is the fresh-B1 layout and requires --b1-profile")
	}
	return nil
}

// urethTxInputBytes is the pool's per-transaction size bound for the paired ureth: twice the bridge's envelope bound
// (bridgeprofile.MaxEnvelopeBytes), so a redemption at that bound with its Cfg and call framing is admitted. The stock 128 KiB
// default would refuse it (owner section 36, briefs/b7-direct-uncapped-design.md section 1).
const urethTxInputBytes = 2 * bridgeprofile.MaxEnvelopeBytes

// urethFlags are the flags that pin the paired ureth to the profile: the B1 bindings, and every mandatory hook the profile (and so its
// hash) commits to. A ureth started without a hook flag the hash commits to would run a different chain under the same hash. The
// pool is aligned with the profile's capacity: a transaction may use the whole ordinary capacity and carry a maximal bridge envelope.
func urethFlags(p b1state.Profile, hash [32]byte) string {
	s := fmt.Sprintf("--unicity.network-id=%d --unicity.root-genesis-id=%s --unicity.chain-id=%d --unicity.profile-hash=%s --unicity.max-epochs-per-update=%d --unicity.max-gas=%d --unicity.system-gas=%d --txpool.max-tx-gas=%d --txpool.max-tx-input-bytes=%d",
		p.Network, hexutil.Encode(p.RootGenesisID[:]), p.ExecutionChainID, hexutil.Encode(hash[:]), p.MaxEpochsPerUpdate, p.MaxGas, p.SystemGas, p.OrdinaryCapacity, urethTxInputBytes)
	if p.RecordsCustody != ([20]byte{}) {
		s += fmt.Sprintf(" --unicity.records-custody=%s --unicity.h-records=%d --unicity.hook-record-gas=%d",
			strings.ToLower(common.Address(p.RecordsCustody).Hex()), p.HRecords, p.HookRecordGas)
	}
	if p.ElectionContract != ([20]byte{}) {
		s += fmt.Sprintf(" --unicity.election=%s --unicity.elect-gas=%d", strings.ToLower(common.Address(p.ElectionContract).Hex()), p.ElectGas)
	}
	return s
}
