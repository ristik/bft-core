package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/vrschema"
	"github.com/unicitynetwork/bft-go-base/types"
)

// testdata/vr-genesis is a development generation produced by deploy/testnet/vr_genesis.py on the dev server (4 validators): the
// contracts input and deployment, the VR accounts of its EVM genesis, the full EVM shard configuration, the trust base, the profile, the
// roots' genesis identities, the ureth flags, the fresh measurement and the roots' VR deployment `verify` wrote.
func vrTestdata(t *testing.T, name string) string {
	return filepath.Join("testdata", "vr-genesis", name)
}

func vrFixtureInput(t *testing.T) vrVerifyInput {
	var v vrVerifyInput
	var err error
	require.NoError(t, vrStrictJSON(vrTestdata(t, "input.json"), &v.input))
	require.NoError(t, vrStrictJSON(vrTestdata(t, "deployment.json"), &v.deployment))
	v.alloc, err = vrAllocAccounts(vrTestdata(t, "vr-alloc.json"))
	require.NoError(t, err)
	v.full, err = readShardConf(vrTestdata(t, "full-shard-conf.json"))
	require.NoError(t, err)
	v.tb, err = readTrustBase(vrTestdata(t, "trust-base.json"))
	require.NoError(t, err)
	v.profile, v.profileFile, err = readB1ProfileFile(vrTestdata(t, "b1-profile.json"))
	require.NoError(t, err)
	v.identities, _, err = readIdentities(vrTestdata(t, "genesis-identities.json"))
	require.NoError(t, err)
	v.fresh, err = readVRHookMeasurement(vrTestdata(t, "vr-hook-measurement.json"))
	require.NoError(t, err)
	flags, err := os.ReadFile(vrTestdata(t, "ureth-flags.txt"))
	require.NoError(t, err)
	v.urethFlags, v.feeCollector = strings.TrimSpace(string(flags)), "0x00000000000000000000000000000000000000fe"
	return v
}

func TestTheVRGenerationIsConsistent(t *testing.T) {
	dep, err := vrVerify(vrFixtureInput(t))
	require.NoError(t, err)
	var want vrRootDeployment
	require.NoError(t, vrStrictJSON(vrTestdata(t, "vr-deployment.json"), &want))
	require.Equal(t, want, dep)
	// the pins this generation carries (VT-14 report)
	require.Equal(t, "0x19094777cb74c783f82392439d1f6c79fe62b6b57c2915790f00a9e16ee490e9", dep.RegistryCodeHash)
	v := vrFixtureInput(t)
	require.EqualValues(t, 32, v.profile.HRecords)
	require.EqualValues(t, 2_743_763, v.profile.HookRecordGas)
	require.EqualValues(t, 9_976_804, v.profile.ElectGas)
	env, err := v.profile.HookEnvelopeGas()
	require.NoError(t, err)
	require.EqualValues(t, 97_927_220, env)
}

// The plan is a pure function of the trust base, the shard configuration, the bindings, the profile and the governance and fee choices:
// re-planning the fixture reproduces its contracts input and the roots' identities exactly.
func TestTheVRPlanIsReproducible(t *testing.T) {
	v := vrFixtureInput(t)
	var bindings []evmassign.Binding
	for _, i := range v.identities {
		bindings = append(bindings, evmassign.Binding{RootNodeID: i.RootNodeID, EVMNodeID: i.EVMNodeID})
	}
	word, err := vrHex("network", v.input.Network, 32)
	require.NoError(t, err)
	signers := append([]string(nil), v.input.GovernorSigners...)
	signers[0], signers[4] = signers[4], signers[0] // any order: the plan orders the set
	in, ids, err := vrPlan(vrPlanInput{tb: v.tb, conf: v.full, bindings: bindings, profile: v.profile, network: [32]byte(word), governorSigners: signers,
		limits: v.input.Limits, fees: v.input.Fees})
	require.NoError(t, err)
	require.Equal(t, v.input, in)
	require.Equal(t, v.identities, ids)
	for i, id := range ids {
		n, err := evmassign.CustodyID(id.StakingID)
		require.NoError(t, err)
		require.EqualValues(t, i+1, n, "StakingID is the VR id as a 32-byte big-endian word")
	}

	_, _, err = vrPlan(vrPlanInput{tb: v.tb, conf: v.full, bindings: bindings, profile: v.profile, network: [32]byte(word), governorSigners: signers[:4],
		limits: v.input.Limits, fees: v.input.Fees})
	require.ErrorIs(t, err, ErrVRGenesis, "a 3-of-5 multisig needs five signers")
	p := v.profile
	p.ElectionContract = [20]byte{1}
	_, _, err = vrPlan(vrPlanInput{tb: v.tb, conf: v.full, bindings: bindings, profile: p, network: [32]byte(word), governorSigners: signers,
		limits: v.input.Limits, fees: v.input.Fees})
	require.ErrorIs(t, err, ErrVRGenesis, "the hooks must both be on VR")
	unpinned := *v.full
	unpinned.PartitionParams = map[string]string{"chain_id": "3"}
	_, _, err = vrPlan(vrPlanInput{tb: v.tb, conf: &unpinned, bindings: bindings, profile: v.profile, network: [32]byte(word), governorSigners: signers,
		limits: v.input.Limits, fees: v.input.Fees})
	require.ErrorIs(t, err, ErrVRGenesis, "the shard configuration must pin VR")
}

func cloneAlloc(a map[common.Address]vrAllocAccount) map[common.Address]vrAllocAccount {
	out := map[common.Address]vrAllocAccount{}
	for k, v := range a {
		st := map[string]string{}
		for sk, sv := range v.Storage {
			st[sk] = sv
		}
		v.Storage = st
		out[k] = v
	}
	return out
}

// Every artifact is held to every other: one mismatch anywhere refuses the generation.
func TestTheVRGenerationRefusesAnyMismatch(t *testing.T) {
	vr, composer := vrGenesisAddress(3), vrGenesisAddress(8)
	ns := vrschema.VRSlot(vrschema.SlotNetwork)
	networkSlot := common.BytesToHash(ns[:]).Hex()
	for name, edit := range map[string]func(*vrVerifyInput){
		"VR code":          func(v *vrVerifyInput) { a := v.alloc[vr]; a.Code += "00"; v.alloc[vr] = a },
		"missing facet":    func(v *vrVerifyInput) { delete(v.alloc, vrGenesisAddress(5)) },
		"composer storage": func(v *vrVerifyInput) { a := v.alloc[composer]; a.Storage["0x01"] = "0x01"; v.alloc[composer] = a },
		"moved module":     func(v *vrVerifyInput) { v.deployment.Module = "0xff0000000000000000000000000000000000000a" },
		"network word": func(v *vrVerifyInput) {
			a := v.alloc[vr]
			a.Storage[strings.ToLower(networkSlot)] = "0x01"
			v.alloc[vr] = a
		},
		"PDR code pin": func(v *vrVerifyInput) {
			v.full.PartitionParams["validator_registry_code_hash"] = "0x" + strings.Repeat("11", 32)
		},
		"PDR unpinned":     func(v *vrVerifyInput) { delete(v.full.PartitionParams, "validator_registry") },
		"profile max gas":  func(v *vrVerifyInput) { v.input.MaxGas++ },
		"identity payee":   func(v *vrVerifyInput) { v.identities[1].OperatorPayee = common.HexToAddress("0x01").Bytes() },
		"identity order":   func(v *vrVerifyInput) { v.identities[0], v.identities[1] = v.identities[1], v.identities[0] },
		"committee digest": func(v *vrVerifyInput) { v.deployment.CommitteeDigest = "0x" + strings.Repeat("22", 32) },
		"ureth lacks a hook": func(v *vrVerifyInput) {
			v.urethFlags = strings.ReplaceAll(v.urethFlags, "--unicity.elect-gas=9976804", "")
		},
		"ureth fee floor":  func(v *vrVerifyInput) { v.urethFlags += " --unicity.base-fee-floor=7" },
		"fee collector":    func(v *vrVerifyInput) { v.feeCollector = "0x00000000000000000000000000000000000000fd" },
		"fresh needs more": func(v *vrVerifyInput) { v.fresh.Records += 6 },
		"fresh other code": func(v *vrVerifyInput) { v.fresh.RegistryCodeHash = [32]byte{1} },
		"limits":           func(v *vrVerifyInput) { v.input.Limits.NMin = 3 },
		"root epoch":       func(v *vrVerifyInput) { v.input.KnownRootEpoch = 2 },
	} {
		v := vrFixtureInput(t)
		v.alloc = cloneAlloc(v.alloc)
		edit(&v)
		_, err := vrVerify(v)
		require.ErrorIs(t, err, ErrVRGenesis, name)
	}
}

// The roots' VR deployment binds to the genesis EVM PDR they run with, and the roots start in VR mode from the same configuration.
func TestTheRootsVRDeploymentIsTheGenesisPDRs(t *testing.T) {
	v := vrFixtureInput(t)
	confs := []*types.PartitionDescriptionRecord{v.full}
	dep, pins, err := loadVRRootDeployment(vrTestdata(t, "vr-deployment.json"), 3, confs)
	require.NoError(t, err)
	require.Equal(t, vrschema.ValidatorRegistry, dep.Registry)
	require.Equal(t, vrschema.U64(3), dep.ChainID)
	require.Equal(t, vrschema.SealRegistry, pins.SealRegistry)
	_, _, err = loadVRRootDeployment(vrTestdata(t, "vr-deployment.json"), 4, confs)
	require.ErrorIs(t, err, ErrVRGenesis, "another root network")
	other := *v.full
	other.PartitionParams = map[string]string{}
	for k, val := range v.full.PartitionParams {
		other.PartitionParams[k] = val
	}
	other.PartitionParams["validator_registry_code_hash"] = "0x" + strings.Repeat("33", 32)
	_, _, err = loadVRRootDeployment(vrTestdata(t, "vr-deployment.json"), 3, []*types.PartitionDescriptionRecord{&other})
	require.ErrorIs(t, err, ErrVRGenesis, "a deployment the genesis PDR does not pin")
}

func TestTheComposerInertScanSkipsPushData(t *testing.T) {
	require.True(t, inertCode([]byte{0x60, 0x55, 0x60, 0xf4}))
	for _, op := range []byte{0xf0, 0xf1, 0xf2, 0xf4, 0xf5, 0xff, 0x55} {
		require.False(t, inertCode([]byte{0x60, 0x01, op}), "%x", op)
	}
	raw, err := os.ReadFile(vrTestdata(t, "deployment.json"))
	require.NoError(t, err)
	require.True(t, json.Valid(raw))
}

// A VR profile file records its measurement, and its two prices must be exactly the ones the measurement pins.
func TestAVRProfileFileHoldsItsPricesToItsMeasurement(t *testing.T) {
	raw, err := os.ReadFile(vrTestdata(t, "b1-profile.json"))
	require.NoError(t, err)
	for name, edit := range map[string]func(map[string]any){
		"typed record gas":     func(m map[string]any) { m["hookRecordGas"] = 3_000_000 },
		"typed elect gas":      func(m map[string]any) { m["electGas"] = 9_976_805 },
		"a P85 measurement":    func(m map[string]any) { m["hookCaps"] = map[string]any{"vMax": 16, "lMax": 1, "nMax": 6} },
		"election elsewhere":   func(m map[string]any) { m["electionContract"] = "0x00000000000000000000000000000000000000ee" },
		"a lower H, same rate": func(m map[string]any) { m["hRecords"] = 16 },
	} {
		var m map[string]any
		require.NoError(t, json.Unmarshal(raw, &m))
		edit(m)
		b, err := json.Marshal(m)
		require.NoError(t, err)
		path := filepath.Join(t.TempDir(), "p.json")
		require.NoError(t, os.WriteFile(path, b, 0o600))
		_, _, err = readB1ProfileFile(path)
		require.ErrorIs(t, err, ErrB1Profile, name)
	}
}
