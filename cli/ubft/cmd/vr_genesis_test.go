package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/vrschema"
	"github.com/unicitynetwork/bft-go-base/types"
)

// testdata/vr-genesis is a development generation produced by deploy/testnet/vr_genesis.py on the dev server (4 validators): the
// contracts input and deployment, its finalized EVM genesis, the full EVM shard configuration, the trust base, the profile, the roots'
// genesis identities, the ureth flags, the fresh measurement and the roots' VR deployment `verify` wrote.
func vrTestdata(t *testing.T, name string) string {
	return filepath.Join("testdata", "vr-genesis", name)
}

func vrFixtureInput(t *testing.T) vrVerifyInput {
	var v vrVerifyInput
	var err error
	require.NoError(t, vrStrictJSON(vrTestdata(t, "input.json"), &v.input))
	require.NoError(t, vrStrictJSON(vrTestdata(t, "deployment.json"), &v.deployment))
	v.genesis, err = os.ReadFile(vrTestdata(t, "genesis.json"))
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

// ---- refusal: every artifact against every other (the reviewers' mutations, astra and sol VT-14) ------------------------------------------

// editGenesis rewrites the fixture's finalized genesis through a generic JSON edit.
func editGenesis(t *testing.T, v *vrVerifyInput, edit func(g map[string]any)) {
	var g map[string]any
	require.NoError(t, json.Unmarshal(v.genesis, &g))
	edit(g)
	raw, err := json.Marshal(g)
	require.NoError(t, err)
	v.genesis = raw
}

func allocOf(g map[string]any, a common.Address) map[string]any {
	for k, acct := range g["alloc"].(map[string]any) {
		if strings.EqualFold(k, a.Hex()) || strings.EqualFold(k, strings.TrimPrefix(a.Hex(), "0x")) {
			return acct.(map[string]any)
		}
	}
	panic("no account " + a.Hex())
}

func slotKey(g map[string]any, a common.Address, slot vrschema.Word) string {
	st, _ := allocOf(g, a)["storage"].(map[string]any)
	for k := range st {
		if w, ok := bigWord(k); ok && w == slot {
			return k
		}
	}
	return lowerHex(slot[:])
}

// setSlot sets one allocated storage word (value as 0x hex; "0x00" clears it).
func setSlot(t *testing.T, v *vrVerifyInput, a common.Address, slot vrschema.Word, value string) {
	editGenesis(t, v, func(g map[string]any) {
		acct := allocOf(g, a)
		st, _ := acct["storage"].(map[string]any)
		if st == nil {
			st = map[string]any{}
			acct["storage"] = st
		}
		st[slotKey(g, a, slot)] = value
	})
}

// bumpSlot changes the lowest byte of an allocated word by one (a one-byte mutation).
func bumpSlot(t *testing.T, v *vrVerifyInput, a common.Address, slot vrschema.Word, delta int) {
	editGenesis(t, v, func(g map[string]any) {
		st := allocOf(g, a)["storage"].(map[string]any)
		k := slotKey(g, a, slot)
		w, ok := bigWord(st[k].(string))
		require.True(t, ok)
		w[31] = byte(int(w[31]) + delta)
		st[k] = lowerHex(w[:])
	})
}

func setCode(t *testing.T, v *vrVerifyInput, a common.Address, code string) {
	editGenesis(t, v, func(g map[string]any) { allocOf(g, a)["code"] = code })
}

func replaceFlag(line, prefix, with string) string {
	f := strings.Fields(line)
	for i := range f {
		if strings.HasPrefix(f[i], prefix) {
			f[i] = with
		}
	}
	return strings.Join(f, " ")
}

func flipHex(s string) string { // the last hex digit, changed
	last := s[len(s)-1]
	if last == '0' {
		return s[:len(s)-1] + "1"
	}
	return s[:len(s)-1] + "0"
}

func TestTheVRGenerationRefusesAnyMismatch(t *testing.T) {
	vr, poa, composer, governor, seal := vrGenesisAddress(3), vrGenesisAddress(7), vrGenesisAddress(8), vrGenesisAddress(9), common.Address(vrschema.SealRegistry)
	V := vrschema.VRSlot
	stop := "0x00"
	for name, edit := range map[string]func(*vrVerifyInput){
		// astra, VT-14 review (review_vt14_test.go)
		"astra empty actual committee":     func(v *vrVerifyInput) { setSlot(t, v, vr, V(42), "0x00"); setSlot(t, v, vr, V(26), "0x00") },
		"astra zero actual identity count": func(v *vrVerifyInput) { setSlot(t, v, vr, V(vrschema.SlotCounters), "0x01") },
		"astra zero actual hook limits":    func(v *vrVerifyInput) { setSlot(t, v, vr, V(vrschema.SlotHookLimits), "0x00") },
		"astra zero actual fees": func(v *vrVerifyInput) {
			setSlot(t, v, vr, V(vrschema.SlotFeesPrevious), "0x00")
			setSlot(t, v, vr, V(vrschema.SlotFeesCurrent), "0x00")
		},
		"astra empty governor signers": func(v *vrVerifyInput) {
			editGenesis(t, v, func(g map[string]any) { allocOf(g, governor)["storage"] = map[string]any{} })
		},
		"astra records facet STOP, report matching": func(v *vrVerifyInput) {
			setCode(t, v, vrGenesisAddress(6), stop)
			v.deployment.RecordsFacetCodeHash = ethcrypto.Keccak256Hash([]byte{0}).Hex()
		},
		"astra composer STOP, report matching": func(v *vrVerifyInput) {
			setCode(t, v, composer, stop)
			v.deployment.ComposerCodeHash = ethcrypto.Keccak256Hash([]byte{0}).Hex()
		},
		"astra SealRegistry STOP": func(v *vrVerifyInput) { setCode(t, v, seal, stop) },
		"astra zero seal_registry_genesis": func(v *vrVerifyInput) {
			v.full.PartitionParams["seal_registry_genesis"] = "0x" + strings.Repeat("00", 32)
		},
		"astra space-separated fee floor": func(v *vrVerifyInput) { v.urethFlags += " --unicity.base-fee-floor 2000000" },
		"astra zero ureth genesis commitment": func(v *vrVerifyInput) {
			v.urethFlags = replaceFlag(v.urethFlags, "--unicity.genesis-commitment=", "--unicity.genesis-commitment=0x"+strings.Repeat("00", 32))
		},
		// sol, VT-14 review (/tmp/sol-vt14-mutations): one byte each
		"sol PDR seal_registry_genesis": func(v *vrVerifyInput) {
			v.full.PartitionParams["seal_registry_genesis"] = flipHex(v.full.PartitionParams["seal_registry_genesis"])
		},
		"sol actual committee digest":    func(v *vrVerifyInput) { bumpSlot(t, v, vr, V(26), 1) },
		"sol actual committee length":    func(v *vrVerifyInput) { bumpSlot(t, v, vr, V(42), 1) },
		"sol actual fees previous floor": func(v *vrVerifyInput) { bumpSlot(t, v, vr, V(vrschema.SlotFeesPrevious), 1) },
		"sol actual fees current floor":  func(v *vrVerifyInput) { bumpSlot(t, v, vr, V(vrschema.SlotFeesCurrent), 1) },
		"sol actual maxBatch": func(v *vrVerifyInput) {
			setSlot(t, v, vr, V(vrschema.SlotHookLimits), lowerHex(func() []byte { w := packed([3]uint64{0, 4, 16}, [3]uint64{4, 4, 1}, [3]uint64{8, 4, 4}); return w[:] }()))
		},
		"sol actual governor signer": func(v *vrVerifyInput) { bumpSlot(t, v, governor, vrschema.U64(2), 1) },
		"sol genesis chain id": func(v *vrVerifyInput) {
			editGenesis(t, v, func(g map[string]any) { g["config"].(map[string]any)["chainId"] = 4 })
		},
		"sol genesis gas limit": func(v *vrVerifyInput) {
			editGenesis(t, v, func(g map[string]any) { g["gasLimit"] = flipHex(g["gasLimit"].(string)) })
		},
		"sol input governor signer": func(v *vrVerifyInput) { v.input.GovernorSigners[2] = flipHex(v.input.GovernorSigners[2]) },
		"sol input owner":           func(v *vrVerifyInput) { v.input.Identities[0].Owner = flipHex(v.input.Identities[0].Owner) },
		"sol ureth genesis commitment": func(v *vrVerifyInput) {
			for _, f := range strings.Fields(v.urethFlags) {
				if c, ok := strings.CutPrefix(f, "--unicity.genesis-commitment="); ok {
					v.urethFlags = replaceFlag(v.urethFlags, "--unicity.genesis-commitment=", "--unicity.genesis-commitment="+flipHex(c))
				}
			}
		},
		"sol ureth split fee floor": func(v *vrVerifyInput) { v.urethFlags += " --unicity.base-fee-floor 7" },
		// further: code, storage, report and runtime-input mismatches
		"VR code": func(v *vrVerifyInput) {
			editGenesis(t, v, func(g map[string]any) { allocOf(g, vr)["code"] = allocOf(g, vr)["code"].(string) + "00" })
		},
		"governor STOP": func(v *vrVerifyInput) {
			setCode(t, v, governor, stop)
			v.deployment.GovernorCodeHash = ethcrypto.Keccak256Hash([]byte{0}).Hex()
		},
		"missing facet": func(v *vrVerifyInput) {
			editGenesis(t, v, func(g map[string]any) { delete(g["alloc"].(map[string]any), vrGenesisAddress(5).Hex()) })
		},
		"composer storage": func(v *vrVerifyInput) { setSlot(t, v, composer, vrschema.U64(1), "0x01") },
		"an extra VR slot": func(v *vrVerifyInput) { setSlot(t, v, vr, V(27), "0x01") },
		"PoA member state": func(v *vrVerifyInput) { setSlot(t, v, poa, vrschema.MapSlot(vrschema.U64(1), vrschema.Word{}), "0x05") },
		"a VR balance": func(v *vrVerifyInput) {
			editGenesis(t, v, func(g map[string]any) { allocOf(g, vr)["balance"] = "0x1" })
		},
		"report module":           func(v *vrVerifyInput) { v.deployment.Module = "0xff0000000000000000000000000000000000000a" },
		"report committee digest": func(v *vrVerifyInput) { v.deployment.CommitteeDigest = "0x" + strings.Repeat("22", 32) },
		"PDR code pin": func(v *vrVerifyInput) {
			v.full.PartitionParams["validator_registry_code_hash"] = "0x" + strings.Repeat("11", 32)
		},
		"PDR unpinned":    func(v *vrVerifyInput) { delete(v.full.PartitionParams, "validator_registry") },
		"plan max gas":    func(v *vrVerifyInput) { v.input.MaxGas++ },
		"plan limits":     func(v *vrVerifyInput) { v.input.Limits.NMin = 3 },
		"plan root epoch": func(v *vrVerifyInput) { v.input.KnownRootEpoch = 2 },
		"identity payee":  func(v *vrVerifyInput) { v.identities[1].OperatorPayee = common.HexToAddress("0x01").Bytes() },
		"identity order":  func(v *vrVerifyInput) { v.identities[0], v.identities[1] = v.identities[1], v.identities[0] },
		"ureth lacks a hook": func(v *vrVerifyInput) {
			v.urethFlags = strings.ReplaceAll(v.urethFlags, "--unicity.elect-gas=9976804", "")
		},
		"ureth hook value": func(v *vrVerifyInput) {
			v.urethFlags = replaceFlag(v.urethFlags, "--unicity.elect-gas=", "--unicity.elect-gas=9976805")
		},
		"ureth repeated flag":     func(v *vrVerifyInput) { v.urethFlags += " --unicity.elect-gas=9976804" },
		"ureth denominator split": func(v *vrVerifyInput) { v.urethFlags += " --unicity.base-fee-change-denominator 9" },
		"ureth elasticity":        func(v *vrVerifyInput) { v.urethFlags += " --unicity.elasticity=3" },
		"no ureth flags":          func(v *vrVerifyInput) { v.urethFlags = "" },
		"no fee collector":        func(v *vrVerifyInput) { v.feeCollector = "" },
		"fee collector":           func(v *vrVerifyInput) { v.feeCollector = "0x00000000000000000000000000000000000000fd" },
		"fresh needs more":        func(v *vrVerifyInput) { v.fresh.Records += 6 },
		"fresh other code":        func(v *vrVerifyInput) { v.fresh.RegistryCodeHash = [32]byte{1} },
		"duplicate slot spelling": func(v *vrVerifyInput) {
			editGenesis(t, v, func(g map[string]any) {
				st := allocOf(g, vr)["storage"].(map[string]any)
				k := slotKey(g, vr, V(5))
				st[strings.ToUpper(strings.TrimPrefix(k, "0x"))] = "0x00"
			})
		},
	} {
		t.Run(name, func(t *testing.T) {
			v := vrFixtureInput(t)
			_, err := vrVerify(v)
			require.NoError(t, err, "the unmodified control passes")
			v = vrFixtureInput(t)
			edit(&v)
			_, err = vrVerify(v)
			require.ErrorIs(t, err, ErrVRGenesis)
			t.Log(err)
		})
	}
}

// --partial checks the files without the runtime inputs and certifies nothing.
func TestAPartialVRCheckCertifiesNothing(t *testing.T) {
	v := vrFixtureInput(t)
	v.urethFlags, v.feeCollector, v.partial = "", "", true
	dep, err := vrVerify(v)
	require.ErrorIs(t, err, ErrVRGenesisPartial, "files that agree still exit as PARTIAL, never as success")
	require.Equal(t, vrRootDeployment{}, dep, "no root deployment from a partial check")
	v = vrFixtureInput(t)
	v.partial = true
	_, err = vrVerify(v)
	require.ErrorIs(t, err, ErrVRGenesis, "a partial check refuses runtime inputs it would ignore")
	require.NotErrorIs(t, err, ErrVRGenesisPartial)
	v = vrFixtureInput(t)
	v.urethFlags, v.feeCollector, v.partial = "", "", true
	setSlot(t, &v, vrGenesisAddress(3), vrschema.VRSlot(26), "0x00")
	_, err = vrVerify(v)
	require.ErrorIs(t, err, ErrVRGenesis, "the files are still checked")
}

func TestUrethArgumentsParseBothFormsAndRefuseRepeats(t *testing.T) {
	a, err := parseUrethArgs("--unicity.base-fee-floor 7 --unicity.max-gas=5 --unicity.no-proof-source --txpool.max-tx-gas 9")
	require.NoError(t, err)
	require.Equal(t, urethArgs{"--unicity.base-fee-floor": "7", "--unicity.max-gas": "5", "--unicity.no-proof-source": "", "--txpool.max-tx-gas": "9"}, a)
	for _, bad := range []string{"--unicity.no-proof-source 2000000", "--unicity.no-proof-source=true", "-vvv", "--datadir /x", "--unicity.max-gas"} {
		_, err = parseUrethArgs(bad)
		require.ErrorIs(t, err, ErrVRGenesis, bad)
	}
	_, err = parseUrethArgs("--unicity.max-gas=5 --unicity.max-gas 5")
	require.ErrorIs(t, err, ErrVRGenesis)
	_, err = parseUrethArgs("--unicity.max-gas=5 stray")
	require.ErrorIs(t, err, ErrVRGenesis)
}

// ---- dev funding: the premine of a development generation (testdata/vr-genesis-dev: vr_genesis.py --dev-fund) ----------------------------

const vrDevGeneration = "gen-devfund"

func vrDevFixtureInput(t *testing.T) vrVerifyInput {
	t.Helper()
	dir := func(n string) string { return filepath.Join("testdata", "vr-genesis-dev", n) }
	var v vrVerifyInput
	var err error
	require.NoError(t, vrStrictJSON(dir("input.json"), &v.input))
	require.NoError(t, vrStrictJSON(dir("deployment.json"), &v.deployment))
	v.genesis, err = os.ReadFile(dir("genesis.json"))
	require.NoError(t, err)
	v.full, err = readShardConf(dir("full-shard-conf.json"))
	require.NoError(t, err)
	v.tb, err = readTrustBase(dir("trust-base.json"))
	require.NoError(t, err)
	v.profile, v.profileFile, err = readB1ProfileFile(dir("b1-profile.json"))
	require.NoError(t, err)
	v.identities, _, err = readIdentities(dir("genesis-identities.json"))
	require.NoError(t, err)
	v.fresh, err = readVRHookMeasurement(dir("vr-hook-measurement-fresh.json"))
	require.NoError(t, err)
	flags, err := os.ReadFile(dir("ureth-flags.txt"))
	require.NoError(t, err)
	v.urethFlags, v.feeCollector = strings.TrimSpace(string(flags)), "0x00000000000000000000000000000000000000fe"
	var funded map[string]string
	require.NoError(t, vrStrictJSON(dir("dev-funded-accounts.json"), &funded))
	v.funded = map[common.Address]vrschema.Word{}
	for k, b := range funded {
		w, ok := bigWord(b)
		require.True(t, ok)
		v.funded[common.HexToAddress(k)] = w
	}
	v.devGeneration = vrDevGeneration
	return v
}

func TestADevGenerationsPremineIsExpectedNeverAHole(t *testing.T) {
	_, err := vrVerify(vrDevFixtureInput(t))
	require.NoError(t, err, "the dev generation with its premine verifies")
	owner := common.HexToAddress(vrDevFixtureInput(t).input.Identities[0].Owner)
	signer := common.HexToAddress(vrDevFixtureInput(t).input.GovernorSigners[0])
	for name, edit := range map[string]func(*vrVerifyInput){
		"no dev generation":             func(v *vrVerifyInput) { v.devGeneration = "" },
		"another dev generation's name": func(v *vrVerifyInput) { v.devGeneration = "gen-other" },
		"an owner not funded":           func(v *vrVerifyInput) { delete(v.funded, owner) },
		"a signer not funded":           func(v *vrVerifyInput) { delete(v.funded, signer) },
		"a listed premine not allocated": func(v *vrVerifyInput) {
			v.funded[common.HexToAddress("0x000000000000000000000000000000000000beef")] = vrschema.U64(1)
		},
		"a premine balance changed": func(v *vrVerifyInput) {
			editGenesis(t, v, func(g map[string]any) { allocOf(g, owner)["balance"] = "0x1" })
		},
		"an unlisted premine": func(v *vrVerifyInput) {
			editGenesis(t, v, func(g map[string]any) {
				g["alloc"].(map[string]any)["0x000000000000000000000000000000000000cafe"] = map[string]any{"balance": "0x3635c9adc5dea00000"}
			})
		},
		"a premine with code": func(v *vrVerifyInput) {
			editGenesis(t, v, func(g map[string]any) { allocOf(g, owner)["code"] = "0x00" })
		},
		"no funded list": func(v *vrVerifyInput) { v.funded = nil },
	} {
		t.Run(name, func(t *testing.T) {
			v := vrDevFixtureInput(t)
			edit(&v)
			_, err := vrVerify(v)
			require.ErrorIs(t, err, ErrVRGenesis)
		})
	}
	// and a non-dev generation takes no funding at all
	v := vrFixtureInput(t)
	v.funded = map[common.Address]vrschema.Word{owner: vrschema.U64(1)}
	_, err = vrVerify(v)
	require.ErrorIs(t, err, ErrVRGenesis)
	v.devGeneration = "gen-dev1"
	_, err = vrVerify(v)
	require.ErrorIs(t, err, ErrVRGenesis, "a testnet network word is not a dev generation's")
}
