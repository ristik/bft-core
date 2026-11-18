package cmd

// The round-2 review mutations of #1182 (Opus, briefs/opus-review-vt14-r2-answer.md), permanent: every inconsistent generation is refused
// against an unmodified control that passes, and the benign variants the review named are accepted.

import (
	"bytes"
	"sort"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/vrschema"
)

func opusStorageJSON(s vrStorage) map[string]any {
	out := map[string]any{}
	for k, v := range s {
		out[lowerHex(k[:])] = lowerHex(v[:])
	}
	return out
}

// opusRewriteState replaces the allocated storage of VR, the module and the multisig with the state the (possibly mutated) plan
// determines, and the report's committee digest with its digest: a self-consistent generation of a different plan.
func opusRewriteState(t *testing.T, v *vrVerifyInput) {
	_, alloc, err := vrParseGenesis(v.genesis)
	require.NoError(t, err)
	code := common.FromHex(alloc[vrGenesisAddress(7)].Code)
	vr, poa, ms, committee, err := vrExpectedState(v.input, v.identities, [32]byte(ethcrypto.Keccak256(code)))
	require.NoError(t, err)
	editGenesis(t, v, func(g map[string]any) {
		allocOf(g, vrGenesisAddress(3))["storage"] = opusStorageJSON(vr)
		allocOf(g, vrGenesisAddress(7))["storage"] = opusStorageJSON(poa)
		allocOf(g, vrGenesisAddress(9))["storage"] = opusStorageJSON(ms)
	})
	v.deployment.CommitteeDigest = lowerHex(committee[:])
}

func opusCode(g map[string]any, low byte) string {
	return allocOf(g, vrGenesisAddress(low))["code"].(string)
}

func opusHash(code string) string { return ethcrypto.Keccak256Hash(common.FromHex(code)).Hex() }

// benignR2 are the variants that must still verify: the ones the review found harmless, the case of an address in the report, and the
// measurement's informational source string (its provenance is recorded by the plan, F7). A non-canonical key in input.json, which the
// review asked about, is refused: the plan is re-derived byte for byte. A companion retention depth of 1 is refused (astra r2: the client
// does not start with it).
var benignR2 = map[string]bool{
	"deployment: composer address case":                                    true,
	"fresh: source string":                                                 true,
	"ureth: pinned value in space form (legit, should pass)":               true,
	"plan: unchanged rewrite (control of the rewrite helper, should pass)": true,
	"storage: zero-valued extra slot on VR (must be benign)":               true,
	"ureth: +sign floor (clap u64 accepts +)":                              true,
	"header: extraData last nibble":                                        true,
}

func TestTheRound2MutationsAreRefused(t *testing.T) {
	type c struct {
		name string
		edit func(*vrVerifyInput)
	}
	vr := vrGenesisAddress(3)
	cases := []c{
		// ---- nonces of the seven accounts (vrAllocAccount.Nonce is never read)
		{"nonce: VR nonce 0x1", func(v *vrVerifyInput) { editGenesis(t, v, func(g map[string]any) { allocOf(g, vr)["nonce"] = "0x1" }) }},
		{"nonce: module nonce 0x5", func(v *vrVerifyInput) {
			editGenesis(t, v, func(g map[string]any) { allocOf(g, vrGenesisAddress(7))["nonce"] = "0x5" })
		}},
		{"nonce: multisig nonce 0xff", func(v *vrVerifyInput) {
			editGenesis(t, v, func(g map[string]any) { allocOf(g, vrGenesisAddress(9))["nonce"] = "0xff" })
		}},
		{"nonce: SealRegistry nonce 0x1 (control: B1Origin)", func(v *vrVerifyInput) {
			editGenesis(t, v, func(g map[string]any) { allocOf(g, common.Address(vrschema.SealRegistry))["nonce"] = "0x1" })
		}},
		// ---- accounts outside the seven
		{"extra: 0xff..0a with code (reserved range)", func(v *vrVerifyInput) {
			editGenesis(t, v, func(g map[string]any) {
				g["alloc"].(map[string]any)["0xff0000000000000000000000000000000000000a"] = map[string]any{"balance": "0x0", "code": "0x00"}
			})
		}},
		{"extra: 0xff..01 with code and storage (reserved range)", func(v *vrVerifyInput) {
			editGenesis(t, v, func(g map[string]any) {
				g["alloc"].(map[string]any)["0xff00000000000000000000000000000000000001"] = map[string]any{"balance": "0x0", "code": "0x600160005500",
					"storage": map[string]any{"0x01": "0x01"}}
			})
		}},
		{"extra: EIP-4788 beacon-roots address with code", func(v *vrVerifyInput) {
			editGenesis(t, v, func(g map[string]any) {
				g["alloc"].(map[string]any)["0x000f3df6d732807ef1319fb7b8bb8522d0beac02"] = map[string]any{"balance": "0x0", "code": "0x5b600056"}
			})
		}},
		{"extra: funded EOA (premine 2^200)", func(v *vrVerifyInput) {
			editGenesis(t, v, func(g map[string]any) {
				g["alloc"].(map[string]any)["0x000000000000000000000000000000000000beef"] = map[string]any{"balance": "0x100000000000000000000000000000000000000000000000000"}
			})
		}},
		{"extra: storage-only account outside the seven", func(v *vrVerifyInput) {
			editGenesis(t, v, func(g map[string]any) {
				g["alloc"].(map[string]any)["0x000000000000000000000000000000000000cafe"] = map[string]any{"balance": "0x0", "storage": map[string]any{"0x00": "0x01"}}
			})
		}},
		{"extra: the a_sys system address (control: B1Origin)", func(v *vrVerifyInput) {
			editGenesis(t, v, func(g map[string]any) {
				g["alloc"].(map[string]any)["0xfffffffffffffffffffffffffffffffffffffffe"] = map[string]any{"balance": "0x0"}
			})
		}},
		// ---- facet code bound by "some PUSH32 of the core", not by role
		{"facets: governance <-> repair code swapped, report matching", func(v *vrVerifyInput) {
			editGenesis(t, v, func(g map[string]any) {
				a, b := opusCode(g, 4), opusCode(g, 5)
				allocOf(g, vrGenesisAddress(4))["code"], allocOf(g, vrGenesisAddress(5))["code"] = b, a
				v.deployment.GovernanceFacetCodeHash, v.deployment.RepairFacetCodeHash = opusHash(b), opusHash(a)
			})
		}},
		{"facets: records facet code at all three, report matching", func(v *vrVerifyInput) {
			editGenesis(t, v, func(g map[string]any) {
				r := opusCode(g, 6)
				allocOf(g, vrGenesisAddress(4))["code"], allocOf(g, vrGenesisAddress(5))["code"] = r, r
				v.deployment.GovernanceFacetCodeHash, v.deployment.RepairFacetCodeHash = opusHash(r), opusHash(r)
			})
		}},
		// ---- header fields of the finalized genesis
		{"header: baseFeePerGas 0x3b9aca00 -> 0x3b9aca01", func(v *vrVerifyInput) {
			editGenesis(t, v, func(g map[string]any) { g["baseFeePerGas"] = "0x3b9aca01" })
		}},
		{"header: baseFeePerGas 0x0 (below VR floor)", func(v *vrVerifyInput) {
			editGenesis(t, v, func(g map[string]any) { g["baseFeePerGas"] = "0x0" })
		}},
		{"header: timestamp 0x1", func(v *vrVerifyInput) { editGenesis(t, v, func(g map[string]any) { g["timestamp"] = "0x1" }) }},
		{"header: extraData last nibble", func(v *vrVerifyInput) {
			editGenesis(t, v, func(g map[string]any) { g["extraData"] = flipHex(g["extraData"].(string)) })
		}},
		{"header: coinbase", func(v *vrVerifyInput) {
			editGenesis(t, v, func(g map[string]any) { g["coinbase"] = "0x0000000000000000000000000000000000000001" })
		}},
		{"header: nonce 0x1", func(v *vrVerifyInput) { editGenesis(t, v, func(g map[string]any) { g["nonce"] = "0x1" }) }},
		{"header: mixHash", func(v *vrVerifyInput) {
			editGenesis(t, v, func(g map[string]any) { g["mixHash"] = "0x" + strings.Repeat("00", 31) + "01" })
		}},
		// ---- storage, one byte each, on words the round-1 tests did not touch
		{"storage: VR network word", func(v *vrVerifyInput) { bumpSlot(t, v, vr, vrschema.VRSlot(vrschema.SlotNetwork), 1) }},
		{"storage: VR generation params V+24", func(v *vrVerifyInput) { bumpSlot(t, v, vr, vrschema.VRSlot(24), 1) }},
		{"storage: VR systemGas V+25", func(v *vrVerifyInput) { bumpSlot(t, v, vr, vrschema.VRSlot(25), 1) }},
		{"storage: VR module TAG V+16", func(v *vrVerifyInput) { bumpSlot(t, v, vr, vrschema.VRSlot(16), 1) }},
		{"storage: VR gas bounds V+18", func(v *vrVerifyInput) { bumpSlot(t, v, vr, vrschema.VRSlot(18), 1) }},
		{"storage: VR status (root epoch)", func(v *vrVerifyInput) { bumpSlot(t, v, vr, vrschema.VRSlot(vrschema.SlotStatus), 1) }},
		{"storage: PoA members length", func(v *vrVerifyInput) { bumpSlot(t, v, vrGenesisAddress(7), vrschema.U64(1), 1) }},
		{"storage: facet gets a slot", func(v *vrVerifyInput) { setSlot(t, v, vrGenesisAddress(5), vrschema.U64(0), "0x01") }},
		{"storage: zero-valued extra slot on VR (must be benign)", func(v *vrVerifyInput) { setSlot(t, v, vr, vrschema.VRSlot(30), "0x00") }},
		// ---- ureth argument vector
		{"ureth: --unicity.fee-collector=0x..fd appended", func(v *vrVerifyInput) {
			v.urethFlags += " --unicity.fee-collector=0x00000000000000000000000000000000000000fd"
		}},
		{"ureth: --unicity.fee-collector 0x..fd (space form)", func(v *vrVerifyInput) {
			v.urethFlags += " --unicity.fee-collector 0x00000000000000000000000000000000000000fd"
		}},
		{"ureth: pinned value in space form (legit, should pass)", func(v *vrVerifyInput) {
			v.urethFlags = replaceFlag(v.urethFlags, "--unicity.h-records=", "--unicity.h-records 32")
		}},
		{"ureth: leading-zero max-gas (clap would read the same)", func(v *vrVerifyInput) {
			v.urethFlags = replaceFlag(v.urethFlags, "--unicity.max-gas=", "--unicity.max-gas=0184729388")
		}},
		{"ureth: +sign floor (clap u64 accepts +)", func(v *vrVerifyInput) { v.urethFlags += " --unicity.base-fee-floor=+1000000" }},
		{"ureth: bool flag swallows the floor's value", func(v *vrVerifyInput) {
			v.urethFlags += " --unicity.no-proof-source 2000000"
		}},
		{"ureth: short flag -vvv", func(v *vrVerifyInput) { v.urethFlags += " -vvv" }},
		{"ureth: companion retention depth 1", func(v *vrVerifyInput) { v.urethFlags += " --unicity.companion-retention-depth=1" }},
		// ---- self-consistent generations of an out-of-policy plan (input + alloc rewritten together)
		{"plan: nMin 0 > policy (input + alloc)", func(v *vrVerifyInput) { v.input.Limits.NMin = 0; opusRewriteState(t, v) }},
		{"plan: nMax 17 > MaxCommittee (input + alloc)", func(v *vrVerifyInput) { v.input.Limits.NMax = 17; opusRewriteState(t, v) }},
		{"plan: vMax 0 (input + alloc)", func(v *vrVerifyInput) { v.input.Limits.VMax = 0; opusRewriteState(t, v) }},
		{"plan: epochStartProgress 99 (input + alloc)", func(v *vrVerifyInput) { v.input.EpochStartProgress = 99; opusRewriteState(t, v) }},
		{"plan: fee floor 0 everywhere (input + alloc + ureth)", func(v *vrVerifyInput) {
			v.input.Fees.BaseFeeFloor = 0
			opusRewriteState(t, v)
			v.urethFlags += " --unicity.base-fee-floor=0"
		}},
		{"plan: change denominator 0 everywhere (input + alloc + ureth)", func(v *vrVerifyInput) {
			v.input.Fees.ChangeDenominator = 0
			opusRewriteState(t, v)
			v.urethFlags += " --unicity.base-fee-change-denominator=0"
		}},
		{"plan: zero fee collector everywhere (input + alloc + nodes)", func(v *vrVerifyInput) {
			v.input.Fees.FeeCollector = "0x0000000000000000000000000000000000000000"
			opusRewriteState(t, v)
			v.feeCollector = "0x0000000000000000000000000000000000000000"
		}},
		{"plan: owner 0 (input + alloc)", func(v *vrVerifyInput) {
			v.input.Identities[0].Owner = "0x0000000000000000000000000000000000000000"
			opusRewriteState(t, v)
		}},
		{"plan: governor signer = zero (input + alloc)", func(v *vrVerifyInput) {
			v.input.GovernorSigners[0] = "0x0000000000000000000000000000000000000000"
			sort.Strings(v.input.GovernorSigners)
			opusRewriteState(t, v)
		}},
		{"plan: unchanged rewrite (control of the rewrite helper, should pass)", func(v *vrVerifyInput) { opusRewriteState(t, v) }},
		// ---- reports and other files
		{"deployment: moduleTag", func(v *vrVerifyInput) { v.deployment.ModuleTag = flipHex(v.deployment.ModuleTag) }},
		{"deployment: lastAcked", func(v *vrVerifyInput) { v.deployment.LastAcked = flipHex(v.deployment.LastAcked) }},
		{"deployment: composer address case", func(v *vrVerifyInput) { v.deployment.Composer = strings.ToLower(v.deployment.Composer) }},
		{"input: vMax only", func(v *vrVerifyInput) { v.input.Limits.VMax = 15 }},
		{"input: epochStartProgress only", func(v *vrVerifyInput) { v.input.EpochStartProgress = 1 }},
		{"input: network word only", func(v *vrVerifyInput) { v.input.Network = flipHex(v.input.Network) }},
		{"input: identity 3 rootKey case (benign?)", func(v *vrVerifyInput) {
			v.input.Identities[2].RootKey = strings.ToUpper(v.input.Identities[2].RootKey[:2]) + v.input.Identities[2].RootKey[2:]
		}},
		{"identities: exposure digest of #2", func(v *vrVerifyInput) {
			v.identities[1].ExposureDigest = bytes.Clone(v.identities[1].ExposureDigest)
			v.identities[1].ExposureDigest[31] ^= 1
		}},
		{"identities: weight of #1", func(v *vrVerifyInput) { v.identities[0].Weight++ }},
		{"fresh: elect +1 (still covered, should pass)", func(v *vrVerifyInput) { v.fresh.Elect++ }},
		{"fresh: source string", func(v *vrVerifyInput) { v.fresh.Source = "anything" }},
		{"profile measurement: combined name", func(v *vrVerifyInput) {
			m := *v.profileFile.VRHookMeasurement
			m.Combined = append(m.Combined[:0:0], m.Combined...)
			m.Combined[0].Name = "x"
			v.profileFile.VRHookMeasurement = &m
		}},
		{"PDR: continuity_max_distance 1/3", func(v *vrVerifyInput) { v.full.PartitionParams["continuity_max_distance"] = "1/3" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := vrFixtureInput(t)
			_, err := vrVerify(v)
			require.NoError(t, err, "the unmodified control passes")
			v = vrFixtureInput(t)
			tc.edit(&v)
			_, err = vrVerify(v)
			if benignR2[tc.name] {
				require.NoError(t, err, "a benign variant verifies")
				return
			}
			require.ErrorIs(t, err, ErrVRGenesis)
			t.Log(strings.SplitN(err.Error(), "\n", 2)[0])
		})
	}
}
