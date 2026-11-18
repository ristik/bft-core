package cmd

// The round-2 re-review mutations of #1182 (astra, briefs/astra-review-vt14-r2-answer.md), permanent.

import (
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/vrschema"
)

// A self-consistent generation with a zero network word (VR's constructor refuses it: BadGenesis(1)) is refused by the plan and by verify.
func TestAZeroNetworkWordIsRefusedByThePlanAndVerify(t *testing.T) {
	v := vrFixtureInput(t)
	_, err := vrVerify(v)
	require.NoError(t, err, "unmodified control")
	v.input.Network = "0x" + strings.Repeat("00", 32)
	v.deployment.NetworkWord = v.input.Network
	for i := range v.identities {
		e := vrschema.PoaExposureDigest(vrschema.Word{}, vrschema.U64(v.input.ChainID), vrschema.ValidatorRegistry, vrschema.GenesisResult, uint64(i+1))
		v.identities[i].ExposureDigest = append([]byte(nil), e[:]...)
	}
	opusRewriteState(t, &v)
	require.ErrorIs(t, vrReplan(v), ErrVRGenesis, "the plan refuses the zero network")
	dep, err := vrVerify(v)
	require.ErrorIs(t, err, ErrVRGenesis)
	require.Equal(t, vrRootDeployment{}, dep)
}

// Listed funded accounts are checked in both directions, and none may take a reserved genesis account.
func TestFundedAccountsAreExactInBothDirections(t *testing.T) {
	a := common.HexToAddress("0x000000000000000000000000000000000000beef")
	funded := func(t *testing.T) vrVerifyInput {
		v := vrDevFixtureInput(t) // funded accounts are a development generation's premine
		v.funded[a] = vrschema.U64(123)
		editGenesis(t, &v, func(g map[string]any) { g["alloc"].(map[string]any)[a.Hex()] = map[string]any{"balance": "0x7b"} })
		return v
	}
	v := funded(t)
	_, err := vrVerify(v)
	require.NoError(t, err, "an explicitly funded account, allocated as listed")
	for name, edit := range map[string]func(*vrVerifyInput){
		"the listed account disappears": func(v *vrVerifyInput) {
			editGenesis(t, v, func(g map[string]any) { delete(g["alloc"].(map[string]any), a.Hex()) })
		},
		"another balance":       func(v *vrVerifyInput) { v.funded[a] = vrschema.U64(124) },
		"a listed SealRegistry": func(v *vrVerifyInput) { v.funded[common.Address(vrschema.SealRegistry)] = vrschema.U64(1) },
		"a listed VR role":      func(v *vrVerifyInput) { v.funded[vrGenesisAddress(7)] = vrschema.U64(1) },
		"the system caller":     func(v *vrVerifyInput) { v.funded[vrGenesisAddress(1)] = vrschema.U64(1) },
	} {
		t.Run(name, func(t *testing.T) {
			v := funded(t)
			edit(&v)
			_, err := vrVerify(v)
			require.ErrorIs(t, err, ErrVRGenesis)
		})
	}
}

// Every admitted ureth option is held to the client's parsing (u64, address, hash) and to its retention rule
// (depth >= ACCOUNTING_WINDOW + repair limit, default 64): a vector the client refuses at start-up is not certified.
func TestTheUrethVectorIsOneTheClientStartsWith(t *testing.T) {
	for arg, ok := range map[string]bool{
		"--unicity.companion-retention-depth=banana":                                                   false,
		"--unicity.accounting-repair-limit=banana":                                                     false,
		"--unicity.companion-retention-depth=1":                                                        false,
		"--unicity.companion-retention-depth=79":                                                       false,
		"--unicity.companion-retention-depth=80":                                                       true,
		"--unicity.companion-retention-depth=+80":                                                      true,
		"--unicity.companion-retention-depth=-80":                                                      false,
		"--unicity.companion-retention-depth 18446744073709551616":                                     false,
		"--unicity.accounting-repair-limit=10 --unicity.companion-retention-depth=26":                  true,
		"--unicity.accounting-repair-limit=10 --unicity.companion-retention-depth=25":                  false,
		"--unicity.accounting-repair-limit=18446744073709551615 --unicity.companion-retention-depth=1": false,
		"--unicity.accounting-repair-limit=7":                                                          true,
		"--unicity.no-proof-source":                                                                    true,
	} {
		t.Run(arg, func(t *testing.T) {
			v := vrFixtureInput(t)
			_, err := vrVerify(v)
			require.NoError(t, err)
			v.urethFlags += " " + arg
			_, err = vrVerify(v)
			if ok {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, ErrVRGenesis)
			}
		})
	}
}
