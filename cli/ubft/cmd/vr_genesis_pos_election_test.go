package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/vrschema"
)

// testdata/vr-genesis-pos is a PoS generation's contracts genesis (script/vr-pos-genesis.sh: plan input, deployment report, alloc) as the dev
// server produced it, with limits 4,4,5, a cadence of 400 rounds and 300 seconds.
func posElectionFixture(t *testing.T) (vrGenesisInput, vrDeploymentFile, map[common.Address]vrAllocAccount) {
	t.Helper()
	read := func(name string, v any) {
		raw, err := os.ReadFile(filepath.Join("testdata", "vr-genesis-pos", name))
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(raw, v))
	}
	var in vrGenesisInput
	var d vrDeploymentFile
	var raw map[string]vrAllocAccount
	read("input.json", &in)
	read("deployment.json", &d)
	read("alloc.json", &raw)
	alloc := map[common.Address]vrAllocAccount{}
	for k, v := range raw {
		alloc[common.HexToAddress(k)] = v
	}
	return in, d, alloc
}

func TestPosElectionInitializationIsBoundToThePlan(t *testing.T) {
	in, d, alloc := posElectionFixture(t)
	network, err := vrHex("network", in.Network, 32)
	require.NoError(t, err)
	election := common.HexToAddress(d.Election)
	require.NoError(t, vrCheckPosElection(in, d, network, alloc), "the generated alloc passes")

	mutate := func(f func(a vrAllocAccount) vrAllocAccount) map[common.Address]vrAllocAccount {
		out := map[common.Address]vrAllocAccount{}
		for k, v := range alloc {
			out[k] = v
		}
		out[election] = f(alloc[election])
		return out
	}
	setSlot := func(a vrAllocAccount, slot vrschema.Word, v vrschema.Word) vrAllocAccount {
		st := map[string]string{}
		for k, x := range a.Storage {
			st[k] = x
		}
		for k := range st {
			if strings.EqualFold(strings.TrimPrefix(k, "0x"), lowerHex(slot[:])[2:]) {
				delete(st, k)
			}
		}
		st[lowerHex(slot[:])] = lowerHex(v[:])
		a.Storage = st
		return a
	}
	cases := map[string]map[common.Address]vrAllocAccount{
		"no election storage at all (code kept)": mutate(func(a vrAllocAccount) vrAllocAccount { a.Storage = nil; return a }),
		"not initialized": mutate(func(a vrAllocAccount) vrAllocAccount {
			return setSlot(a, vrschema.U64(vrElectionInitializedSlot), vrschema.U64(0))
		}),
		"another network word": mutate(func(a vrAllocAccount) vrAllocAccount {
			return setSlot(a, vrschema.U64(vrElectionNetworkSlot), vrschema.U64(9))
		}),
		"another cadence": mutate(func(a vrAllocAccount) vrAllocAccount {
			return setSlot(a, vrschema.U64(vrElectionCadenceSlot), vrschema.U64(1))
		}),
		"another registry": mutate(func(a vrAllocAccount) vrAllocAccount {
			return setSlot(a, vrschema.U64(vrElectionRegistrySlot), vrschema.U64(1))
		}),
		"a staged binding dropped": mutate(func(a vrAllocAccount) vrAllocAccount {
			base := vrschema.MapSlot(vrschema.U64(1), vrschema.MapSlot(vrschema.U64(2), vrschema.U64(vrElectionStagedSlot)))
			return setSlot(a, vrschema.SlotAdd(base, 7), vrschema.Word{})
		}),
		"the index entries removed (length kept)": mutate(func(a vrAllocAccount) vrAllocAccount {
			return setSlot(a, vrschema.Keccak(wb(vrschema.U64(vrElectionIndexLenSlot))), vrschema.Word{})
		}),
		"a staged root key's bytes removed (hash kept)": mutate(func(a vrAllocAccount) vrAllocAccount {
			base := vrschema.MapSlot(vrschema.U64(1), vrschema.MapSlot(vrschema.U64(1), vrschema.U64(vrElectionStagedSlot)))
			return setSlot(a, vrschema.Keccak(wb(vrschema.SlotAdd(base, 1))), vrschema.Word{})
		}),
		"the reverse index position removed": mutate(func(a vrAllocAccount) vrAllocAccount {
			return setSlot(a, vrschema.MapSlot(vrschema.U64(3), vrschema.U64(vrElectionPositionSlot)), vrschema.Word{})
		}),
		"the eligibility reader link removed": mutate(func(a vrAllocAccount) vrAllocAccount {
			return setSlot(a, vrschema.U64(vrElectionReaderSlot), vrschema.Word{})
		}),
		"an extra slot":         mutate(func(a vrAllocAccount) vrAllocAccount { return setSlot(a, vrschema.U64(0x1234), vrschema.U64(1)) }),
		"another policy source": mutate(func(a vrAllocAccount) vrAllocAccount { return setSlot(a, vrschema.U64(7), vrschema.U64(7)) }),
		"another maxBatch": mutate(func(a vrAllocAccount) vrAllocAccount {
			return setSlot(a, vrschema.U64(vrElectionMaxBatchSlot), vrschema.U64(1))
		}),
		"no manifest hash": mutate(func(a vrAllocAccount) vrAllocAccount { return setSlot(a, vrschema.U64(1), vrschema.Word{}) }),
		"the live index emptied": mutate(func(a vrAllocAccount) vrAllocAccount {
			return setSlot(a, vrschema.U64(vrElectionIndexLenSlot), vrschema.U64(0))
		}),
	}
	for name, a := range cases {
		require.ErrorIs(t, vrCheckPosElection(in, d, network, a), ErrVRGenesis, name)
	}
}

// custody's genesis storage is the plan's, slot for slot: the mutations a partial check would miss are refused.
func TestPosCustodyStorageIsBoundToThePlan(t *testing.T) {
	in, d, alloc := posElectionFixture(t)
	network, err := vrHex("network", in.Network, 32)
	require.NoError(t, err)
	custody := common.HexToAddress(d.Custody)
	require.NoError(t, vrCheckPosCustody(in, d, network, alloc), "the generated alloc passes")

	mutate := func(slot vrschema.Word, v vrschema.Word) map[common.Address]vrAllocAccount {
		out := map[common.Address]vrAllocAccount{}
		for k, x := range alloc {
			out[k] = x
		}
		a := alloc[custody]
		st := map[string]string{}
		for k, x := range a.Storage {
			if !strings.EqualFold(strings.TrimPrefix(k, "0x"), lowerHex(slot[:])[2:]) {
				st[k] = x
			}
		}
		st[lowerHex(slot[:])] = lowerHex(v[:])
		a.Storage = st
		out[custody] = a
		return out
	}
	one := vrschema.U64(1)
	eid := vrschema.PoaExposureDigest(vrschema.Word(network), vrschema.U64(in.ChainID), vrschema.ValidatorRegistry, vrschema.Word(mustHex32(t, in.Pos.AssignmentID)), 2)
	cursor := vrschema.LiabilityNS
	for name, a := range map[string]map[common.Address]vrAllocAccount{
		"initialized cleared (genesisStarted kept)": mutate(vrschema.U64(1), packed([3]uint64{0, 1, 1})),
		"a member digest":          mutate(vrschema.MapSlot(eid, vrschema.U64(40)), one),
		"a lot's remaining amount": mutate(vrschema.SlotAdd(vrschema.MapSlot(vrschema.U64(3), vrschema.U64(27)), 1), one),
		"the record cursor":        mutate(cursor, one),
		"an extra slot":            mutate(vrschema.U64(0x4321), one),
		"a position's owner":       mutate(vrschema.MapSlot(vrschema.U64(1), vrschema.U64(22)), one),
		"the exposure digest":      mutate(vrschema.SlotAdd(vrschema.MapSlot(vrschema.Word(mustHex32(t, in.Pos.AssignmentID)), vrschema.U64(32)), 5), one),
		"no manifest hash":         mutate(vrschema.U64(3), vrschema.Word{}),
	} {
		require.ErrorIs(t, vrCheckPosCustody(in, d, network, a), ErrVRGenesis, name)
	}
}

func mustHex32(t *testing.T, s string) [32]byte {
	b, err := vrHex("word", s, 32)
	require.NoError(t, err)
	return [32]byte(b)
}

// a genesis bond that does not fit a custody lot is an error, never a panic of the verifier
func TestPosCustodyOversizedBondIsRefused(t *testing.T) {
	in, d, alloc := posElectionFixture(t)
	network, err := vrHex("network", in.Network, 32)
	require.NoError(t, err)
	in.Identities = append([]vrInputIdentity(nil), in.Identities...)
	in.Identities[0].RawWeight = ^uint64(0)
	in.Pos.BondUnit = "340282366920938463463374607431768211455" // 2^128-1: the product overflows the 16-byte lot field
	require.NotPanics(t, func() {
		err = vrCheckPosCustody(in, d, network, alloc)
	})
	require.ErrorIs(t, err, ErrVRGenesis)
	require.ErrorContains(t, err, "uint128")
}
