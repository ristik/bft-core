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
		"the live index emptied": mutate(func(a vrAllocAccount) vrAllocAccount {
			return setSlot(a, vrschema.U64(vrElectionIndexLenSlot), vrschema.U64(0))
		}),
	}
	for name, a := range cases {
		require.ErrorIs(t, vrCheckPosElection(in, d, network, a), ErrVRGenesis, name)
	}
}
