package cmd

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
)

func TestPosRelayerInputs(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
		return p
	}
	key, err := readEVMKey(write("k", "0x"+strings.Repeat("11", 32)+"\n"))
	require.NoError(t, err)
	require.NotNil(t, key)
	for name, body := range map[string]string{"short": "0x1122", "not hex": strings.Repeat("zz", 32), "zero": strings.Repeat("00", 32), "empty": ""} {
		_, err := readEVMKey(write("bad", body))
		require.Error(t, err, name)
	}
	_, err = readEVMKey(filepath.Join(dir, "missing"))
	require.ErrorIs(t, err, ErrPosRelayer)

	p := evmassign.EVMPoP{ID: 3, EVMKey: []byte{2, 3}, Signature: []byte{4, 5}}
	back, err := toPoPJSON(p).pop()
	require.NoError(t, err)
	require.Equal(t, p, back)
	_, err = popJSON{ID: 1, EVMKey: "zz", Signature: "00"}.pop()
	require.ErrorIs(t, err, ErrPosRelayer)

	_, err = electionDeployment(writeDeployment(t, deploymentJSON(goodWord, "1", goodCustody)))
	require.ErrorIs(t, err, ErrPosRelayer, "a deployment without the election cannot take proofs")
	withElection := strings.TrimSuffix(deploymentJSON(goodWord, "1", goodCustody), "}") +
		`,"election":"0xff00000000000000000000000000000000000003","electionCodeHash":"` + goodCode + `"}`
	d, err := electionDeployment(writeDeployment(t, withElection))
	require.NoError(t, err)
	require.Equal(t, byte(3), d.Election[19])
	require.Equal(t, byte(0x8d), d.Custody[0])

	_, err = readCandidateFile(write("c", "0x00"))
	require.ErrorIs(t, err, ErrPosRelayer, "not a candidate")
}

func posPlan(d genesisDeployment) posGenesisPlan {
	plan := posGenesisPlan{BondUnit: "100000000000000000000"}
	for i := range d.tb.RootNodes {
		plan.Identities = append(plan.Identities, posGenesisIdentity{StakingID: uint64(i + 1),
			Owner: "0x" + strings.Repeat("a", 39) + string(rune('1'+i)), Withdrawal: "0x" + strings.Repeat("b", 39) + string(rune('1'+i)),
			Payee: "0x" + strings.Repeat("c", 39) + string(rune('1'+i)), BondUnits: 1,
			RootNodeID: d.tb.RootNodes[i].NodeID, RootKey: "0x" + hex.EncodeToString(d.tb.RootNodes[i].SigKey),
			EVMNodeID: d.conf.Validators[i].NodeID, EVMKey: "0x" + hex.EncodeToString(d.conf.Validators[i].SigKey), LotIDs: []uint64{uint64(i + 1)}})
	}
	return plan
}

func TestThePoSGenesisPlanYieldsTheRecordsTheRootSeedsAndTheContractsInput(t *testing.T) {
	d := newGenesisDeployment(t)
	plan := posPlan(d)
	ids, assignment, out, err := buildPosGenesis(plan, d.tb, d.conf)
	require.NoError(t, err)
	require.Len(t, ids, 4)
	require.Len(t, out.Identities, 4)
	require.Equal(t, "0x"+hex.EncodeToString(assignment[:]), out.AssignmentID)
	for i, id := range ids {
		cid, err := evmassign.CustodyID(id.StakingID)
		require.NoError(t, err)
		require.EqualValues(t, i+1, cid, "custody's id is the record's staking id")
		lots := evmassign.LotsDigest([]uint64{uint64(i + 1)})
		require.Equal(t, lots[:], id.ExposureDigest)
		word, err := evmassign.NodeIDWord(id.RootNodeID)
		require.NoError(t, err)
		require.Equal(t, "0x"+hex.EncodeToString(word[:]), out.Identities[i].RootNodeID)
		require.Equal(t, "100000000000000000000", out.Identities[i].Bond)
	}
	// the root accepts exactly these records as the baseline, and refuses a different set after it
	o := d.orchestration(t)
	require.NoError(t, o.SetGenesisIdentities(d.conf.PartitionID, d.conf.ShardID, ids))
	require.NoError(t, o.SetGenesisIdentities(d.conf.PartitionID, d.conf.ShardID, ids), "recording again is a no-op")

	// the assignment id is a function of the records: another payee, another id
	other := posPlan(d)
	other.Identities[0].Payee = "0x" + strings.Repeat("d", 40)
	_, assignment2, _, err := buildPosGenesis(other, d.tb, d.conf)
	require.NoError(t, err)
	require.NotEqual(t, assignment, assignment2)
}

func TestThePoSGenesisPlanRefusalsAreIsolated(t *testing.T) {
	d := newGenesisDeployment(t)
	for name, change := range map[string]func(*posGenesisPlan){
		"a zero bond unit":                        func(p *posGenesisPlan) { p.BondUnit = "0" },
		"a non-numeric bond unit":                 func(p *posGenesisPlan) { p.BondUnit = "x" },
		"ids not 1..N in order":                   func(p *posGenesisPlan) { p.Identities[0].StakingID = 9 },
		"no bond":                                 func(p *posGenesisPlan) { p.Identities[1].BondUnits = 0 },
		"no lots":                                 func(p *posGenesisPlan) { p.Identities[1].LotIDs = nil },
		"a short root key":                        func(p *posGenesisPlan) { p.Identities[2].RootKey = "0x02" },
		"a bad payee":                             func(p *posGenesisPlan) { p.Identities[2].Payee = "0x12" },
		"a weight that is not the trust base's":   func(p *posGenesisPlan) { p.Identities[3].BondUnits = 2 },
		"a root key that is not the trust base's": func(p *posGenesisPlan) { p.Identities[0].RootKey = p.Identities[1].RootKey },
		"a missing entity":                        func(p *posGenesisPlan) { p.Identities = p.Identities[:3] },
	} {
		plan := posPlan(d)
		change(&plan)
		_, _, _, err := buildPosGenesis(plan, d.tb, d.conf)
		require.Error(t, err, name)
	}
}
