package cmd

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/registrygenesis"
)

// The cross-repository genesis vector (see xrepo/README.md). The inputs (a plan, the genesis trust base and the FULL shard
// configuration) and the file `ubft pos-relayer genesis --out-contracts` writes for them are committed; unicity-pos-contracts
// parses a copy of that file with its genesis script's own decoder (XRepoGenesis.t.sol). XREPO_UPDATE=1 rewrites the output, and
// creates the inputs when they are missing.
const xrepoGenesisDir = "../../../xrepo/testdata/genesis"

func TestTheContractsGenesisInputIsTheCommittedVectorAndNamesTheRootsGenesisAssignment(t *testing.T) {
	planPath, tbPath, confPath := filepath.Join(xrepoGenesisDir, "plan.json"), filepath.Join(xrepoGenesisDir, "trust-base.json"), filepath.Join(xrepoGenesisDir, "shard-conf-full.json")
	outPath := filepath.Join(xrepoGenesisDir, "contracts-genesis.json")
	update := os.Getenv("XREPO_UPDATE") == "1"
	if _, err := os.Stat(planPath); update && os.IsNotExist(err) {
		d := newGenesisDeployment(t)
		full := *d.conf
		full.PartitionParams = map[string]string{registrygenesis.GenesisParam: strings.Repeat("ab", 32)}
		for k, v := range d.conf.PartitionParams {
			full.PartitionParams[k] = v
		}
		require.NoError(t, writeJSONFile(planPath, posPlan(d)))
		require.NoError(t, writeJSONFile(tbPath, d.tb))
		require.NoError(t, writeJSONFile(confPath, &full))
	}
	raw, err := os.ReadFile(planPath)
	require.NoError(t, err)
	var plan posGenesisPlan
	require.NoError(t, json.Unmarshal(raw, &plan))
	tb, err := readTrustBase(tbPath)
	require.NoError(t, err)
	conf, err := readShardConf(confPath)
	require.NoError(t, err)
	require.NoError(t, requireFullShardConf(conf), "the vector is over the FULL configuration, the one the roots install")

	ids, assignment, out, err := buildPosGenesis(plan, tb, conf)
	require.NoError(t, err)
	got, err := json.MarshalIndent(out, "", "  ")
	require.NoError(t, err)
	got = append(got, '\n')
	if update {
		require.NoError(t, os.WriteFile(outPath, got, 0o644))
	}
	want, err := os.ReadFile(outPath)
	require.NoError(t, err)
	require.Equal(t, string(want), string(got), "the contracts genesis input changed: regenerate with XREPO_UPDATE=1 and replace the copy in unicity-pos-contracts")

	// The id in the file is the one the root will name in the first CloseLiability: the custody key of the genesis epoch, as the
	// root's own store derives it from the installed configuration and the recorded identities.
	d := genesisDeployment{tb: tb, conf: conf}
	o := d.orchestration(t)
	require.NoError(t, o.SetGenesisIdentities(conf.PartitionID, conf.ShardID, ids))
	rootsID, err := o.CustodyAssignmentID(conf.PartitionID, conf.ShardID, conf.Epoch)
	require.NoError(t, err)
	require.Equal(t, assignment, rootsID, "the root closes the genesis epoch under the id custody is deployed with")
	require.Equal(t, "0x"+hex.EncodeToString(rootsID[:]), out.AssignmentID)

	// The same plan over the BASE configuration (no seal_registry_genesis) is another id: the file must never be prepared from it.
	base := *conf
	base.PartitionParams = map[string]string{}
	for k, v := range conf.PartitionParams {
		if k != registrygenesis.GenesisParam {
			base.PartitionParams[k] = v
		}
	}
	_, fromBase, _, err := buildPosGenesis(plan, tb, &base)
	require.NoError(t, err)
	require.NotEqual(t, assignment, fromBase)
	require.ErrorIs(t, requireFullShardConf(&base), ErrPosRelayer)
}
