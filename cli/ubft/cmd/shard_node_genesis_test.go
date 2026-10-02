package cmd

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/util"

	"github.com/unicitynetwork/bft-core/internal/testutils/certifiedchain"
	"github.com/unicitynetwork/bft-core/registrygenesis"
	"github.com/unicitynetwork/bft-core/registryproof"
)

// preparedGenesisFixture builds the two artifacts `ubft engine-api genesis` emits for a test shard
// conf: the finalized genesis JSON and the full shard configuration. The full configuration is
// returned as a value and written to a file, because both the loader test and the origin test need it.
func preparedGenesisFixture(t *testing.T, chainID uint64) (*types.PartitionDescriptionRecord, string, string) {
	return preparedGenesisFixtureAt(t, chainID, 1)
}

// preparedGenesisFixtureAt is preparedGenesisFixture for a genesis generated at the given root epoch.
func preparedGenesisFixtureAt(t *testing.T, chainID, rootEpoch uint64) (*types.PartitionDescriptionRecord, string, string) {
	t.Helper()
	base := certifiedchain.Config(3)
	base.PartitionParams = map[string]string{registrygenesis.ChainIDParam: strconv.FormatUint(chainID, 10)}
	art, err := registrygenesis.PinnedArtifact()
	require.NoError(t, err)
	pins := registrygenesis.Pins{
		RootEpoch: rootEpoch, RegistryCodeHash: art.CodeHash,
		SystemAddress: registrygenesis.SystemAddress, RegistryAddress: registryproof.RegistryAddress,
	}
	prepared, err := registrygenesis.PrepareGenesisJSON(base, pins, art, sourceGenesisJSON(t, chainID), registrygenesis.DefaultGenesisJSONLimits())
	require.NoError(t, err)
	full, err := prepared.FullConfig()
	require.NoError(t, err)

	dir := t.TempDir()
	genesisPath := filepath.Join(dir, "genesis.json")
	require.NoError(t, os.WriteFile(genesisPath, prepared.GenesisJSON(), 0600))
	fullPath := filepath.Join(dir, "full-shard-conf.json")
	require.NoError(t, util.WriteJsonFile(fullPath, full))
	return full, genesisPath, fullPath
}

// sourceGenesisJSON is a minimal standard genesis template with no allocation at the reserved
// addresses, which is what PrepareGenesisJSON accepts.
func sourceGenesisJSON(t *testing.T, chainID uint64) []byte {
	t.Helper()
	doc := map[string]any{
		"config": map[string]any{
			"chainId":        chainID,
			"homesteadBlock": 0, "eip150Block": 0, "eip155Block": 0, "eip158Block": 0,
			"byzantiumBlock": 0, "constantinopleBlock": 0, "petersburgBlock": 0,
			"istanbulBlock": 0, "berlinBlock": 0, "londonBlock": 0, "mergeNetsplitBlock": 0,
			"shanghaiTime": 0, "cancunTime": 0,
			"terminalTotalDifficulty": 0, "terminalTotalDifficultyPassed": true,
		},
		"nonce": "0x0", "timestamp": "0x0", "extraData": "0x",
		"gasLimit": "0x1c9c380", "difficulty": "0x0",
		"mixHash": common.Hash{}.Hex(), "coinbase": common.Address{}.Hex(),
		"alloc": map[string]any{}, "baseFeePerGas": "0x3b9aca00",
	}
	raw, err := json.Marshal(doc)
	require.NoError(t, err)
	return raw
}

// TestLoadGenesisOrigin_ValidatesAndBuildsTheBootstrapSnapshot is the unit's core assertion: the
// finalized artifact and the full shard configuration produce a checked origin, and the origin's own
// evidence verifies as its block-0 snapshot with no RPC.
func TestLoadGenesisOrigin_ValidatesAndBuildsTheBootstrapSnapshot(t *testing.T) {
	full, genesisPath, _ := preparedGenesisFixture(t, 1337)

	origin, bootstrap, err := loadGenesisOrigin(full, genesisPath, "", 1)
	require.NoError(t, err)
	require.True(t, origin.Valid())
	require.True(t, bootstrap.Valid())
	require.True(t, bootstrap.Genesis(), "the bootstrap snapshot must be block 0")
	require.EqualValues(t, 0, bootstrap.Number())
	require.Equal(t, origin.StateRoot(), bootstrap.StateRoot())
	require.Equal(t, origin.BlockHash(), bootstrap.ParentHash())
	t.Logf("origin identity=%s blockHash=%s stateRoot=%s; bootstrap valid=%t genesis=%t number=%d stateRoot=%s parentHash=%s",
		origin.Identity(), origin.BlockHash(), origin.StateRoot(),
		bootstrap.Valid(), bootstrap.Genesis(), bootstrap.Number(), bootstrap.StateRoot(), bootstrap.ParentHash())
}

// TestLoadGenesisOrigin_Refusals pins the three startup refusals the node can make here: a finalized
// artifact for another deployment, an expected identity that does not match, and a root epoch that
// does not reproduce the configuration's commitment.
func TestLoadGenesisOrigin_Refusals(t *testing.T) {
	full, genesisPath, _ := preparedGenesisFixture(t, 1337)

	t.Run("finalized artifact for another chain id", func(t *testing.T) {
		_, otherGenesis, _ := preparedGenesisFixture(t, 4242)
		_, _, err := loadGenesisOrigin(full, otherGenesis, "", 1)
		require.ErrorIs(t, err, registrygenesis.ErrChainIDMismatch)
	})

	t.Run("expected identity mismatch", func(t *testing.T) {
		_, _, err := loadGenesisOrigin(full, genesisPath, common.HexToHash("0x1111111111111111111111111111111111111111111111111111111111111111").Hex(), 1)
		require.ErrorIs(t, err, registrygenesis.ErrOriginIdentity)
	})

	t.Run("malformed expected identity", func(t *testing.T) {
		_, _, err := loadGenesisOrigin(full, genesisPath, "0xnot-a-hash", 1)
		require.ErrorContains(t, err, "parsing --expected-origin-identity")
	})

	t.Run("trust base before the genesis root epoch", func(t *testing.T) {
		_, _, err := loadGenesisOrigin(full, genesisPath, "", 0)
		require.ErrorIs(t, err, registrygenesis.ErrGenesisRootEpoch)
	})

	t.Run("malformed finalized artifact", func(t *testing.T) {
		bad := filepath.Join(t.TempDir(), "bad.json")
		require.NoError(t, os.WriteFile(bad, []byte("{}"), 0600))
		_, _, err := loadGenesisOrigin(full, bad, "", 1)
		require.ErrorIs(t, err, registrygenesis.ErrGenesisJSON)
	})
}

// TestLoadRunShardConf pins the input rules: the two artifacts are required together, and the full
// configuration is the node's one shard-configuration source.
func TestLoadRunShardConf(t *testing.T) {
	_, genesisPath, fullPath := preparedGenesisFixture(t, 1337)
	base := &baseFlags{}
	noFlag := func(string) bool { return false }

	_, err := loadRunShardConf(&shardNodeRunFlags{baseFlags: base, GenesisFile: "genesis.json"}, noFlag)
	require.ErrorContains(t, err, "--full-shard-conf")
	_, err = loadRunShardConf(&shardNodeRunFlags{baseFlags: base, FullShardConf: fullPath}, noFlag)
	require.ErrorContains(t, err, "--genesis")
	_, err = loadRunShardConf(&shardNodeRunFlags{baseFlags: base, ExpectedOriginIdentity: "0x01"}, noFlag)
	require.ErrorContains(t, err, "--expected-origin-identity requires")

	_, err = loadRunShardConf(&shardNodeRunFlags{baseFlags: base, GenesisFile: "genesis.json", FullShardConf: fullPath},
		func(name string) bool { return name == "shard-conf" })
	require.ErrorContains(t, err, "--shard-conf")

	conf, err := loadRunShardConf(&shardNodeRunFlags{baseFlags: base, GenesisFile: genesisPath, FullShardConf: fullPath}, noFlag)
	require.NoError(t, err)
	require.Contains(t, conf.PartitionParams, registrygenesis.GenesisParam, "the node runs on the full configuration")
}

func TestShardNodeRun_JournalFlagsForSealOrigin(t *testing.T) {
	full, genesisPath, _ := preparedGenesisFixture(t, 1337)
	origin, _, err := loadGenesisOrigin(full, genesisPath, "", 1)
	require.NoError(t, err)

	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"missing journal", []string{"--executor", "engine-api"}, "require --execution-journal"},
		{"journal enabled", []string{"--executor", "engine-api", "--execution-journal", "journal.db"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := shardNodeRunCmd(&baseFlags{})
			require.NoError(t, cmd.ParseFlags(tc.args))
			flags := &shardNodeRunFlags{Executor: cmd.Flags().Lookup("executor").Value.String(), ExecutionJournal: cmd.Flags().Lookup("execution-journal").Value.String(), EvidenceRecover: cmd.Flags().Lookup("evidence-recover").Value.String() == "true"}
			err := validateExecutionJournalFlags(flags, origin)
			if tc.want == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tc.want)
			}
		})
	}
}

// A node started under a later root epoch's trust base validates the genesis against the epoch the genesis was generated at, which it
// reads from the genesis. shardNodeRun passes only the trust base's epoch, as the bound, so a revert to pinning it cannot compile away
// this property.
func TestLoadGenesisOrigin_DerivesTheGenesisRootEpochAndBoundsItByTheTrustBase(t *testing.T) {
	full, genesisPath, _ := preparedGenesisFixture(t, 1337)
	for _, trustBaseEpoch := range []uint64{1, 3, 7} {
		_, _, err := loadGenesisOrigin(full, genesisPath, "", trustBaseEpoch)
		require.NoError(t, err, "the genesis at root epoch 1 under a trust base at epoch %d", trustBaseEpoch)
	}
	_, _, err := loadGenesisOrigin(full, genesisPath, "", 0)
	require.ErrorIs(t, err, registrygenesis.ErrGenesisRootEpoch, "a trust base before the genesis' epoch")
}

// shardNodeRun is the one caller: it must hand the trust base's epoch to the loader as the bound, and the loader derives the pin. An
// earlier revision passed the trust base's epoch AS the pin, which no unit test of the loader can see.
func TestShardNodeRunPassesTheTrustBasesEpochAsTheGenesisBound(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "shard_node_run.go", nil, 0)
	require.NoError(t, err)
	var found bool
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name == "loadGenesisOrigin" {
			continue // the layout-1 convenience wrapper passes a literal
		}
		ast.Inspect(fn, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if id, ok := call.Fun.(*ast.Ident); !ok || id.Name != "loadGenesisOriginLayout" {
				return true
			}
			require.Len(t, call.Args, 5)
			arg, ok := call.Args[3].(*ast.CallExpr)
			require.True(t, ok, "the fourth argument is the trust base's epoch")
			sel, ok := arg.Fun.(*ast.SelectorExpr)
			require.True(t, ok)
			require.Equal(t, "GetEpoch", sel.Sel.Name)
			found = true
			return true
		})
	}
	require.True(t, found, "shardNodeRun loads the genesis through loadGenesisOriginLayout")
}

func TestLoadGenesisOrigin_RefusesAGenesisAtRootEpochZeroOrBeyondTheTrustBase(t *testing.T) {
	full, path, _ := preparedGenesisFixtureAt(t, 1337, 5)
	_, _, err := loadGenesisOrigin(full, path, "", 7)
	require.NoError(t, err, "a genesis at epoch 5 under a trust base at epoch 7")
	_, _, err = loadGenesisOrigin(full, path, "", 5)
	require.NoError(t, err, "under a trust base at the genesis' own epoch")
	_, _, err = loadGenesisOrigin(full, path, "", 4)
	require.ErrorIs(t, err, registrygenesis.ErrGenesisRootEpoch, "the trust base has not reached the genesis' epoch")

	zero, zeroPath, _ := preparedGenesisFixtureAt(t, 1337, 0)
	_, _, err = loadGenesisOrigin(zero, zeroPath, "", 3)
	require.ErrorIs(t, err, registrygenesis.ErrGenesisRootEpoch, "root epoch zero is not a root epoch")
}
