package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"
)

func writeDeployment(t *testing.T, body string) string {
	p := filepath.Join(t.TempDir(), "pos.json")
	require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
	return p
}

const (
	goodWord    = "0x" + "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff"
	goodCustody = "0x8d2C17FAd02B7bb64139109c6533b7C2b9CADb81"
)

const (
	goodCode     = "0x" + "aa00bb11cc22dd33ee44ff5500661177aa00bb11cc22dd33ee44ff5500661177"
	goodRegCode  = "0x" + "bb00cc11dd22ee33ff4400551166227700bb11cc22dd33ee44ff550066117722"
	goodRegistry = "0xff00000000000000000000000000000000000002"
)

func deploymentJSON(word, chain, custody string) string {
	return deploymentJSONWith(word, chain, custody, goodCode, goodRegistry, goodRegCode)
}

func deploymentJSONWith(word, chain, custody, custodyCode, registry, registryCode string) string {
	return `{"networkWord":"` + word + `","chainId":"` + chain + `","custody":"` + custody + `","custodyCodeHash":"` + custodyCode +
		`","registry":"` + registry + `","registryCodeHash":"` + registryCode + `"}`
}

func TestLoadPosDeploymentPinsTheCustodyIdentity(t *testing.T) {
	d, pins, err := loadPosDeployment(writeDeployment(t, deploymentJSON(goodWord, "31337", goodCustody)), 5)
	require.NoError(t, err)
	require.EqualValues(t, 5, d.RootNetwork)
	require.Equal(t, byte(0x11), d.NetworkWord[0], "the manifest word, not re-hashed")
	require.Equal(t, byte(0x8d), d.Custody[0])
	require.Equal(t, d.Custody, pins.Custody)
	require.Equal(t, d.NetworkWord, pins.NetworkWord)
	require.Equal(t, byte(0xaa), pins.CustodyCode[0])
	require.Equal(t, byte(0xbb), pins.RegistryCode[0])
	require.Equal(t, byte(0xff), pins.Registry[0])
	require.Equal(t, byte(0x02), pins.Registry[19])
	require.NotEqual(t, pins.Registry[:], d.Custody[:])
	require.Equal(t, [2]byte{0x7a, 0x69}, [2]byte{d.ChainID[30], d.ChainID[31]}, "31337 = 0x7a69, big-endian in a 32-byte word")
	require.Equal(t, make([]byte, 30), d.ChainID[:30])
	hexChain, _, err := loadPosDeployment(writeDeployment(t, deploymentJSON(goodWord, "0x7a69", goodCustody)), 5)
	require.NoError(t, err)
	require.Equal(t, d, hexChain)
	big := "0x" + strings.Repeat("ff", 32)
	d, _, err = loadPosDeployment(writeDeployment(t, deploymentJSON(goodWord, big, goodCustody)), 5)
	require.NoError(t, err)
	require.Equal(t, strings.Repeat("\xff", 32), string(d.ChainID[:]))
}

func TestLoadPosDeploymentRefusals(t *testing.T) {
	zeroWord := "0x" + strings.Repeat("00", 32)
	zeroCustody := "0x" + strings.Repeat("00", 20)
	for name, body := range map[string]string{
		"a short network word":      deploymentJSON("0x1122", "1", goodCustody),
		"a zero network word":       deploymentJSON(zeroWord, "1", goodCustody),
		"not hex":                   deploymentJSON("0x"+strings.Repeat("zz", 32), "1", goodCustody),
		"a short custody":           deploymentJSON(goodWord, "1", "0x1122"),
		"a zero custody":            deploymentJSON(goodWord, "1", zeroCustody),
		"a zero chain id":           deploymentJSON(goodWord, "0", goodCustody),
		"a negative chain id":       deploymentJSON(goodWord, "-1", goodCustody),
		"a chain id above 2^256":    deploymentJSON(goodWord, "0x1"+strings.Repeat("00", 32), goodCustody),
		"a chain id that is text":   deploymentJSON(goodWord, "main", goodCustody),
		"a short custody code hash": deploymentJSONWith(goodWord, "1", goodCustody, "0x1122", goodRegistry, goodCode),
		"a zero custody code hash":  deploymentJSONWith(goodWord, "1", goodCustody, "0x"+strings.Repeat("00", 32), goodRegistry, goodCode),
		"a short registry":          deploymentJSONWith(goodWord, "1", goodCustody, goodCode, "0x1122", goodCode),
		"a zero registry":           deploymentJSONWith(goodWord, "1", goodCustody, goodCode, zeroCustody, goodCode),
		"a short registry code":     deploymentJSONWith(goodWord, "1", goodCustody, goodCode, goodRegistry, "0x1122"),
		"a zero registry code":      deploymentJSONWith(goodWord, "1", goodCustody, goodCode, goodRegistry, "0x"+strings.Repeat("00", 32)),
		"the pins omitted":          `{"networkWord":"` + goodWord + `","chainId":"1","custody":"` + goodCustody + `"}`,
		"an unknown field":          `{"networkWord":"` + goodWord + `","chainId":"1","custody":"` + goodCustody + `","x":1}`,
		"not json":                  "{",
		"empty":                     "",
	} {
		_, _, err := loadPosDeployment(writeDeployment(t, body), 5)
		require.ErrorIs(t, err, ErrPosDeployment, name)
	}
	_, _, err := loadPosDeployment(filepath.Join(t.TempDir(), "missing.json"), 5)
	require.ErrorIs(t, err, ErrPosDeployment)
}

func TestEnablePosClosureRefusesAProofOfAuthorityGenesisAndAnUncoupledOne(t *testing.T) {
	path := writeDeployment(t, deploymentJSON(goodWord, "1", goodCustody))
	err := enablePosClosure(nil, nil, nil, &types.RootTrustBaseV1{NetworkID: 5}, nil, path, true)
	require.ErrorIs(t, err, ErrPosDeployment, "operator-assigned staking ids do not fit custody")
	require.NotErrorIs(t, err, ErrGenesisIdentities, "refused for being proof of authority, before anything else is read")
	err = enablePosClosure(nil, nil, nil, &types.RootTrustBaseV1{NetworkID: 5}, nil, path, false)
	require.ErrorIs(t, err, ErrPosDeployment, "no genesis shard has coupled changes")
	require.ErrorIs(t, err, ErrGenesisIdentities)
	err = enablePosClosure(nil, nil, nil, &types.RootTrustBaseV1{NetworkID: 5}, nil, filepath.Join(t.TempDir(), "none"), false)
	require.ErrorIs(t, err, ErrPosDeployment)
}

func TestEnablePosClosureAcceptsACommitteeOfSeveralRootNodes(t *testing.T) {
	path := writeDeployment(t, deploymentJSON(goodWord, "1", goodCustody))
	nodes := func(n int) []*types.NodeInfo {
		out := make([]*types.NodeInfo, n)
		for i := range out {
			out[i] = &types.NodeInfo{NodeID: string(rune('a' + i))}
		}
		return out
	}
	// the witnesses are pulled by hash from the other root nodes, so the committee size is no reason to refuse: the next check, the
	// coupled genesis shard, is the one that answers for every size
	for _, n := range []int{1, 2, 4} {
		err := enablePosClosure(nil, nil, nil, &types.RootTrustBaseV1{NetworkID: 5, RootNodes: nodes(n)}, nil, path, false)
		require.ErrorIs(t, err, ErrGenesisIdentities, "%d root nodes", n)
	}
}
