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

func deploymentJSON(word, chain, custody string) string {
	return `{"networkWord":"` + word + `","chainId":"` + chain + `","custody":"` + custody + `"}`
}

func TestLoadPosDeploymentPinsTheCustodyIdentity(t *testing.T) {
	d, err := loadPosDeployment(writeDeployment(t, deploymentJSON(goodWord, "31337", goodCustody)), 5)
	require.NoError(t, err)
	require.EqualValues(t, 5, d.RootNetwork)
	require.Equal(t, byte(0x11), d.NetworkWord[0], "the manifest word, not re-hashed")
	require.Equal(t, byte(0x8d), d.Custody[0])
	require.Equal(t, [2]byte{0x7a, 0x69}, [2]byte{d.ChainID[30], d.ChainID[31]}, "31337 = 0x7a69, big-endian in a 32-byte word")
	require.Equal(t, make([]byte, 30), d.ChainID[:30])
	hexChain, err := loadPosDeployment(writeDeployment(t, deploymentJSON(goodWord, "0x7a69", goodCustody)), 5)
	require.NoError(t, err)
	require.Equal(t, d, hexChain)
	big := "0x" + strings.Repeat("ff", 32)
	d, err = loadPosDeployment(writeDeployment(t, deploymentJSON(goodWord, big, goodCustody)), 5)
	require.NoError(t, err)
	require.Equal(t, strings.Repeat("\xff", 32), string(d.ChainID[:]))
}

func TestLoadPosDeploymentRefusals(t *testing.T) {
	zeroWord := "0x" + strings.Repeat("00", 32)
	zeroCustody := "0x" + strings.Repeat("00", 20)
	for name, body := range map[string]string{
		"a short network word":    deploymentJSON("0x1122", "1", goodCustody),
		"a zero network word":     deploymentJSON(zeroWord, "1", goodCustody),
		"not hex":                 deploymentJSON("0x"+strings.Repeat("zz", 32), "1", goodCustody),
		"a short custody":         deploymentJSON(goodWord, "1", "0x1122"),
		"a zero custody":          deploymentJSON(goodWord, "1", zeroCustody),
		"a zero chain id":         deploymentJSON(goodWord, "0", goodCustody),
		"a negative chain id":     deploymentJSON(goodWord, "-1", goodCustody),
		"a chain id above 2^256":  deploymentJSON(goodWord, "0x1"+strings.Repeat("00", 32), goodCustody),
		"a chain id that is text": deploymentJSON(goodWord, "main", goodCustody),
		"an unknown field":        `{"networkWord":"` + goodWord + `","chainId":"1","custody":"` + goodCustody + `","x":1}`,
		"not json":                "{",
		"empty":                   "",
	} {
		_, err := loadPosDeployment(writeDeployment(t, body), 5)
		require.ErrorIs(t, err, ErrPosDeployment, name)
	}
	_, err := loadPosDeployment(filepath.Join(t.TempDir(), "missing.json"), 5)
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

func TestEnablePosClosureRefusesACommitteeThatCannotDistributeTheWitness(t *testing.T) {
	path := writeDeployment(t, deploymentJSON(goodWord, "1", goodCustody))
	nodes := func(n int) []*types.NodeInfo {
		out := make([]*types.NodeInfo, n)
		for i := range out {
			out[i] = &types.NodeInfo{NodeID: string(rune('a' + i))}
		}
		return out
	}
	err := enablePosClosure(nil, nil, nil, &types.RootTrustBaseV1{NetworkID: 5, RootNodes: nodes(2)}, nil, path, false)
	require.ErrorIs(t, err, ErrPosDeployment)
	require.NotErrorIs(t, err, ErrGenesisIdentities, "refused for the committee size, before any shard is looked at")
	// one root node passes the guard (and is then refused for the missing coupled shard, the next check)
	err = enablePosClosure(nil, nil, nil, &types.RootTrustBaseV1{NetworkID: 5, RootNodes: nodes(1)}, nil, path, false)
	require.ErrorIs(t, err, ErrGenesisIdentities)
}
