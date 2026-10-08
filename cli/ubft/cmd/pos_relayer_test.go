package cmd

import (
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
