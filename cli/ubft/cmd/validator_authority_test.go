package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/vrschema"
)

const policyKey = "0x0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

func policyJSON(extra string) string {
	return `{"network":"0x` + strings.Repeat("11", 32) + `","chainId":3,"registry":"0xff00000000000000000000000000000000000003","authorized":[` +
		`{"action":"register","owner":"0x00000000000000000000000000000000000000aa","rootNodeId":"r","rootKey":"` + policyKey + `","payee":"0x00000000000000000000000000000000000000bb"}` + extra + `]}`
}

// The operator-facing policy file: what it reads, and what it refuses.
func TestRegistrationPolicyFile(t *testing.T) {
	read := func(content string) error {
		p := filepath.Join(t.TempDir(), "policy.json")
		require.NoError(t, os.WriteFile(p, []byte(content), 0o600))
		_, err := readRegistrationPolicy(p)
		return err
	}
	p := filepath.Join(t.TempDir(), "policy.json")
	require.NoError(t, os.WriteFile(p, []byte(policyJSON(`,{"action":"binding","id":5,"owner":"0x00000000000000000000000000000000000000aa","rootNodeId":"r","rootKey":"`+policyKey+`","payee":"0x00000000000000000000000000000000000000cc"}`)), 0o600))
	got, err := readRegistrationPolicy(p)
	require.NoError(t, err)
	require.Len(t, got.Authorized, 2)
	require.Equal(t, vrschema.RegisterDomainText, got.Authorized[0].Domain)
	require.Equal(t, vrschema.BindingDomainText, got.Authorized[1].Domain)
	require.Equal(t, uint64(5), got.Authorized[1].ID)
	require.Equal(t, vrschema.U64(3), got.Deployment.ChainID)

	require.NoError(t, read(policyJSON("")))
	require.Error(t, read(policyJSON("")+` {}`), "trailing data")
	require.Error(t, read(strings.Replace(policyJSON(""), `"action":"register"`, `"action":"exit"`, 1)), "unknown action")
	require.Error(t, read(strings.Replace(policyJSON(""), `"chainId":3,`, `"chainId":3,"extra":1,`, 1)), "unknown field")
	require.Error(t, read(strings.Replace(policyJSON(""), `0xff00000000000000000000000000000000000003`, `zz`, 1)), "bad registry")
	require.Error(t, read(strings.Replace(policyJSON(""), `0x`+strings.Repeat("11", 32), `0x11`, 1)), "short network")
}

// A config naming both holders of the EVM key is refused.
func TestValidatorConfigRefusesBothEVMHolders(t *testing.T) {
	home := t.TempDir()
	out, err := runValidator(t, home, "init", "--rpc", "http://127.0.0.1:1")
	require.NoError(t, err, out)
	c := readConfig(t, home)
	c.EVMAuthority = &evmAuthorityConfig{Socket: "s", Credential: "c", NodeInfo: "n"}
	b, err := configBytes(c)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(home, validatorConfigFile), b, 0o600))
	out, err = runValidator(t, home, "status")
	require.ErrorContains(t, err, "two holders", out)
}
