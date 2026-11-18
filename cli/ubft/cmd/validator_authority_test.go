package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/vrschema"
	"github.com/unicitynetwork/bft-go-base/types"
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

// init selects an authority-held EVM key: no EVM key file is made, the config names the authority, --force keeps it, and an explicit
// --evm-keys switches back; two holders are refused.
func TestValidatorInitWithAnAuthority(t *testing.T) {
	dir := t.TempDir()
	info := filepath.Join(dir, "node-info.json")
	k, err := ethcrypto.GenerateKey()
	require.NoError(t, err)
	ni, err := json.Marshal(&types.NodeInfo{NodeID: "auth-node", SigKey: ethcrypto.CompressPubkey(&k.PublicKey), Stake: 1})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(info, ni, 0o600))
	cred := filepath.Join(dir, "operator.cred")
	require.NoError(t, os.WriteFile(cred, []byte(strings.Repeat("ab", 32)), 0o600))
	sock := filepath.Join(dir, "op.sock")
	home := t.TempDir()
	auth := []string{"--evm-authority-socket", sock, "--evm-authority-credential", cred, "--evm-authority-node-info", info}

	out, err := runValidator(t, home, append([]string{"init", "--rpc", "http://127.0.0.1:1"}, auth...)...)
	require.NoError(t, err, out)
	_, statErr := os.Stat(filepath.Join(home, "evm"))
	require.True(t, os.IsNotExist(statErr), "no EVM key file is created")
	c := readConfig(t, home)
	require.Equal(t, &evmAuthorityConfig{Socket: sock, Credential: cred, NodeInfo: info}, c.EVMAuthority)
	require.Empty(t, c.EVMKeys)
	require.NotContains(t, out, "EVM shard node")

	// --force without a holder keeps the authority
	out, err = runValidator(t, home, "init", "--rpc", "http://127.0.0.1:1", "--force")
	require.NoError(t, err, out)
	require.Equal(t, &evmAuthorityConfig{Socket: sock, Credential: cred, NodeInfo: info}, readConfig(t, home).EVMAuthority)
	_, statErr = os.Stat(filepath.Join(home, "evm"))
	require.True(t, os.IsNotExist(statErr))

	// two holders, or half an authority, are refused
	_, err = runValidator(t, home, append([]string{"init", "--rpc", "http://127.0.0.1:1", "--force", "--evm-keys", "evm/keys.json"}, auth...)...)
	require.ErrorIs(t, err, ErrValidator)
	_, err = runValidator(t, home, "init", "--rpc", "http://127.0.0.1:1", "--force", "--evm-authority-socket", sock)
	require.ErrorIs(t, err, ErrValidator)

	// the authority's credential and socket are in the alias checks: not a config to overwrite, not another service's key
	base := []string{"init", "--rpc", "http://127.0.0.1:1", "--force"}
	for name, extra := range map[string][]string{
		"the config is the credential":  {"--validator-config", cred},
		"ureth key is the credential":   {"--ureth-key", cred},
		"the JWT is the credential":     {"--jwt", cred},
		"operator key is the socket":    {"--operator-key", sock},
		"the config is the socket path": {"--validator-config", sock},
	} {
		before, rerr := os.ReadFile(cred)
		require.NoError(t, rerr)
		_, err = runValidator(t, home, append(append(append([]string{}, base...), auth...), extra...)...)
		require.ErrorIs(t, err, ErrValidator, name)
		after, rerr := os.ReadFile(cred)
		require.NoError(t, rerr)
		require.Equal(t, before, after, "%s: the credential is untouched", name)
	}

	// an existing config that cannot be loaded is not silently replaced by a key-file one
	bad := readConfig(t, home)
	bad.EVMKeys = "evm/keys.json" // both holders: refused at load
	bb, err := configBytes(bad)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(home, validatorConfigFile), bb, 0o600))
	_, err = runValidator(t, home, base...)
	require.ErrorContains(t, err, "cannot tell which holder")
	_, statErr = os.Stat(filepath.Join(home, "evm"))
	require.True(t, os.IsNotExist(statErr))
	require.NoError(t, os.WriteFile(filepath.Join(home, validatorConfigFile), mustBytes(t, readConfigWithAuthority(t, home, sock, cred, info)), 0o600))

	// an explicit --evm-keys switches back to a key file
	out, err = runValidator(t, home, "init", "--rpc", "http://127.0.0.1:1", "--force", "--evm-keys", "evm/keys.json")
	require.NoError(t, err, out)
	c = readConfig(t, home)
	require.Nil(t, c.EVMAuthority)
	require.Equal(t, "evm/keys.json", c.EVMKeys)
}

func mustBytes(t *testing.T, c validatorConfig) []byte {
	b, err := configBytes(c)
	require.NoError(t, err)
	return b
}

// readConfigWithAuthority is the config of home with the authority selected and no key file named (the config bad above was cleaned by hand).
func readConfigWithAuthority(t *testing.T, home, sock, cred, info string) validatorConfig {
	raw, err := os.ReadFile(filepath.Join(home, validatorConfigFile))
	require.NoError(t, err)
	var c validatorConfig
	require.NoError(t, json.Unmarshal(raw, &c))
	c.EVMKeys = ""
	c.EVMAuthority = &evmAuthorityConfig{Socket: sock, Credential: cred, NodeInfo: info}
	return c
}
