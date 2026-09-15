package registrygenesis

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

/*
Offline checks of testdata/reth-funded-genesis-vector.sh. Each case runs a copy of the script in a
temporary tree against stand-in executables: a fake reth, and fake curl and lsof earlier on PATH. No port is
opened and no real client runs.

A refusal must exit non-zero with the message of the check it targets, leave the previously retained vector
byte-identical, and leave no temporary file. The fundedHonest case shows the same stand-ins produce a vector, so
each refusal is reached by its one deviation and not by an earlier check.
*/

const (
	fundedPinnedRethVersion = "Reth Version: 2.5.0-dev\nCommit SHA: 189c0df32617afc488e0f091dbface1bd72cceb4\nBuild Profile: release\n"
	fundedAddress           = "0x1000000000000000000000000000000000000001"
	nonceAddress            = "0x1000000000000000000000000000000000000002"
	codeAddress             = "0x2000000000000000000000000000000000000001"
	sealRegistryAddress     = "0xff00000000000000000000000000000000000002"
	fullStorageKey          = "0x0000000000000000000000000000000000000000000000000000000000000001"
	fullStorageValue        = "0x0000000000000000000000000000000000000000000000000000000000000002"
)

type fundedScriptCase struct {
	version     string // fake `reth --version` output
	nodeExits   bool   // the fake node exits at once instead of running
	preListener bool   // something answers on the port before the node starts
	lsofOwner   string // "node" (the fake node's PID), "other" or "" (no listener)
	mvFails     bool   // publishing fails after every check has passed (a failing mv on PATH)
	respond     func(method, address string, v rethVector) string
	mutateInput func([]byte) []byte
}

func fundedOKResult(result any) string {
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "result": result})
	return string(b)
}

func fundedHonest(method, address string, v rethVector) string {
	switch method {
	case "web3_clientVersion":
		return fundedOKResult(v.ClientVersion)
	case "eth_getBlockByNumber":
		return fundedOKResult(map[string]any{"hash": v.RPCBlock0Hash.Hex(), "stateRoot": v.StateRoot.Hex(), "number": "0x0"})
	case "debug_getRawHeader":
		return fundedOKResult(v.Header)
	case "eth_getProof":
		return fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"result":%s}`, v.Proof)
	case "eth_getBalance":
		return fundedOKResult(map[string]string{fundedAddress: "0x0123456789ABCDEF", nonceAddress: "0x2A", codeAddress: "0x05"}[address])
	case "eth_getTransactionCount":
		return fundedOKResult(map[string]string{fundedAddress: "0x00", nonceAddress: "0x07", codeAddress: "0x03"}[address])
	case "eth_getCode":
		return fundedOKResult(map[string]string{fundedAddress: "0x", nonceAddress: "0x", codeAddress: "0x6001600055"}[address])
	case "eth_getStorageAt":
		return fundedOKResult(fullStorageValue)
	}
	return `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}`
}

func fundedHonestCase() fundedScriptCase {
	return fundedScriptCase{version: fundedPinnedRethVersion, lsofOwner: "node", respond: fundedHonest}
}

func fundedGenesisInput() []byte {
	return []byte(fmt.Sprintf(`{"alloc":{
%q:{"balance":"0x123456789abcdef","nonce":"0x0"},
%q:{"balance":"0x2a","nonce":"0x7"},
%q:{"balance":"0x5","nonce":"0x3","code":"0x6001600055","storage":{%q:%q}}
}}`, fundedAddress, nonceAddress, codeAddress, fullStorageKey, fullStorageValue))
}

func runFundedVectorScript(t *testing.T, c fundedScriptCase) (output string, exitErr error, before, after []byte) {
	for _, tool := range []string{"bash", "jq"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not available", tool)
		}
	}
	raw, err := os.ReadFile("testdata/reth-genesis-vector.json")
	require.NoError(t, err)
	var v rethVector
	require.NoError(t, json.Unmarshal(raw, &v))

	root := t.TempDir()
	td := filepath.Join(root, "testdata")
	stubs := filepath.Join(root, "stubs")
	require.NoError(t, os.MkdirAll(td, 0o755))
	require.NoError(t, os.MkdirAll(stubs, 0o755))
	for src, dst := range map[string]string{
		"testdata/reth-funded-genesis-vector.sh": filepath.Join(td, "reth-funded-genesis-vector.sh"),
		"seal-registry-v1.json":                  filepath.Join(root, "seal-registry-v1.json"),
	} {
		b, err := os.ReadFile(src)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(dst, b, 0o644))
	}
	input := fundedGenesisInput()
	if c.mutateInput != nil {
		input = c.mutateInput(input)
	}
	require.NoError(t, os.WriteFile(filepath.Join(td, "funded-genesis-vector.json"), input, 0o644))
	before = []byte(`{"retained":"previous vector"}`)
	vectorPath := filepath.Join(td, "reth-funded-genesis-vector.json")
	require.NoError(t, os.WriteFile(vectorPath, before, 0o644))

	// Canned inputs for the stand-ins, one file each, so no text passes through shell quoting.
	canned := filepath.Join(root, "canned")
	require.NoError(t, os.MkdirAll(canned, 0o755))
	for _, call := range []struct{ method, address string }{
		{"web3_clientVersion", ""}, {"eth_getBlockByNumber", ""}, {"debug_getRawHeader", ""}, {"eth_getProof", sealRegistryAddress},
		{"eth_getBalance", fundedAddress}, {"eth_getBalance", nonceAddress}, {"eth_getBalance", codeAddress},
		{"eth_getTransactionCount", fundedAddress}, {"eth_getTransactionCount", nonceAddress}, {"eth_getTransactionCount", codeAddress},
		{"eth_getCode", fundedAddress}, {"eth_getCode", nonceAddress}, {"eth_getCode", codeAddress},
		{"eth_getStorageAt", codeAddress},
	} {
		require.NoError(t, os.WriteFile(filepath.Join(canned, call.method+"_"+call.address), []byte(c.respond(call.method, call.address, v)), 0o644))
	}
	require.NoError(t, os.WriteFile(filepath.Join(canned, "version"), []byte(c.version), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(canned, "init"), []byte("INFO Genesis block written hash="+v.InitGenesisHash.Hex()+"\n"), 0o644))

	pidFile := filepath.Join(root, "node.pid")
	launched := filepath.Join(root, "node.launched")
	nodeBody := fmt.Sprintf("touch %q\n\techo $$ > %q\n\texec sleep 30", launched, pidFile)
	if c.nodeExits {
		nodeBody = fmt.Sprintf("touch %q\n\techo 'address already in use' >&2\n\texit 1", launched)
	}
	writeFundedStub(t, filepath.Join(stubs, "reth"), fmt.Sprintf(`
case "$1" in
--version) cat %q ;;
init) cat %q ;;
node)
	%s ;;
esac
`, filepath.Join(canned, "version"), filepath.Join(canned, "init"), nodeBody))

	preListener := "0"
	if c.preListener {
		preListener = "1"
	}
	// curl: a probe without --data succeeds only when something already listens; RPC calls answer from the
	// canned file for their method.
	writeFundedStub(t, filepath.Join(stubs, "curl"), fmt.Sprintf(`
data=""
while [ $# -gt 0 ]; do
	case "$1" in --data) data="$2"; shift ;; esac
	shift
done
if [ -z "$data" ]; then
	[ %q = 1 ] && exit 0
	exit 7
fi
method=$(printf '%%s' "$data" | sed -n 's/.*"method":"\([^"]*\)".*/\1/p')
address=$(printf '%%s' "$data" | sed -n 's/.*"params":\["\(0x[0-9a-f]\{40\}\)".*/\1/p')
cat %q/"${method}_${address}"
`, preListener, canned))

	lsofBody := ":"
	switch c.lsofOwner {
	case "node":
		lsofBody = fmt.Sprintf(`[ -f %q ] && cat %q`, pidFile, pidFile)
	case "other":
		// Another process listens once this run has launched its node, so the pre-start check passes and
		// only the liveness or ownership checks can refuse.
		lsofBody = fmt.Sprintf(`[ -f %q ] && echo 424242`, launched)
	}
	// Before the node starts, no listener is reported unless the case has one.
	if c.preListener {
		lsofBody = "echo 424242"
	}
	writeFundedStub(t, filepath.Join(stubs, "lsof"), lsofBody+"\nexit 0\n")
	if c.mvFails {
		writeFundedStub(t, filepath.Join(stubs, "mv"), "echo 'mv: stand-in failure' >&2\nexit 1\n")
	}

	cmd := exec.Command("bash", filepath.Join(td, "reth-funded-genesis-vector.sh"), filepath.Join(stubs, "reth"), filepath.Join(root, "work"))
	cmd.Env = append(os.Environ(), "PATH="+stubs+string(os.PathListSeparator)+os.Getenv("PATH"), "RETH_VECTOR_READY_SECONDS=2")
	out, err := cmd.CombinedOutput()
	after, readErr := os.ReadFile(vectorPath)
	require.NoError(t, readErr)
	leftovers, _ := filepath.Glob(filepath.Join(td, ".reth-funded-genesis-vector.*"))
	require.Empty(t, leftovers, "no temporary vector may be left behind")
	return string(out), err, before, after
}

func writeFundedStub(t *testing.T, path, body string) {
	require.NoError(t, os.WriteFile(path, []byte("#!/usr/bin/env bash\nset -u\n"+strings.TrimLeft(body, "\n")), 0o755))
}

func TestRethFundedVectorScriptAcceptsAnHonestPinnedRun(t *testing.T) {
	out, err, before, after := runFundedVectorScript(t, fundedHonestCase())
	require.NoError(t, err, out)
	require.Contains(t, out, "wrote ")
	require.NotEqual(t, before, after)

	var published struct {
		Accounts map[string]struct {
			Balance string            `json:"balance"`
			Nonce   string            `json:"nonce"`
			Code    string            `json:"code"`
			Storage map[string]string `json:"storage"`
		} `json:"accounts"`
	}
	require.NoError(t, json.Unmarshal(after, &published))
	require.Equal(t, "0x123456789abcdef", published.Accounts[fundedAddress].Balance, "large quantities are normalized as strings without jq numeric conversion")
	require.Equal(t, "0x0", published.Accounts[fundedAddress].Nonce)
	require.Equal(t, "0x2a", published.Accounts[nonceAddress].Balance)
	require.Equal(t, "0x7", published.Accounts[nonceAddress].Nonce)
	require.Equal(t, "0x6001600055", published.Accounts[codeAddress].Code)
	require.Equal(t, map[string]string{fullStorageKey: fullStorageValue}, published.Accounts[codeAddress].Storage)
}

func TestRethFundedVectorScriptRefusals(t *testing.T) {
	errorEverywhere := func(string, string, rethVector) string {
		return `{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"unavailable"}}`
	}
	override := func(method, address, response string) func(string, string, rethVector) string {
		return func(m, a string, v rethVector) string {
			if m == method && (address == "" || a == address) {
				return response
			}
			return fundedHonest(m, a, v)
		}
	}
	with := func(change func(*fundedScriptCase)) fundedScriptCase {
		c := fundedHonestCase()
		change(&c)
		return c
	}
	for name, tc := range map[string]struct {
		c    fundedScriptCase
		want string
	}{
		"unpinned binary": {with(func(c *fundedScriptCase) {
			c.version = "Reth Version: 2.5.0\nCommit SHA: wrong-unpinned-client\n"
		}), "is not the pinned build"},
		"a listener already answers": {with(func(c *fundedScriptCase) { c.preListener = true }), "already answers"},
		"node exits while another endpoint answers": {with(func(c *fundedScriptCase) {
			c.nodeExits = true
			c.lsofOwner = "other"
		}), "is not running|not this run's node"},
		"node exits and nothing listens": {with(func(c *fundedScriptCase) {
			c.nodeExits = true
			c.lsofOwner = ""
		}), "is not running"},
		"node runs but never listens":         {with(func(c *fundedScriptCase) { c.lsofOwner = "" }), "did not listen"},
		"listener is another process":         {with(func(c *fundedScriptCase) { c.lsofOwner = "other" }), "not this run's node"},
		"every call returns a JSON-RPC error": {with(func(c *fundedScriptCase) { c.respond = errorEverywhere }), "not a successful JSON-RPC result"},
		"response id is not one": {with(func(c *fundedScriptCase) {
			c.respond = override("web3_clientVersion", "", `{"jsonrpc":"2.0","id":2,"result":"reth/v2.5.0-dev-189c0df/x86_64"}`)
		}), "web3_clientVersion: not a successful JSON-RPC result"},
		"multiple response objects": {with(func(c *fundedScriptCase) {
			one := fundedOKResult("reth/v2.5.0-dev-189c0df/x86_64")
			c.respond = override("web3_clientVersion", "", one+"\n"+one)
		}), "web3_clientVersion: not a successful JSON-RPC result"},
		"client version names another commit": {with(func(c *fundedScriptCase) {
			c.respond = override("web3_clientVersion", "", fundedOKResult("reth/v2.5.0-dev-deadbeef/x86_64"))
		}), "does not name"},
		"null block": {with(func(c *fundedScriptCase) {
			c.respond = override("eth_getBlockByNumber", "", fundedOKResult(nil))
		}), "eth_getBlockByNumber: not a successful JSON-RPC result"},
		"block without a state root": {with(func(c *fundedScriptCase) {
			c.respond = override("eth_getBlockByNumber", "", fundedOKResult(map[string]any{"hash": "0x" + strings.Repeat("11", 32), "number": "0x0"}))
		}), "result is malformed"},
		"RPC genesis hash differs from init": {with(func(c *fundedScriptCase) {
			c.respond = override("eth_getBlockByNumber", "", fundedOKResult(map[string]any{"hash": "0x" + strings.Repeat("11", 32), "stateRoot": "0x" + strings.Repeat("22", 32), "number": "0x0"}))
		}), "differs from the reth init hash"},
		"header is not hex": {with(func(c *fundedScriptCase) {
			c.respond = override("debug_getRawHeader", "", fundedOKResult("0xzz"))
		}), "is not hex bytes"},
		"response without a JSON-RPC envelope": {with(func(c *fundedScriptCase) {
			c.respond = override("debug_getRawHeader", "", `"0x00"`)
		}), "debug_getRawHeader: not a successful JSON-RPC result"},
		"null proof": {with(func(c *fundedScriptCase) {
			c.respond = override("eth_getProof", "", fundedOKResult(nil))
		}), "eth_getProof: not a successful JSON-RPC result"},
		// An otherwise complete, well-formed proof; only the address differs.
		"proof for another address": {with(func(c *fundedScriptCase) {
			c.respond = func(m, a string, v rethVector) string {
				if m != "eth_getProof" {
					return fundedHonest(m, a, v)
				}
				var p map[string]any
				_ = json.Unmarshal(v.Proof, &p)
				p["address"] = "0xff00000000000000000000000000000000000003"
				return fundedOKResult(p)
			}
		}), "eth_getProof result is malformed"},
		"balance is not a quantity": {with(func(c *fundedScriptCase) {
			c.respond = override("eth_getBalance", fundedAddress, fundedOKResult("123"))
		}), "eth_getBalance result for " + fundedAddress + " is not a hex quantity"},
		"balance disagrees with finalized input": {with(func(c *fundedScriptCase) {
			c.respond = override("eth_getBalance", fundedAddress, fundedOKResult("0x9"))
		}), "balance for " + fundedAddress},
		"nonce disagrees with finalized input": {with(func(c *fundedScriptCase) {
			c.respond = override("eth_getTransactionCount", nonceAddress, fundedOKResult("0x8"))
		}), "nonce for " + nonceAddress},
		"code is malformed": {with(func(c *fundedScriptCase) {
			c.respond = override("eth_getCode", codeAddress, fundedOKResult("0x1"))
		}), "eth_getCode result for " + codeAddress + " is not even-length hex bytes"},
		"code disagrees with finalized input": {with(func(c *fundedScriptCase) {
			c.respond = override("eth_getCode", codeAddress, fundedOKResult("0x6000"))
		}), "code for " + codeAddress},
		"storage is malformed": {with(func(c *fundedScriptCase) {
			c.respond = override("eth_getStorageAt", codeAddress, fundedOKResult("0x2"))
		}), "eth_getStorageAt result for " + codeAddress},
		"storage disagrees with finalized input": {with(func(c *fundedScriptCase) {
			c.respond = override("eth_getStorageAt", codeAddress, fundedOKResult("0x"+strings.Repeat("03", 32)))
		}), "storage for " + codeAddress},
		"finalized input omits funded account": {with(func(c *fundedScriptCase) {
			c.mutateInput = func(in []byte) []byte {
				return []byte(strings.Replace(string(in), fundedAddress, "0x3000000000000000000000000000000000000001", 1))
			}
		}), "no allocation object for " + fundedAddress},
		"finalized input has no explicit balance": {with(func(c *fundedScriptCase) {
			c.mutateInput = func(in []byte) []byte {
				return []byte(strings.Replace(string(in), `"balance":"0x123456789abcdef"`, `"balance":null`, 1))
			}
		}), "no explicit string balance for " + fundedAddress},
		"finalized input has unqueried EOA storage": {with(func(c *fundedScriptCase) {
			c.mutateInput = func(in []byte) []byte {
				return []byte(strings.Replace(string(in), `"nonce":"0x0"`, `"nonce":"0x0","storage":{"0x01":"0x02"}`, 1))
			}
		}), "unqueried storage for " + fundedAddress},
		"finalized contract storage key is not canonical": {with(func(c *fundedScriptCase) {
			c.mutateInput = func(in []byte) []byte { return []byte(strings.Replace(string(in), fullStorageKey, "0x1", 1)) }
		}), "must contain exactly " + fullStorageKey},
		// Every check passes and the publish step fails: the retained vector must survive and no temporary
		// file may remain. set -e stops the script at mv, so no message is required.
		"publishing fails after validation": {with(func(c *fundedScriptCase) { c.mvFails = true }), ""},
	} {
		t.Run(name, func(t *testing.T) {
			out, err, before, after := runFundedVectorScript(t, tc.c)
			require.Error(t, err, "the script must fail: %s", out)
			// want lists the acceptable refusals, separated by |. A node that exits while another process answers
			// may be refused by liveness or by ownership, whichever check sees it first; both refuse the evidence.
			matched := false
			for _, w := range strings.Split(tc.want, "|") {
				matched = matched || strings.Contains(out, w)
			}
			require.True(t, matched, "refused by the check this case targets (%s): %s", tc.want, out)
			require.NotContains(t, out, "wrote ")
			require.Equal(t, before, after, "a failed run must leave the retained vector unchanged")
		})
	}
}
