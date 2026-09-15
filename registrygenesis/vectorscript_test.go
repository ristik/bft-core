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
Offline checks of testdata/reth-genesis-vector.sh (review of #157). Each case runs a copy of the script in a
temporary tree against stand-in executables: a fake reth, and fake curl and lsof earlier on PATH. No port is
opened and no real client runs.

A refusal must exit non-zero with the message of the check it targets, leave the previously retained vector
byte-identical, and leave no temporary file. The honest case shows the same stand-ins produce a vector, so
each refusal is reached by its one deviation and not by an earlier check.
*/

const pinnedRethVersion = "Reth Version: 2.5.0-dev\nCommit SHA: 189c0df32617afc488e0f091dbface1bd72cceb4\nBuild Profile: release\n"

type scriptCase struct {
	version     string // fake `reth --version` output
	nodeExits   bool   // the fake node exits at once instead of running
	preListener bool   // something answers on the port before the node starts
	lsofOwner   string // "node" (the fake node's PID), "other" or "" (no listener)
	mvFails     bool   // publishing fails after every check has passed (a failing mv on PATH)
	respond     func(method string, v rethVector) string
}

func okResult(result any) string {
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "result": result})
	return string(b)
}

func honest(method string, v rethVector) string {
	switch method {
	case "web3_clientVersion":
		return okResult(v.ClientVersion)
	case "eth_getBlockByNumber":
		return okResult(map[string]any{"hash": v.RPCBlock0Hash.Hex(), "stateRoot": v.StateRoot.Hex(), "number": "0x0"})
	case "debug_getRawHeader":
		return okResult(v.Header)
	case "eth_getProof":
		return fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"result":%s}`, v.Proof)
	}
	return `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}`
}

func honestCase() scriptCase {
	return scriptCase{version: pinnedRethVersion, lsofOwner: "node", respond: honest}
}

func runVectorScript(t *testing.T, c scriptCase) (output string, exitErr error, before, after []byte) {
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
		"testdata/reth-genesis-vector.sh": filepath.Join(td, "reth-genesis-vector.sh"),
		"testdata/genesis-vector.json":    filepath.Join(td, "genesis-vector.json"),
		"seal-registry-v1.json":           filepath.Join(root, "seal-registry-v1.json"),
	} {
		b, err := os.ReadFile(src)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(dst, b, 0o644))
	}
	before = []byte(`{"retained":"previous vector"}`)
	vectorPath := filepath.Join(td, "reth-genesis-vector.json")
	require.NoError(t, os.WriteFile(vectorPath, before, 0o644))

	// Canned inputs for the stand-ins, one file each, so no text passes through shell quoting.
	canned := filepath.Join(root, "canned")
	require.NoError(t, os.MkdirAll(canned, 0o755))
	for _, m := range []string{"web3_clientVersion", "eth_getBlockByNumber", "debug_getRawHeader", "eth_getProof"} {
		require.NoError(t, os.WriteFile(filepath.Join(canned, m), []byte(c.respond(m, v)), 0o644))
	}
	require.NoError(t, os.WriteFile(filepath.Join(canned, "version"), []byte(c.version), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(canned, "init"), []byte("INFO Genesis block written hash="+v.InitGenesisHash.Hex()+"\n"), 0o644))

	pidFile := filepath.Join(root, "node.pid")
	launched := filepath.Join(root, "node.launched")
	nodeBody := fmt.Sprintf("touch %q\n\techo $$ > %q\n\texec sleep 30", launched, pidFile)
	if c.nodeExits {
		nodeBody = fmt.Sprintf("touch %q\n\techo 'address already in use' >&2\n\texit 1", launched)
	}
	writeStub(t, filepath.Join(stubs, "reth"), fmt.Sprintf(`
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
	writeStub(t, filepath.Join(stubs, "curl"), fmt.Sprintf(`
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
cat %q/"$method"
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
	writeStub(t, filepath.Join(stubs, "lsof"), lsofBody+"\nexit 0\n")
	if c.mvFails {
		writeStub(t, filepath.Join(stubs, "mv"), "echo 'mv: stand-in failure' >&2\nexit 1\n")
	}

	cmd := exec.Command("bash", filepath.Join(td, "reth-genesis-vector.sh"), filepath.Join(stubs, "reth"), filepath.Join(root, "work"))
	cmd.Env = append(os.Environ(), "PATH="+stubs+string(os.PathListSeparator)+os.Getenv("PATH"), "RETH_VECTOR_READY_SECONDS=2")
	out, err := cmd.CombinedOutput()
	after, readErr := os.ReadFile(vectorPath)
	require.NoError(t, readErr)
	leftovers, _ := filepath.Glob(filepath.Join(td, ".reth-genesis-vector.*"))
	require.Empty(t, leftovers, "no temporary vector may be left behind")
	return string(out), err, before, after
}

func writeStub(t *testing.T, path, body string) {
	require.NoError(t, os.WriteFile(path, []byte("#!/usr/bin/env bash\nset -u\n"+strings.TrimLeft(body, "\n")), 0o755))
}

func TestRethVectorScriptAcceptsAnHonestPinnedRun(t *testing.T) {
	out, err, before, after := runVectorScript(t, honestCase())
	require.NoError(t, err, out)
	require.Contains(t, out, "wrote ")
	require.NotEqual(t, before, after)

	var published, retained map[string]any
	require.NoError(t, json.Unmarshal(after, &published))
	raw, err := os.ReadFile("testdata/reth-genesis-vector.json")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &retained))
	delete(published, "generator")
	delete(retained, "generator")
	require.Equal(t, retained, published, "the stand-ins replay the retained vector, so the script republishes its content")
}

func TestRethVectorScriptRefusals(t *testing.T) {
	errorEverywhere := func(string, rethVector) string {
		return `{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"unavailable"}}`
	}
	override := func(method, response string) func(string, rethVector) string {
		return func(m string, v rethVector) string {
			if m == method {
				return response
			}
			return honest(m, v)
		}
	}
	with := func(change func(*scriptCase)) scriptCase {
		c := honestCase()
		change(&c)
		return c
	}
	for name, tc := range map[string]struct {
		c    scriptCase
		want string
	}{
		"unpinned binary": {with(func(c *scriptCase) {
			c.version = "Reth Version: 2.5.0\nCommit SHA: wrong-unpinned-client\n"
		}), "is not the pinned build"},
		"a listener already answers": {with(func(c *scriptCase) { c.preListener = true }), "already answers"},
		"node exits while another endpoint answers": {with(func(c *scriptCase) {
			c.nodeExits = true
			c.lsofOwner = "other"
		}), "is not running|not this run's node"},
		"node exits and nothing listens": {with(func(c *scriptCase) {
			c.nodeExits = true
			c.lsofOwner = ""
		}), "is not running"},
		"node runs but never listens":         {with(func(c *scriptCase) { c.lsofOwner = "" }), "did not listen"},
		"listener is another process":         {with(func(c *scriptCase) { c.lsofOwner = "other" }), "not this run's node"},
		"every call returns a JSON-RPC error": {with(func(c *scriptCase) { c.respond = errorEverywhere }), "not a successful JSON-RPC result"},
		"client version names another commit": {with(func(c *scriptCase) {
			c.respond = override("web3_clientVersion", okResult("reth/v2.5.0-dev-deadbeef/x86_64"))
		}), "does not name"},
		"null block": {with(func(c *scriptCase) {
			c.respond = override("eth_getBlockByNumber", okResult(nil))
		}), "eth_getBlockByNumber: not a successful JSON-RPC result"},
		"block without a state root": {with(func(c *scriptCase) {
			c.respond = override("eth_getBlockByNumber", okResult(map[string]any{"hash": "0x" + strings.Repeat("11", 32), "number": "0x0"}))
		}), "result is malformed"},
		"RPC genesis hash differs from init": {with(func(c *scriptCase) {
			c.respond = override("eth_getBlockByNumber", okResult(map[string]any{"hash": "0x" + strings.Repeat("11", 32), "stateRoot": "0x" + strings.Repeat("22", 32), "number": "0x0"}))
		}), "differs from the reth init hash"},
		"header is not hex": {with(func(c *scriptCase) {
			c.respond = override("debug_getRawHeader", okResult("0xzz"))
		}), "is not hex bytes"},
		"response without a JSON-RPC envelope": {with(func(c *scriptCase) {
			c.respond = override("debug_getRawHeader", `"0x00"`)
		}), "debug_getRawHeader: not a successful JSON-RPC result"},
		"null proof": {with(func(c *scriptCase) {
			c.respond = override("eth_getProof", okResult(nil))
		}), "eth_getProof: not a successful JSON-RPC result"},
		// An otherwise complete, well-formed proof; only the address differs.
		"proof for another address": {with(func(c *scriptCase) {
			c.respond = func(m string, v rethVector) string {
				if m != "eth_getProof" {
					return honest(m, v)
				}
				var p map[string]any
				_ = json.Unmarshal(v.Proof, &p)
				p["address"] = "0xff00000000000000000000000000000000000003"
				return okResult(p)
			}
		}), "eth_getProof result is malformed"},
		// Every check passes and the publish step fails: the retained vector must survive and no temporary
		// file may remain. set -e stops the script at mv, so no message is required.
		"publishing fails after validation": {with(func(c *scriptCase) { c.mvFails = true }), ""},
	} {
		t.Run(name, func(t *testing.T) {
			out, err, before, after := runVectorScript(t, tc.c)
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
