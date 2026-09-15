package registrywitness

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
Offline checks of testdata/reth-proof-window.sh, in the style of registrygenesis's evidence-script tests
(review of #157). A copy of the script runs in a temporary tree against a stand-in reth, curl and lsof. The
stand-in curl derives the head from the time the stand-in node started (one block per second) and applies
the proof window the node was started with, so the honest case exercises the real sampling loop. No port
is opened and no client runs.

A refusal must exit non-zero with the message of the check it targets, leave the previous measurement
byte-identical and leave no temporary file.
*/

type windowCase struct {
	version     string
	nodeExits   bool
	preListener bool
	lsofOwner   string // "node", "other" or ""
	mode        string // stand-in curl behaviour: "", "proof-beyond-window", "unexpected-proof-error",
	// "header-fails", "not-jsonrpc-head", "unknown-header-served"
	mvFails bool
	windows string // RETH_WINDOW_WINDOWS for the run
}

func honestWindowCase() windowCase {
	return windowCase{version: pinnedRethVersionText, lsofOwner: "node", windows: "0 1"}
}

const pinnedRethVersionText = "Reth Version: 2.5.0-dev\nCommit SHA: 189c0df32617afc488e0f091dbface1bd72cceb4\nBuild Profile: release\n"

func runWindowScript(t *testing.T, c windowCase) (output string, exitErr error, before, after []byte) {
	for _, tool := range []string{"bash", "jq"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not available", tool)
		}
	}
	m := loadMeasurement(t)
	genesis, block1 := m.Vectors["genesis"], m.Vectors["block1"]

	root := t.TempDir()
	wtd := filepath.Join(root, "registrywitness", "testdata")
	gtd := filepath.Join(root, "registrygenesis", "testdata")
	stubs := filepath.Join(root, "stubs")
	canned := filepath.Join(root, "canned")
	for _, d := range []string{wtd, gtd, stubs, canned} {
		require.NoError(t, os.MkdirAll(d, 0o755))
	}
	for src, dst := range map[string]string{
		"testdata/reth-proof-window.sh":                   filepath.Join(wtd, "reth-proof-window.sh"),
		"../registrygenesis/testdata/genesis-vector.json": filepath.Join(gtd, "genesis-vector.json"),
		"../registrygenesis/seal-registry-v1.json":        filepath.Join(root, "registrygenesis", "seal-registry-v1.json"),
	} {
		b, err := os.ReadFile(src)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(dst, b, 0o644))
	}
	before = []byte(`{"retained":"previous measurement"}`)
	outPath := filepath.Join(wtd, "reth-proof-window.json")
	require.NoError(t, os.WriteFile(outPath, before, 0o644))

	write := func(name, body string) {
		require.NoError(t, os.WriteFile(filepath.Join(canned, name), []byte(body), 0o644))
	}
	write("version", c.version)
	write("mode", c.mode)
	write("genesis", genesis.Hash.Hex())
	write("block1", block1.Hash.Hex())
	write("header", genesis.Header)
	write("proof", string(genesis.Proof))
	write("client", m.ClientVersion)
	// The stand-in head advances by call count, not wall-clock time: one block per 12 eth_blockNumber calls.
	// The script brackets each proof request with two such calls, so it still discards samples that straddle
	// a block, but every distance gets consistent samples however slowly the stand-ins run.
	write("callsperblock", "12")

	pidFile, launched, counterFile, windowFile := filepath.Join(root, "node.pid"), filepath.Join(root, "node.launched"), filepath.Join(root, "node.calls"), filepath.Join(root, "node.window")
	nodeBody := fmt.Sprintf(`touch %[1]q
	window=0
	while [ $# -gt 0 ]; do case "$1" in --rpc.eth-proof-window) window="$2"; shift ;; esac; shift; done
	echo "$window" > %[2]q
	echo 0 > %[3]q
	echo $$ > %[4]q
	exec sleep 120`, launched, windowFile, counterFile, pidFile)
	if c.nodeExits {
		nodeBody = fmt.Sprintf("touch %q\n\techo 'address already in use' >&2\n\texit 1", launched)
	}
	writeWindowStub(t, filepath.Join(stubs, "reth"), fmt.Sprintf(`
case "$1" in
--version) cat %q ;;
node)
	shift
	%s ;;
esac
`, filepath.Join(canned, "version"), nodeBody))

	pre := "0"
	if c.preListener {
		pre = "1"
	}
	writeWindowStub(t, filepath.Join(stubs, "curl"), fmt.Sprintf(`
canned=%[1]q
data=""
while [ $# -gt 0 ]; do case "$1" in --data) data="$2"; shift ;; esac; shift; done
if [ -z "$data" ]; then
	[ %[2]q = 1 ] && exit 0
	exit 7
fi
mode=$(cat "$canned/mode")
genesis=$(cat "$canned/genesis")
block1=$(cat "$canned/block1")
method=$(printf '%%s' "$data" | sed -n 's/.*"method":"\([^"]*\)".*/\1/p')
calls=0
if [ -f %[3]q ]; then
	calls=$(cat %[3]q)
	# The head also moves while a proof is being served, as a real head can, so a sample whose proof was
	# answered at another head than its first head read differs from a bracketed one.
	case "$method" in eth_blockNumber|eth_getProof) calls=$((calls + 1)); echo "$calls" > %[3]q ;; esac
fi
head=$((calls / $(cat "$canned/callsperblock")))
# skip-head: the head jumps from 0 to 2, so block 1 is never the head.
if [ "$(cat "$canned/mode")" = skip-head ] && [ "$head" -ge 1 ]; then head=$((head + 1)); fi
window=0
[ -f %[4]q ] && window=$(cat %[4]q)
ok() { printf '{"jsonrpc":"2.0","id":1,"result":%%s}' "$1"; }
err() { printf '{"jsonrpc":"2.0","id":1,"error":{"code":%%s,"message":"%%s"}}' "$1" "$2"; }
number_of() { case "$1" in "$genesis") echo 0 ;; "$block1") echo 1 ;; *) echo unknown ;; esac; }
case "$method" in
web3_clientVersion) ok "\"$(cat "$canned/client")\"" ;;
eth_blockNumber)
	if [ "$mode" = not-jsonrpc-head ]; then echo '"0x1"'; exit 0; fi
	ok "\"$(printf '0x%%x' "$head")\"" ;;
eth_getBlockByNumber)
	n=$(printf '%%s' "$data" | sed -n 's/.*"params":\["\(0x[0-9a-f]*\)".*/\1/p')
	case "$n" in 0x0) h=$genesis ;; 0x1) h=$block1 ;; *) h=0x$(printf '%%064x' $((n))) ;; esac
	ok "{\"hash\":\"$h\",\"number\":\"$n\"}" ;;
debug_getRawHeader|eth_getBlockByHash|eth_getProof)
	if [ "$method" = eth_getProof ]; then
		hash=$(printf '%%s' "$data" | sed -n 's/.*"blockHash":"\(0x[0-9a-f]*\)".*/\1/p')
	else
		hash=$(printf '%%s' "$data" | sed -n 's/.*"params":\["\(0x[0-9a-f]*\)".*/\1/p')
	fi
	n=$(number_of "$hash")
	if [ "$n" = unknown ]; then
		if [ "$mode" = unknown-header-served ] && [ "$method" = debug_getRawHeader ]; then ok "\"$(cat "$canned/header")\""; exit 0; fi
		[ "$method" = eth_getBlockByHash ] && { ok null; exit 0; }
		err -32001 "block not found: hash $hash"; exit 0
	fi
	case "$method" in
	debug_getRawHeader)
		if [ "$mode" = header-fails ] && [ $((head - n)) -ge 2 ]; then err -32603 "internal error"; exit 0; fi
		ok "\"$(cat "$canned/header")\"" ;;
	eth_getBlockByHash) ok "{\"hash\":\"$hash\"}" ;;
	eth_getProof)
		if [ "$mode" = error-without-code ]; then printf '{"jsonrpc":"2.0","id":1,"error":{"message":"no code"}}'; exit 0; fi
		if [ $((head - n)) -le "$window" ] || [ "$mode" = proof-beyond-window ] || { [ "$mode" = proof-two-beyond ] && [ $((head - n)) -eq $((window + 2)) ]; }; then ok "$(cat "$canned/proof")"
		elif [ "$mode" = unexpected-proof-error ]; then err -32603 "internal error"
		else err -32602 "distance to target block exceeds maximum proof window"; fi ;;
	esac ;;
*) err -32601 "method not found" ;;
esac
`, canned, pre, counterFile, windowFile))

	lsofBody := ":"
	switch c.lsofOwner {
	case "node":
		// Like a real lsof, a stopped node is no longer reported, although its PID file remains.
		lsofBody = fmt.Sprintf(`[ -f %q ] && pid=$(cat %q) && kill -0 "$pid" 2>/dev/null && echo "$pid"`, pidFile, pidFile)
	case "other":
		lsofBody = fmt.Sprintf(`[ -f %q ] && echo 424242`, launched)
	}
	if c.preListener {
		lsofBody = "echo 424242"
	}
	writeWindowStub(t, filepath.Join(stubs, "lsof"), lsofBody+"\nexit 0\n")
	if c.mvFails {
		// Only the final publication is refused; the script's other moves are not affected.
		writeWindowStub(t, filepath.Join(stubs, "mv"), fmt.Sprintf(`case "$2" in %q) echo 'mv: stand-in failure' >&2; exit 1 ;; esac
exec /bin/mv "$@"
`, outPath))
	}

	cmd := exec.Command("bash", filepath.Join(wtd, "reth-proof-window.sh"), filepath.Join(stubs, "reth"), filepath.Join(root, "work"))
	cmd.Env = append(os.Environ(),
		"PATH="+stubs+string(os.PathListSeparator)+os.Getenv("PATH"),
		"RETH_WINDOW_READY_SECONDS=15", "RETH_WINDOW_WINDOWS="+c.windows, "RETH_WINDOW_SAMPLE_SLEEP=0", "RETH_WINDOW_BLOCK_TIME=3s")
	out, err := cmd.CombinedOutput()
	after, readErr := os.ReadFile(outPath)
	require.NoError(t, readErr)
	leftovers, _ := filepath.Glob(filepath.Join(wtd, ".reth-proof-window.*"))
	require.Empty(t, leftovers, "no temporary measurement may be left behind")
	return string(out), err, before, after
}

func writeWindowStub(t *testing.T, path, body string) {
	require.NoError(t, os.WriteFile(path, []byte("#!/usr/bin/env bash\nset -u\n"+strings.TrimLeft(body, "\n")), 0o755))
}

func TestWindowScriptAcceptsAnHonestPinnedRun(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the sampling loop against a one-second stand-in chain")
	}
	out, err, before, after := runWindowScript(t, honestWindowCase())
	require.NoError(t, err, out)
	require.Contains(t, out, "wrote ")
	require.NotEqual(t, before, after)

	var published measurement
	require.NoError(t, json.Unmarshal(after, &published))
	require.Len(t, published.Runs, 2)
	for _, run := range published.Runs {
		lastProof, firstRefusal := false, false
		for _, o := range run.Observed {
			lastProof = lastProof || (o.Target == 1 && o.Distance == run.Window && o.Outcome == "proof")
			firstRefusal = firstRefusal || (o.Target == 1 && o.Distance == run.Window+1 && o.Outcome == "refused")
		}
		require.True(t, lastProof && firstRefusal, "window %d boundaries: %+v", run.Window, run.Observed)
	}
	require.Contains(t, published.Vectors, "genesis")
	require.Contains(t, published.Vectors, "block1")
}

func TestWindowScriptRefusals(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the sampling loop against a one-second stand-in chain")
	}
	with := func(change func(*windowCase)) windowCase {
		c := honestWindowCase()
		// One window is enough for a refusal; the honest case covers both boundaries of two windows.
		c.windows = "0"
		change(&c)
		return c
	}
	for name, tc := range map[string]struct {
		c    windowCase
		want string
	}{
		"unpinned binary":                   {with(func(c *windowCase) { c.version = "Reth Version: 2.5.0\nCommit SHA: other\n" }), "is not the pinned build"},
		"a listener already answers":        {with(func(c *windowCase) { c.preListener = true }), "already answers"},
		"node exits":                        {with(func(c *windowCase) { c.nodeExits = true; c.lsofOwner = "" }), "is not running"},
		"listener is another process":       {with(func(c *windowCase) { c.lsofOwner = "other" }), "not this run's node"},
		"proof served beyond the window":    {with(func(c *windowCase) { c.mode = "proof-beyond-window" }), "do not show proofs exactly up to the window"},
		"unexpected proof error":            {with(func(c *windowCase) { c.mode = "unexpected-proof-error" }), "returned an unexpected response"},
		"header lookup fails after expiry":  {with(func(c *windowCase) { c.mode = "header-fails" }), "debug_getRawHeader("},
		"head response is not JSON-RPC":     {with(func(c *windowCase) { c.mode = "not-jsonrpc-head" }), "eth_blockNumber: not a JSON-RPC result or error object"},
		"header served for an unknown hash": {with(func(c *windowCase) { c.mode = "unknown-header-served" }), "for a block hash it cannot have"},
		// Window 1, so genesis is inside the window while sampling and both vectors are captured: every check
		// passes and only the publication fails.
		// Each of the next three is refused only by the check it names: an error object without a numeric code,
		// a proof two blocks past the window while both boundaries look right, and missing boundary samples
		// with no contradicting sample.
		"error object without a code":         {with(func(c *windowCase) { c.mode = "error-without-code" }), "eth_getProof: not a JSON-RPC result or error object"},
		"proof served two blocks past window": {with(func(c *windowCase) { c.mode = "proof-two-beyond" }), "do not show proofs exactly up to the window"},
		"block 1 never observed as the head":  {with(func(c *windowCase) { c.mode = "skip-head" }), "do not show proofs exactly up to the window"},
		"publication fails":                   {with(func(c *windowCase) { c.mvFails = true; c.windows = "1" }), "mv: stand-in failure"},
	} {
		t.Run(name, func(t *testing.T) {
			out, err, before, after := runWindowScript(t, tc.c)
			require.Error(t, err, "the script must fail: %s", out)
			require.Contains(t, out, tc.want, "refused by the check this case targets")
			require.NotContains(t, out, "wrote ")
			require.Equal(t, before, after, "a failed run must leave the previous measurement unchanged")
		})
	}
}
