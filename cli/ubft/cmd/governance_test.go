package cmd

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	testobserve "github.com/unicitynetwork/bft-core/internal/testutils/observability"
	"github.com/unicitynetwork/bft-core/vrclient"
	"github.com/unicitynetwork/bft-core/vrclient/vrfake"
)

func runGov(t *testing.T, args ...string) (string, error) {
	t.Helper()
	app := New(testobserve.NewFactory(t))
	var out bytes.Buffer
	app.baseCmd.SetOut(&out)
	app.baseCmd.SetErr(&out)
	app.baseCmd.SetArgs(append([]string{"governance"}, args...))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err := app.Execute(ctx)
	return out.String(), err
}

// govNet is a fake network with a five-signer multisig; signer key files are made with init-signer.
type govNet struct {
	t       *testing.T
	chain   *vrfake.Chain
	url     string
	dir     string
	keys    []string // signer key files
	keyObjs []*ecdsa.PrivateKey
	sender  string
}

func newGovNet(t *testing.T) *govNet {
	chain, url := fakeNetwork(t)
	g := &govNet{t: t, chain: chain, url: url, dir: t.TempDir()}
	var addrs [5]ethcommon.Address
	for i := 0; i < 5; i++ {
		p := filepath.Join(g.dir, fmt.Sprintf("signer%d", i), "key")
		out, err := runGov(t, "init-signer", "--key", p)
		require.NoError(t, err, out)
		k, err := readSignerKey(p)
		require.NoError(t, err)
		g.keys = append(g.keys, p)
		g.keyObjs = append(g.keyObjs, k)
		addrs[i] = ethcrypto.PubkeyToAddress(k.PublicKey)
	}
	chain.SetSigners(addrs)
	g.sender = filepath.Join(g.dir, "sender", "key")
	out, err := runGov(t, "init-signer", "--key", g.sender)
	require.NoError(t, err, out)
	sk, err := readSignerKey(g.sender)
	require.NoError(t, err)
	chain.Fund(ethcrypto.PubkeyToAddress(sk.PublicKey), bigWei())
	return g
}

func (g *govNet) rpc() []string { return []string{"--rpc", g.url} }

func (g *govNet) args(a ...string) []string { return append(append([]string{}, a...), g.rpc()...) }

// pipeline proposes (args after "propose"), has the signers by index sign, aggregates and returns the bundle path.
func (g *govNet) pipeline(name string, signers []int, propose ...string) string {
	t := g.t
	prop := filepath.Join(g.dir, name+".proposal.json")
	out, err := runGov(t, g.args(append(append([]string{"propose"}, propose...), "--out", prop)...)...)
	require.NoError(t, err, out)
	agg := []string{"aggregate", "--proposal", prop}
	for _, i := range signers {
		ap := filepath.Join(g.dir, fmt.Sprintf("%s.approval%d.json", name, i))
		out, err := runGov(t, "sign", "--proposal", prop, "--signer-key", g.keys[i], "--out", ap)
		require.NoError(t, err, out)
		agg = append(agg, "--approval", ap)
	}
	bundle := filepath.Join(g.dir, name+".bundle.json")
	out, err = runGov(t, g.args(append(agg, "--out", bundle)...)...)
	require.NoError(t, err, out)
	return bundle
}

func (g *govNet) execBundle(bundle string, extra ...string) (string, error) {
	return runGov(g.t, g.args(append([]string{"execute", "--bundle", bundle, "--sender-key", g.sender}, extra...)...)...)
}

func (g *govNet) execChange(id uint64, extra ...string) (string, error) {
	return runGov(g.t, g.args(append([]string{"execute", "--change", fmt.Sprint(id), "--sender-key", g.sender}, extra...)...)...)
}

// pass moves the clock past both governance delays of every change.
func (g *govNet) pass() {
	g.chain.With(func(c *vrfake.Chain) {
		c.Progress += c.Config.DelayRounds
		c.UcTime += c.Config.DelaySeconds
	})
}

func bigWei() *big.Int { return big.NewInt(1e18) }

func TestGovernanceAdmitAndConfirmExitPipeline(t *testing.T) {
	g := newGovNet(t)
	// an applicant, and an Active member that asked to exit
	g.chain.AddMember(ethcommon.HexToAddress("0xaa"), vrclient.Registration{RootNodeID: "r5", RootKey: make([]byte, 33), EvmNodeID: "e5", EvmKey: make([]byte, 33)})
	g.chain.SetState(5, vrclient.PoaApplied)

	bundle := g.pipeline("admit", []int{4, 0, 2}, "admit", "--id", "5", "--note", "the Foundation approves identity 5")
	out, err := g.execBundle(bundle, "--dry-run")
	require.NoError(t, err, out)
	require.Contains(t, out, "dry run: nothing sent")
	require.Contains(t, out, "ModuleAction Admit identity 5")
	require.Zero(t, g.chain.Sends())

	out, err = g.execBundle(bundle)
	require.NoError(t, err, out)
	t.Logf("execute --bundle:\n%s", out)
	require.Contains(t, out, "queued: change 1 (ModuleAction)")

	// not before the delays
	out, err = g.execChange(1)
	require.ErrorContains(t, err, "DelayNotElapsed")
	require.Contains(t, out, "waiting for progress")

	out, err = runGov(t, g.args("list")...)
	require.NoError(t, err, out)
	t.Logf("list:\n%s", out)
	require.Contains(t, out, "#1 ModuleAction Admit identity 5")
	require.Contains(t, out, "state Queued")
	require.Contains(t, out, "waiting for progress 7000 (in 2000 units) and UC time")

	g.pass()
	out, err = g.execChange(1)
	require.NoError(t, err, out)
	require.Contains(t, out, "change 1 is now Active")
	require.Equal(t, vrclient.PoaAdmitted, g.chain.State(5))

	// the bundle's nonce is spent: the same bundle is stale
	out, err = g.execBundle(bundle)
	require.ErrorContains(t, err, "propose again")

	// exit and ConfirmExit
	g.chain.SetState(2, vrclient.PoaExitRequested)
	bundle = g.pipeline("confirm", []int{1, 2, 3}, "confirm-exit", "--id", "2")
	out, err = g.execBundle(bundle)
	require.NoError(t, err, out)
	g.pass()
	out, err = g.execChange(2)
	require.NoError(t, err, out)
	require.Equal(t, vrclient.PoaRemoving, g.chain.State(2))
}

func TestGovernanceProposeRefusals(t *testing.T) {
	g := newGovNet(t)
	// Admit of an Active member: the module would refuse it without effect
	_, err := runGov(t, g.args("propose", "admit", "--id", "1")...)
	require.ErrorContains(t, err, "PoaElection would refuse Admit")
	// ConfirmExit before an exit request
	_, err = runGov(t, g.args("propose", "confirm-exit", "--id", "1")...)
	require.ErrorContains(t, err, "would refuse ConfirmExit")
	// Remove of an unknown identity
	_, err = runGov(t, g.args("propose", "remove", "--id", "99")...)
	require.ErrorContains(t, err, "None")
	// the override still reaches VR's own check, which accepts the ModuleAction
	out, err := runGov(t, g.args("propose", "admit", "--id", "1", "--no-state-check", "--dry-run")...)
	require.NoError(t, err, out)
	// VR's refusals are decoded
	_, err = runGov(t, g.args("propose", "force-remove", "--id", "77", "--dry-run")...)
	require.ErrorContains(t, err, "QueueRefused(16)")
	require.ErrorContains(t, err, "not in the committee")
	_, err = runGov(t, g.args("propose", "committee-limits", "--n-min", "5", "--n-target", "4", "--n-max", "16")...)
	require.ErrorContains(t, err, "QueueRefused")
	_, err = runGov(t, g.args("propose", "fee-params", "--base-fee-floor", "0", "--change-denominator", "8", "--fee-collector", "0x00000000000000000000000000000000000000fe")...)
	require.ErrorContains(t, err, "QueueRefused")
	_, err = runGov(t, g.args("propose", "raw", "--kind", "4", "--payload", "0x1234")...)
	require.ErrorContains(t, err, "QueueRefused")
	// without --rpc nothing is read
	_, err = runGov(t, "propose", "admit", "--id", "1")
	require.ErrorContains(t, err, "--rpc")
}

func TestGovernanceLiveConfigAndForceRemoveAndCancel(t *testing.T) {
	g := newGovNet(t)
	b := g.pipeline("limits", []int{0, 1, 2}, "committee-limits", "--n-min", "4", "--n-target", "6", "--n-max", "16")
	out, err := g.execBundle(b)
	require.NoError(t, err, out)
	b = g.pipeline("fees", []int{0, 1, 2}, "fee-params", "--base-fee-floor", "2000000", "--change-denominator", "8", "--fee-collector", "0x00000000000000000000000000000000000000fe")
	out, err = g.execBundle(b)
	require.NoError(t, err, out)
	b = g.pipeline("force", []int{0, 1, 2}, "force-remove", "--id", "3")
	out, err = g.execBundle(b)
	require.NoError(t, err, out)
	out, err = runGov(t, g.args("list")...)
	require.NoError(t, err, out)
	require.Contains(t, out, "CommitteeLimits(nMin=4, nTarget=6, nMax=16)")
	require.Contains(t, out, "FeeParams(baseFeeFloor=2000000")
	require.Contains(t, out, "ForceRemove(id=3)")
	require.Contains(t, out, "pending changes: 3")

	g.pass()
	out, err = g.execChange(1)
	require.NoError(t, err, out)
	require.Contains(t, out, "change 1 is now Scheduled")
	// a Scheduled change is cancelled by the multisig
	b = g.pipeline("cancel", []int{0, 1, 2}, "cancel", "--change", "1")
	out, err = g.execBundle(b)
	require.NoError(t, err, out)
	out, err = runGov(t, g.args("list", "--change", "1")...)
	require.NoError(t, err, out)
	require.Contains(t, out, "state Cancelled")
	// cancel of a change that is Cancelled is refused with VR's reason
	_, err = runGov(t, g.args("propose", "cancel", "--change", "1")...)
	require.ErrorContains(t, err, "NotCancellable")
}

func TestGovernanceModuleActionRefusedByModuleFails(t *testing.T) {
	g := newGovNet(t)
	g.chain.AddMember(ethcommon.HexToAddress("0xaa"), vrclient.Registration{RootNodeID: "r5", RootKey: make([]byte, 33), EvmNodeID: "e5", EvmKey: make([]byte, 33)})
	g.chain.SetState(5, vrclient.PoaApplied)
	b := g.pipeline("admit", []int{0, 1, 2}, "admit", "--id", "5")
	out, err := g.execBundle(b)
	require.NoError(t, err, out)
	// the state moves between queue and execution
	g.chain.SetState(5, vrclient.PoaNone)
	g.pass()
	out, err = g.execChange(1)
	require.ErrorContains(t, err, "the module refused the action")
	require.Contains(t, out, "PoaElection refused Admit of identity 5")
}

func TestGovernanceSigningRules(t *testing.T) {
	g := newGovNet(t)
	prop := filepath.Join(g.dir, "p.json")
	out, err := runGov(t, g.args("propose", "committee-limits", "--n-min", "4", "--n-target", "5", "--n-max", "16", "--out", prop)...)
	require.NoError(t, err, out)
	require.Contains(t, out, "simulation: VR accepts the call as the governor (it would be change 1)")

	// the output is never over an existing file, nor over a key
	_, err = runGov(t, g.args("propose", "committee-limits", "--n-min", "4", "--n-target", "5", "--n-max", "16", "--out", prop)...)
	require.ErrorContains(t, err, "exists")
	_, err = runGov(t, "sign", "--proposal", prop, "--signer-key", g.keys[0], "--out", g.keys[0])
	require.ErrorContains(t, err, "is the key file")
	alias := filepath.Join(g.dir, "alias")
	require.NoError(t, os.Symlink(g.keys[0], alias))
	_, err = runGov(t, "sign", "--proposal", prop, "--signer-key", g.keys[0], "--out", alias)
	require.ErrorContains(t, err, "is the key file")
	before, _ := os.ReadFile(g.keys[0])
	require.True(t, strings.HasPrefix(string(before), "0x"))

	// init-signer keeps an existing key
	out, err = runGov(t, "init-signer", "--key", g.keys[0])
	require.NoError(t, err, out)
	require.Contains(t, out, "found")
	after, _ := os.ReadFile(g.keys[0])
	require.Equal(t, before, after)
	st, err := os.Stat(g.keys[0])
	require.NoError(t, err)
	require.Zero(t, st.Mode().Perm()&0o077)

	// a key other users can read is refused
	loose := filepath.Join(g.dir, "loose")
	require.NoError(t, os.WriteFile(loose, before, 0o644))
	_, err = runGov(t, "sign", "--proposal", prop, "--signer-key", loose)
	require.ErrorContains(t, err, "readable by other users")

	// a tampered proposal is refused by the signer and the aggregator
	var p govProposal
	raw, _ := os.ReadFile(prop)
	require.NoError(t, json.Unmarshal(raw, &p))
	p.Nonce = 9
	tampered := filepath.Join(g.dir, "tampered.json")
	b, _ := json.Marshal(p)
	require.NoError(t, os.WriteFile(tampered, b, 0o600))
	_, err = runGov(t, "sign", "--proposal", tampered, "--signer-key", g.keys[0])
	require.ErrorContains(t, err, "not the digest of its fields")

	// a proposal of another call than queue or cancel is not signed
	other, err := vrclient.PoaCalldata(vrclient.MethodRequestExit, 1)
	require.NoError(t, err)
	digest, err := vrclient.CallDigest(g.chain.ChainID, g.chain.Governor, g.chain.Module, other, 0)
	require.NoError(t, err)
	op := govProposal{Format: proposalFormat, ChainID: 3, Multisig: g.chain.Governor.Hex(), Target: g.chain.Module.Hex(), Data: hexutil.Encode(other),
		Digest: hexutil.Encode(digest[:])}
	b, _ = json.Marshal(op)
	otherFile := filepath.Join(g.dir, "other.json")
	require.NoError(t, os.WriteFile(otherFile, b, 0o600))
	_, err = runGov(t, "sign", "--proposal", otherFile, "--signer-key", g.keys[0])
	require.ErrorContains(t, err, "not a ValidatorRegistry call this tool signs")

	// sign with --rpc: a stranger is refused
	stranger := filepath.Join(g.dir, "stranger", "key")
	_, err = runGov(t, "init-signer", "--key", stranger)
	require.NoError(t, err)
	_, err = runGov(t, g.args("sign", "--proposal", prop, "--signer-key", stranger)...)
	require.ErrorContains(t, err, "is not one of the multisig's signers")

	// aggregate: two approvals, a duplicate, a stranger, a wrong digest
	ap := func(i int) string {
		p := filepath.Join(g.dir, fmt.Sprintf("a%d.json", i))
		out, err := runGov(t, "sign", "--proposal", prop, "--signer-key", g.keys[i], "--out", p)
		require.NoError(t, err, out)
		return p
	}
	a0, a1, a2 := ap(0), ap(1), ap(2)
	_, err = runGov(t, "aggregate", "--proposal", prop, "--approval", a0, "--approval", a1)
	require.ErrorContains(t, err, "needs 3 distinct signers")
	_, err = runGov(t, "aggregate", "--proposal", prop, "--approval", a0, "--approval", a1, "--approval", a1)
	require.ErrorContains(t, err, "approved twice")
	sa := filepath.Join(g.dir, "stranger-approval.json")
	_, err = runGov(t, "sign", "--proposal", prop, "--signer-key", stranger, "--out", sa)
	require.NoError(t, err)
	_, err = runGov(t, g.args("aggregate", "--proposal", prop, "--approval", a0, "--approval", a1, "--approval", sa)...)
	require.ErrorContains(t, err, "is not one of the multisig's signers")
	// an approval whose signature is by another key than it names
	var forged govApproval
	raw, _ = os.ReadFile(a2)
	require.NoError(t, json.Unmarshal(raw, &forged))
	forged.Signer = ethcrypto.PubkeyToAddress(g.keyObjs[3].PublicKey).Hex()
	fb, _ := json.Marshal(forged)
	ff := filepath.Join(g.dir, "forged.json")
	require.NoError(t, os.WriteFile(ff, fb, 0o600))
	_, err = runGov(t, "aggregate", "--proposal", prop, "--approval", a0, "--approval", a1, "--approval", ff)
	require.ErrorContains(t, err, "is by")

	// a good bundle with two signers dropped to the minimum executes; a bundle with approvals for another nonce does not
	out, err = runGov(t, g.args("aggregate", "--proposal", prop, "--approval", a2, "--approval", a0, "--approval", a1)...)
	require.NoError(t, err, out)
}

func TestGovernanceListEmpty(t *testing.T) {
	g := newGovNet(t)
	out, err := runGov(t, g.args("list")...)
	require.NoError(t, err, out)
	require.Contains(t, out, "pending changes: 0")
	require.Contains(t, out, "(3 of 5), nonce 0")
	_, err = runGov(t, g.args("list", "--change", "5")...)
	require.ErrorContains(t, err, "there is no change 5")
}

func TestGovernanceExecuteRefusesStaleAndNeedsSender(t *testing.T) {
	g := newGovNet(t)
	b1 := g.pipeline("one", []int{0, 1, 2}, "committee-limits", "--n-min", "4", "--n-target", "5", "--n-max", "16")
	b2 := g.pipeline("two", []int{0, 1, 2}, "committee-limits", "--n-min", "4", "--n-target", "6", "--n-max", "16")
	out, err := g.execBundle(b1)
	require.NoError(t, err, out)
	// alternatives at one nonce: the second is stale
	_, err = g.execBundle(b2)
	require.ErrorContains(t, err, "nonce")
	_, err = runGov(t, g.args("execute", "--bundle", b1)...)
	require.ErrorContains(t, err, "--sender-key")
	_, err = runGov(t, g.args("execute", "--sender-key", g.sender)...)
	require.ErrorContains(t, err, "exactly one")
}
