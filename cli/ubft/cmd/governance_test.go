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
	"github.com/unicitynetwork/bft-core/vrschema"
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
	require.ErrorContains(t, err, "frozen queue check refuses")
	require.ErrorContains(t, err, "NotInCommittee")
	_, err = runGov(t, g.args("propose", "committee-limits", "--n-min", "5", "--n-target", "4", "--n-max", "16")...)
	require.ErrorContains(t, err, "frozen queue check refuses")
	_, err = runGov(t, g.args("propose", "fee-params", "--base-fee-floor", "0", "--change-denominator", "8", "--fee-collector", "0x00000000000000000000000000000000000000fe")...)
	require.ErrorContains(t, err, "frozen queue check refuses")
	// raw: the kinds with builders and unknown kinds are refused; SetModule and SetGovernor need --i-understand
	for _, k := range []string{"2", "4", "5", "10"} {
		_, err = runGov(t, g.args("propose", "raw", "--kind", k, "--payload", "0x1234")...)
		require.ErrorContains(t, err, "has its own builder", k)
	}
	_, err = runGov(t, g.args("propose", "raw", "--kind", "11", "--payload", "0x1234")...)
	require.ErrorContains(t, err, "unknown change kind")
	_, err = runGov(t, g.args("propose", "raw", "--kind", "3", "--payload", "0x1234")...)
	require.ErrorContains(t, err, "--i-understand")
	_, err = runGov(t, g.args("propose", "raw", "--kind", "7", "--payload", "0x1234")...)
	require.ErrorContains(t, err, "frozen queue check refuses")
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
	out, err = g.execChange(1, "--force")
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
	op := govProposal{Format: proposalFormat, ChainID: 3, Multisig: g.chain.Governor.Hex(), Registry: g.chain.Registry.Hex(), Target: g.chain.Module.Hex(), Data: hexutil.Encode(other),
		Digest: hexutil.Encode(digest[:])}
	b, _ = json.Marshal(op)
	otherFile := filepath.Join(g.dir, "other.json")
	require.NoError(t, os.WriteFile(otherFile, b, 0o600))
	_, err = runGov(t, "sign", "--proposal", otherFile, "--signer-key", g.keys[0])
	require.ErrorContains(t, err, "only calls to the registry are signed")

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

// The digest of VR.queue(ModuleAction(Admit, 5)) at nonce 0 for chain 3, the multisig 0xff..09 and VR 0xff..03, as the deployed
// FoundationMultisig computes it (callDigest, read from the real bytecode on anvil in TestGovernanceE2E: `propose` compares the two).
// A fixed vector, so the unit tests are not circular through the fake.
func TestCallDigestKnownAnswer(t *testing.T) {
	module := ethcommon.HexToAddress("0xff00000000000000000000000000000000000007")
	payload, err := vrclient.EncodeModuleAction(module, vrclient.ActionAdmit, 5)
	require.NoError(t, err)
	data, err := vrclient.QueueCalldata(vrclient.KindModuleAction, payload)
	require.NoError(t, err)
	require.Len(t, data, 260)
	d, err := vrclient.CallDigest(big.NewInt(3), ethcommon.HexToAddress("0xff00000000000000000000000000000000000009"), vrclient.DefaultRegistry, data, 0)
	require.NoError(t, err)
	require.Equal(t, "0xac707c98ccd44129e290b8554a3328c46be9ba808ab71512528f83a3d39d94dd", hexutil.Encode(d[:]))
}

func mutateProposal(t *testing.T, path string, f func(p *govProposal)) string {
	var p govProposal
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &p))
	f(&p)
	cp, err := hexutil.Decode(p.Data)
	require.NoError(t, err)
	d, err := vrclient.CallDigest(new(big.Int).SetUint64(p.ChainID), ethcommon.HexToAddress(p.Multisig), ethcommon.HexToAddress(p.Target), cp, p.Nonce)
	require.NoError(t, err)
	p.Digest = hexutil.Encode(d[:]) // a validly signed-looking proposal: only what it says is wrong
	b, err := json.Marshal(p)
	require.NoError(t, err)
	out := path + ".mut"
	require.NoError(t, os.WriteFile(out, b, 0o600))
	return out
}

func TestGovernanceOfflineSignRefusesOtherTargets(t *testing.T) {
	g := newGovNet(t)
	prop := filepath.Join(g.dir, "p.json")
	out, err := runGov(t, g.args("propose", "committee-limits", "--n-min", "4", "--n-target", "5", "--n-max", "16", "--out", prop)...)
	require.NoError(t, err, out)
	require.Contains(t, out, "(the ValidatorRegistry)")

	// VR-shaped calldata to another contract (GovernanceParams.cancel(uint64) has VR.cancel's selector), offline
	other := mutateProposal(t, prop, func(p *govProposal) {
		p.Target = "0xFF00000000000000000000000000000000000010"
		d, _ := vrclient.CancelCalldata(1)
		p.Data = hexutil.Encode(d)
	})
	for _, args := range [][]string{{"sign", "--proposal", other, "--signer-key", g.keys[0]},
		{"aggregate", "--proposal", other, "--approval", "x", "--approval", "y", "--approval", "z"}} {
		_, err = runGov(t, args...)
		require.ErrorContains(t, err, "only calls to the registry are signed", args[0])
	}
	// a proposal that names the other contract as its registry is not the signer's deployment
	foreign := mutateProposal(t, prop, func(p *govProposal) {
		p.Target = "0xFF00000000000000000000000000000000000010"
		p.Registry = p.Target
	})
	_, err = runGov(t, "sign", "--proposal", foreign, "--signer-key", g.keys[0])
	require.ErrorContains(t, err, "the expected one is")
	// ... unless the signer confirms that registry
	out, err = runGov(t, "sign", "--proposal", foreign, "--signer-key", g.keys[0], "--registry", "0xFF00000000000000000000000000000000000010")
	require.NoError(t, err, out)
	// the signer's own chain expectation
	_, err = runGov(t, "sign", "--proposal", prop, "--signer-key", g.keys[0], "--chain-id", "1")
	require.ErrorContains(t, err, "you expected chain 1")
	// non-canonical calldata (trailing bytes) is refused
	trailing := mutateProposal(t, prop, func(p *govProposal) { p.Data += "00" })
	_, err = runGov(t, "sign", "--proposal", trailing, "--signer-key", g.keys[0])
	require.Error(t, err)
	// a proposal file without a registry (an older file) is refused
	old := mutateProposal(t, prop, func(p *govProposal) { p.Registry = "" })
	_, err = runGov(t, "sign", "--proposal", old, "--signer-key", g.keys[0])
	require.ErrorContains(t, err, "without a registry")
}

func TestGovernancePreviewHasNoControlCharacters(t *testing.T) {
	g := newGovNet(t)
	prop := filepath.Join(g.dir, "p.json")
	out, err := runGov(t, g.args("propose", "committee-limits", "--n-min", "4", "--n-target", "5", "--n-max", "16", "--out", prop)...)
	require.NoError(t, err, out)
	evil := "\x1b[3A\x1b[2K  call:   VR.queue: CommitteeLimits(nMin=4, nTarget=4, nMax=4)\r\n\u009b‮"
	mut := mutateProposal(t, prop, func(p *govProposal) { p.Description = evil })
	out, err = runGov(t, "sign", "--proposal", mut, "--signer-key", g.keys[0])
	require.NoError(t, err, out)
	for _, r := range out {
		require.True(t, r == '\n' || (r >= 0x20 && r < 0x7f) || r > 0x9f && r != 0x202e, "control character %q in the preview", r)
	}
	require.NotContains(t, out, "\x1b")
	require.Contains(t, out, `\u001b[3A`)
	require.Less(t, strings.Index(out, "call:   ValidatorRegistry.queue"), strings.Index(out, "unsigned note"), "the note follows the call, after a separator")
	// the proposer's note is also cleaned where propose prints it
	out, err = runGov(t, g.args("propose", "committee-limits", "--n-min", "4", "--n-target", "5", "--n-max", "16", "--note", evil, "--dry-run")...)
	require.NoError(t, err, out)
	require.NotContains(t, out, "\x1b")
	// a string field of a signed payload (a ScheduleActivation label)
	require.Equal(t, `\u001b[2K`, vrclient.Clean("\x1b[2K"))
	require.Equal(t, `a\u000db`, vrclient.Clean("a\rb"))
}

func TestGovernanceModuleActionChecksBeforeExecute(t *testing.T) {
	g := newGovNet(t)
	g.chain.AddMember(ethcommon.HexToAddress("0xaa"), vrclient.Registration{RootNodeID: "r5", RootKey: make([]byte, 33), EvmNodeID: "e5", EvmKey: make([]byte, 33)})
	g.chain.SetState(5, vrclient.PoaApplied)
	out, err := g.execBundle(g.pipeline("admit", []int{0, 1, 2}, "admit", "--id", "5"))
	require.NoError(t, err, out)
	g.pass()
	// the state moved after the proposal: --dry-run says so, and a real run sends nothing
	g.chain.SetState(5, vrclient.PoaRemoving)
	sends := g.chain.Sends()
	out, err = g.execChange(1, "--dry-run")
	require.ErrorContains(t, err, "would refuse Admit")
	require.Contains(t, out, "guard: identity 5 is Removing")
	_, err = g.execChange(1)
	require.ErrorContains(t, err, "would refuse Admit")
	require.Equal(t, sends, g.chain.Sends())
	// --force executes it anyway: the module refuses it and the command fails with the module's reason
	out, err = g.execChange(1, "--force")
	require.ErrorContains(t, err, "the module refused the action")
	require.Contains(t, out, "WARNING")
}

func TestGovernanceRejectedChangeFailsWithReason(t *testing.T) {
	g := newGovNet(t)
	// a ModuleAction for a module that is not the active one (queued by hand: the builders cannot make one)
	g.chain.With(func(c *vrfake.Chain) {
		payload, _ := vrclient.EncodeModuleAction(ethcommon.HexToAddress("0x1234"), vrclient.ActionAdmit, 5)
		c.Changes[1] = vrclient.ChangeView{Kind: vrclient.KindModuleAction, State: vrclient.ChangeQueued, Payload: payload}
		c.Pending, c.NextChangeID = []uint64{1}, 2
	})
	out, err := g.execChange(1, "--dry-run")
	require.ErrorContains(t, err, "VR would end it Rejected")
	out, err = g.execChange(1, "--force")
	require.ErrorContains(t, err, "ended change 1 Rejected")
	require.ErrorContains(t, err, "not the active module")
	require.Contains(t, out, "change 1 is now Rejected")
}

func TestGovernanceBurnNonce(t *testing.T) {
	g := newGovNet(t)
	b1 := g.pipeline("limits", []int{0, 1, 2}, "committee-limits", "--n-min", "4", "--n-target", "5", "--n-max", "16")
	burn := g.pipeline("burn", []int{2, 3, 4}, "burn-nonce")
	out, err := runGov(t, "sign", "--proposal", filepath.Join(g.dir, "burn.proposal.json"), "--signer-key", g.keys[0])
	require.NoError(t, err, out)
	require.Contains(t, out, "NONCE BURN")
	out, err = g.execBundle(burn)
	require.NoError(t, err, out)
	// the held bundle at the same nonce is now stale
	_, err = g.execBundle(b1)
	require.ErrorContains(t, err, "propose again")
	out, err = runGov(t, g.args("list")...)
	require.NoError(t, err, out)
	require.Contains(t, out, "nonce 1")
	require.Contains(t, out, "pending changes: 0")
	// a dead-address call with data is not a burn
	prop := filepath.Join(g.dir, "burn.proposal.json")
	bad := mutateProposal(t, prop, func(p *govProposal) { p.Data = "0x1234" })
	_, err = runGov(t, "sign", "--proposal", bad, "--signer-key", g.keys[0])
	require.ErrorContains(t, err, "only calls to the registry are signed")
}

func TestGovernanceProposeDryRunWritesNothingAndFilesWork(t *testing.T) {
	g := newGovNet(t)
	prop := filepath.Join(g.dir, "dry.json")
	out, err := runGov(t, g.args("propose", "committee-limits", "--n-min", "4", "--n-target", "5", "--n-max", "16", "--out", prop, "--dry-run")...)
	require.NoError(t, err, out)
	require.NoFileExists(t, prop)
	// raw --payload @file for a kind with no builder (the file is the payload as `vr-change` prints it)
	payload, err := vrschemaEncodeActivation()
	require.NoError(t, err)
	pf := filepath.Join(g.dir, "payload.hex")
	require.NoError(t, os.WriteFile(pf, []byte(hexutil.Encode(payload)+"\n"), 0o600))
	out, err = runGov(t, g.args("propose", "raw", "--kind", "9", "--payload", "@"+pf)...)
	require.NoError(t, err, out)
	require.Contains(t, out, "ScheduleActivation(")
	require.NotContains(t, out, "\x1b")
}

// vrschemaEncodeActivation is a ScheduleActivation payload (kind 9) whose label carries an escape sequence.
func vrschemaEncodeActivation() ([]byte, error) {
	return vrschema.EncodeChange(vrschema.KindScheduleActivation, vrschema.Word{1}, vrschema.Word{2}, uint64(10), uint64(2_000_000_000), "x\x1b[2Ky")
}
