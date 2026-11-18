package cmd

// The end-to-end check of `ubft governance` against the real ValidatorRegistry, PoaElection and FoundationMultisig bytecode (the fixture
// and the anvil setup of validator_e2e_test.go):
//
//	UBFT_VALIDATOR_E2E_ANVIL=$(which anvil) go test ./cli/ubft/cmd -run TestGovernanceE2E -v
//
// apply -> governance Admit (propose, three offline signatures, aggregate, execute, the delays, execute) -> status Admitted; and the exit
// of an Active member -> governance ConfirmExit -> status Removing. The signers are the fixture's deterministic keys.

import (
	"crypto/ecdsa"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum/common/hexutil"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/vrclient"
)

func writeKeyFile(t *testing.T, dir, name string, k *ecdsa.PrivateKey) string {
	p := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(p, []byte(hexutil.Encode(ethcrypto.FromECDSA(k))), 0o600))
	return p
}

func TestGovernanceE2E(t *testing.T) {
	bin := os.Getenv("UBFT_VALIDATOR_E2E_ANVIL")
	if bin == "" {
		t.Skip("set UBFT_VALIDATOR_E2E_ANVIL to the anvil binary to run the end-to-end check")
	}
	a := startAnvil(t, bin)
	a.load(filepath.Join("testdata", "validator-e2e"))
	dir := t.TempDir()
	rpcArgs := []string{"--rpc", a.url}
	sender := writeKeyFile(t, dir, "sender.key", e2eKey(t, "payer"))
	var signers []string
	for i := 1; i <= 5; i++ {
		signers = append(signers, writeKeyFile(t, dir, fmt.Sprintf("signer-%d.key", i), e2eKey(t, fmt.Sprintf("signer-%d", i))))
	}
	gov := func(args ...string) string {
		t.Helper()
		out, err := runGov(t, append(append([]string{}, args...), rpcArgs...)...)
		require.NoError(t, err, out)
		t.Logf("ubft governance %v:\n%s", args[0], out)
		return out
	}
	// pipeline: propose -> sign by the given signers -> aggregate -> execute --bundle -> clock past the delays -> execute --change
	approve := func(name string, who []int, propose ...string) uint64 {
		t.Helper()
		prop := filepath.Join(dir, name+".proposal.json")
		gov(append(append([]string{"propose"}, propose...), "--out", prop)...)
		agg := []string{"aggregate", "--proposal", prop}
		for _, i := range who {
			ap := filepath.Join(dir, fmt.Sprintf("%s.approval-%d.json", name, i))
			out, err := runGov(t, "sign", "--proposal", prop, "--signer-key", signers[i-1], "--out", ap) // offline: no --rpc
			require.NoError(t, err, out)
			agg = append(agg, "--approval", ap)
		}
		bundle := filepath.Join(dir, name+".bundle.json")
		gov(append(agg, "--out", bundle)...)
		out := gov("execute", "--bundle", bundle, "--sender-key", sender)
		require.Contains(t, out, "queued: change")
		pending, err := a.vr.PendingChanges(t.Context())
		require.NoError(t, err)
		id := pending[len(pending)-1]
		ch, err := a.vr.Change(t.Context(), id)
		require.NoError(t, err)
		listed := gov("list")
		require.Contains(t, listed, fmt.Sprintf("#%d ", id))
		out, err = runGov(t, append([]string{"execute", "--change", fmt.Sprint(id), "--sender-key", sender}, rpcArgs...)...)
		require.ErrorContains(t, err, "DelayNotElapsed", out)
		a.setClock(ch.NotBeforeProgress, ch.NotBeforeTime)
		gov("execute", "--change", fmt.Sprint(id), "--sender-key", sender)
		return id
	}

	// apply -> governance Admit -> status Admitted
	home := initHome(t, a.url)
	_, keys := loadHome(t, home)
	a.fund(ethcrypto.PubkeyToAddress(keys.Operator.PublicKey))
	out, err := runValidator(t, home, "apply")
	require.NoError(t, err, out)
	require.Equal(t, uint64(5), readConfig(t, home).ID)
	out, err = runGov(t, append([]string{"propose", "admit", "--id", "1", "--dry-run"}, rpcArgs...)...)
	require.ErrorContains(t, err, "PoaElection would refuse Admit", out) // identity 1 is Active
	id := approve("admit", []int{2, 4, 5}, "admit", "--id", "5")
	ch, err := a.vr.Change(t.Context(), id)
	require.NoError(t, err)
	require.Equal(t, "Active", vrclient.ChangeState(ch.State))
	out, err = runValidator(t, home, "status")
	require.NoError(t, err, out)
	require.Contains(t, out, "PoA state   Admitted")

	// exit -> governance ConfirmExit
	ownerKey := writeKeyFile(t, dir, "owner-1.key", e2eKey(t, "owner-1"))
	home1 := initHome(t, a.url, "--operator-key", ownerKey, "--id", "1")
	a.fund(ethcrypto.PubkeyToAddress(e2eKey(t, "owner-1").PublicKey))
	out, err = runGov(t, append([]string{"propose", "confirm-exit", "--id", "1", "--dry-run"}, rpcArgs...)...)
	require.ErrorContains(t, err, "would refuse ConfirmExit", out) // no exit requested yet
	out, err = runValidator(t, home1, "exit")
	require.NoError(t, err, out)
	approve("confirm-exit", []int{1, 3, 5}, "confirm-exit", "--id", "1")
	out, err = runValidator(t, home1, "status")
	require.NoError(t, err, out)
	t.Logf("status of identity 1 after ConfirmExit:\n%s", out)
	require.Contains(t, out, "PoA state   Removing")

	// the Foundation can also take out an Admitted validator, which cannot leave on its own
	out, err = runValidator(t, home, "exit", "--dry-run")
	require.ErrorContains(t, err, "ask the Foundation for ModuleAction Remove", out)
	approve("remove", []int{1, 2, 3}, "remove", "--id", "5")
	out, err = runValidator(t, home, "status")
	require.NoError(t, err, out)
	require.Contains(t, out, "PoA state   Removing")

	// live configuration: queued by three signers, listed with its delays
	approveQueueOnly := func() {
		prop := filepath.Join(dir, "limits.proposal.json")
		gov("propose", "committee-limits", "--n-min", "4", "--n-target", "4", "--n-max", "12", "--out", prop)
		agg := []string{"aggregate", "--proposal", prop}
		for _, i := range []int{1, 2, 3} {
			ap := filepath.Join(dir, fmt.Sprintf("limits.approval-%d.json", i))
			o, err := runGov(t, "sign", "--proposal", prop, "--signer-key", signers[i-1], "--out", ap)
			require.NoError(t, err, o)
			agg = append(agg, "--approval", ap)
		}
		bundle := filepath.Join(dir, "limits.bundle.json")
		gov(append(agg, "--out", bundle)...)
		gov("execute", "--bundle", bundle, "--sender-key", sender)
	}
	approveQueueOnly()
	listed := gov("list")
	require.Contains(t, listed, "CommitteeLimits(nMin=4, nTarget=4, nMax=12)")
	require.Contains(t, listed, "state Queued")
}
