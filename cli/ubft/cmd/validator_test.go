package cmd

import (
	"bytes"
	"context"
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

// runValidator runs `ubft validator <args> --home home` in process and returns its output.
func runValidator(t *testing.T, home string, args ...string) (string, error) {
	t.Helper()
	app := New(testobserve.NewFactory(t))
	var out bytes.Buffer
	app.baseCmd.SetOut(&out)
	app.baseCmd.SetErr(&out)
	app.baseCmd.SetArgs(append(append([]string{"validator"}, args...), "--home", home))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err := app.Execute(ctx)
	return out.String(), err
}

func readConfig(t *testing.T, home string) validatorConfig {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(home, validatorConfigFile))
	require.NoError(t, err)
	var c validatorConfig
	require.NoError(t, json.Unmarshal(raw, &c))
	return c
}

func loadHome(t *testing.T, home string) (*loadedValidator, *validatorKeys) {
	t.Helper()
	f := &validatorFlags{baseFlags: &baseFlags{HomeDir: home}}
	v, err := f.load()
	require.NoError(t, err)
	k, err := v.keys()
	require.NoError(t, err)
	return v, k
}

// fakeNetwork is a vrfake chain with four genesis members, served over HTTP.
func fakeNetwork(t *testing.T) (*vrfake.Chain, string) {
	t.Helper()
	c := vrfake.New()
	for i := 1; i <= 4; i++ {
		rk, _ := ethcrypto.GenerateKey()
		ek, _ := ethcrypto.GenerateKey()
		owner, _ := ethcrypto.GenerateKey()
		c.AddMember(ethcrypto.PubkeyToAddress(owner.PublicKey), vrclient.Registration{RootNodeID: fmt.Sprintf("genesis-root-%d", i),
			RootKey: ethcrypto.CompressPubkey(&rk.PublicKey), EvmNodeID: fmt.Sprintf("genesis-evm-%d", i), EvmKey: ethcrypto.CompressPubkey(&ek.PublicKey),
			Payee: ethcrypto.PubkeyToAddress(rk.PublicKey)})
	}
	srv := c.Serve()
	t.Cleanup(srv.Close)
	return c, srv.URL
}

func initHome(t *testing.T, url string, extra ...string) string {
	t.Helper()
	home := t.TempDir()
	out, err := runValidator(t, home, append([]string{"init", "--rpc", url, "--local-rpc", url}, extra...)...)
	require.NoError(t, err, out)
	return home
}

func TestValidatorInitCreatesKeysOnceAndSeparately(t *testing.T) {
	home := t.TempDir()
	out, err := runValidator(t, home, "init", "--rpc", "http://127.0.0.1:1")
	require.NoError(t, err, out)
	for _, p := range []string{"root/keys.json", "root/node-info.json", "evm/keys.json", "evm/node-info.json", "ureth-key/p2p-secret", "jwt/jwt.hex", "operator/key", validatorConfigFile} {
		st, err := os.Stat(filepath.Join(home, p))
		require.NoError(t, err, p)
		require.Zero(t, st.Mode().Perm()&0o077, "%s is private", p)
	}
	st, err := os.Stat(filepath.Join(home, "ureth-key"))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o700), st.Mode().Perm())
	secret, err := os.ReadFile(filepath.Join(home, "ureth-key/p2p-secret"))
	require.NoError(t, err)
	require.Len(t, secret, 64, "64 hex digits without a newline (ureth_key.py)")
	require.Equal(t, 5, strings.Count(out, "created"), out)
	_, k1 := loadHome(t, home)
	cfg := readConfig(t, home)
	require.Equal(t, ethcrypto.PubkeyToAddress(k1.Operator.PublicKey).Hex(), cfg.Payee, "the payee defaults to the operator account")
	require.Equal(t, strings.ToLower(vrclient.DefaultRegistry.Hex()), cfg.Registry)

	// a second init refuses without --force; with it, every key is found and kept
	_, err = runValidator(t, home, "init", "--rpc", "http://127.0.0.1:1")
	require.ErrorContains(t, err, "exists")
	out, err = runValidator(t, home, "init", "--rpc", "http://127.0.0.1:2", "--force", "--payee", "0x00000000000000000000000000000000000000aa")
	require.NoError(t, err, out)
	require.Zero(t, strings.Count(out, "created"), out)
	_, k2 := loadHome(t, home)
	require.Equal(t, k1.Root.SigKey.PrivateKey, k2.Root.SigKey.PrivateKey)
	require.Equal(t, ethcrypto.FromECDSA(k1.Ureth), ethcrypto.FromECDSA(k2.Ureth))
	require.Equal(t, "0x00000000000000000000000000000000000000aa", readConfig(t, home).Payee)

	// a key shared between services is refused
	raw, err := os.ReadFile(filepath.Join(home, "root/keys.json"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(home, "evm/keys.json"), raw, 0o600))
	_, err = runValidator(t, home, "init", "--rpc", "http://127.0.0.1:1", "--force")
	require.ErrorContains(t, err, "the root node signing key is the EVM shard node signing key")

	_, err = runValidator(t, t.TempDir(), "init")
	require.ErrorContains(t, err, "--rpc")
}

func TestValidatorClaimAfterMaturingLots(t *testing.T) {
	chain, url := fakeNetwork(t)
	home := initHome(t, url)
	_, keys := loadHome(t, home)
	operator := ethcrypto.PubkeyToAddress(keys.Operator.PublicKey)
	chain.Fund(operator, big.NewInt(1e18))
	id := chain.AddMember(operator, vrclient.Registration{RootNodeID: "claim-root", EvmNodeID: "claim-evm"})
	chain.Mu.Lock()
	chain.Tag = vrclient.ModuleTagPoS
	chain.Custody = ethcommon.Address{0xc1}
	chain.Election = ethcommon.Address{0xe1}
	chain.ClaimLots = []*big.Int{big.NewInt(42)}
	chain.Mu.Unlock()

	args := []string{"claim", "--id", fmt.Sprint(id)}
	out, err := runValidator(t, home, append(args, "--dry-run")...)
	require.NoError(t, err, out)
	require.Zero(t, chain.Sends())
	require.NotContains(t, out, "claimed 100 base units")

	out, err = runValidator(t, home, args...)
	require.Equal(t, 2, chain.Sends(), "mature and claim were mined: %s", out)
	chain.Mu.Lock()
	remaining := chain.ClaimCredit.Sign()
	chain.Mu.Unlock()
	require.Zero(t, remaining, "the claim spent the credit")
	require.NoError(t, err, out)
	require.Contains(t, out, "claimed 100 base units to "+operator.Hex())

	_, err = runValidator(t, home, args...)
	require.ErrorContains(t, err, "no credit to claim")
	require.Equal(t, 2, chain.Sends(), "an empty balance before any transaction still refuses the claim")

	chain.Mu.Lock()
	chain.ClaimCredit = big.NewInt(60)
	chain.Mu.Unlock()
	out, err = runValidator(t, home, args...)
	require.NoError(t, err, out)
	require.Equal(t, 3, chain.Sends(), "a resumed withdrawal sends only the claim")
	require.Contains(t, out, "claimed 60 base units to "+operator.Hex())
}

// #1297/#1298: custody refuses mature while a closed term of the lots has no report anchors. claim anchors the closed terms its own lots back,
// with the words of each term's Closure record, previewing each: a term custody has not closed, has anchored, that backs no lot of the caller,
// or that is not anchorable yet (its successor epoch is not installed) is not sent and does not stop the claim.
func TestValidatorClaimAnchorsClosedTerms(t *testing.T) {
	chain, url := fakeNetwork(t)
	home := initHome(t, url)
	_, keys := loadHome(t, home)
	operator := ethcrypto.PubkeyToAddress(keys.Operator.PublicKey)
	chain.Fund(operator, big.NewInt(1e18))
	id := chain.AddMember(operator, vrclient.Registration{RootNodeID: "anchor-root", EvmNodeID: "anchor-evm"})
	a, b, open, done, other, later := [32]byte{0xa1}, [32]byte{0xb2}, [32]byte{0xc3}, [32]byte{0xd4}, [32]byte{0xe5}, [32]byte{0xf6}
	lot := big.NewInt(42)
	chain.Mu.Lock()
	chain.Tag = vrclient.ModuleTagPoS
	chain.Custody = ethcommon.Address{0xc1}
	chain.Election = ethcommon.Address{0xe1}
	chain.ClaimLots = []*big.Int{lot}
	chain.Terms = &vrfake.Terms{
		Closures: [][3][32]byte{{a, {0x11}, {0x12}}, {b, {0x21}, {0x22}}, {open, {0x31}, {0x32}}, {done, {0x41}, {0x42}}, {other, {0x51}, {0x52}},
			{later, {0x61}, {0x62}}, {a, {0x11}, {0x12}}},
		Closed:     map[[32]byte]bool{a: true, b: true, done: true, other: true, later: true},
		Anchored:   map[[32]byte]bool{done: true},
		Unanchored: map[string]uint32{"42": 2},
		Backs:      map[[32]byte][]*big.Int{a: {lot}, b: {lot}, open: {lot}, done: {lot}, later: {lot}, other: {big.NewInt(7)}},
		NotReady:   map[[32]byte]bool{later: true, other: true},
	}
	chain.Mu.Unlock()

	args := []string{"claim", "--id", fmt.Sprint(id)}
	out, err := runValidator(t, home, append(args, "--dry-run")...)
	require.NoError(t, err, out)
	require.Zero(t, chain.Sends())
	require.Contains(t, out, "[anchor] anchor closed term "+hexutil.Encode(a[:]))
	require.Contains(t, out, "[anchor] anchor closed term "+hexutil.Encode(b[:]))
	require.NotContains(t, out, hexutil.Encode(open[:]), "custody has not closed it")
	require.NotContains(t, out, hexutil.Encode(done[:]), "anchored already")
	require.NotContains(t, out, hexutil.Encode(other[:]), "it backs no lot of this identity")
	require.Contains(t, out, "skip: anchor closed term "+hexutil.Encode(later[:]), "not anchorable yet: reported, not fatal")
	require.Contains(t, out, "simulation: not run: it can be simulated once the term anchors are included")

	out, err = runValidator(t, home, args...)
	require.NoError(t, err, out)
	require.Equal(t, 4, chain.Sends(), "two anchors, mature and claim: %s", out)
	require.Equal(t, 2, chain.Terms.Anchors)
	require.Contains(t, out, "claimed 100 base units to "+operator.Hex())
}

// review r3 P3: a compact-seat term (sixteen-seat custody: the lot is a seat's, no exposure lots) is anchored, and an anchor that loses to another
// party's between the preview and the send is accepted (the term is anchored), so the claim matures and claims.
func TestValidatorClaimAnchorsACompactSeatTermAndSurvivesALostRace(t *testing.T) {
	chain, url := fakeNetwork(t)
	home := initHome(t, url)
	_, keys := loadHome(t, home)
	operator := ethcrypto.PubkeyToAddress(keys.Operator.PublicKey)
	chain.Fund(operator, big.NewInt(1e18))
	id := chain.AddMember(operator, vrclient.Registration{RootNodeID: "seat-root", EvmNodeID: "seat-evm"})
	seat, raced, foreign := [32]byte{0x5e}, [32]byte{0x7a}, [32]byte{0xf0}
	lot := big.NewInt(9)
	chain.Mu.Lock()
	chain.Tag = vrclient.ModuleTagPoS
	chain.Custody = ethcommon.Address{0xc1}
	chain.Election = ethcommon.Address{0xe1}
	chain.ClaimLots = []*big.Int{lot}
	chain.Terms = &vrfake.Terms{
		Closures:   [][3][32]byte{{seat, {0x01}, {0x02}}, {raced, {0x03}, {0x04}}, {foreign, {0x05}, {0x06}}},
		Closed:     map[[32]byte]bool{seat: true, raced: true, foreign: true},
		Anchored:   map[[32]byte]bool{},
		Unanchored: map[string]uint32{"9": 2},
		Seats:      map[[32]byte][]*big.Int{seat: {big.NewInt(3), lot}, raced: {lot}, foreign: {big.NewInt(4), big.NewInt(5)}},
		Race:       map[[32]byte]bool{raced: true},
	}
	chain.Mu.Unlock()

	out, err := runValidator(t, home, "claim", "--id", fmt.Sprint(id))
	require.NoError(t, err, out)
	require.Contains(t, out, "[anchor] anchor closed term "+hexutil.Encode(seat[:]), "the compact seat's lot is this identity's")
	require.NotContains(t, out, hexutil.Encode(foreign[:]), "no seat of that term is this identity's lot")
	require.Contains(t, out, "anchored meanwhile by another party")
	require.Equal(t, 1, chain.Terms.Anchors, "the seat term by this claim; the raced one by the other party")
	require.True(t, chain.Terms.Anchored[raced])
	require.Contains(t, out, "claimed 100 base units to "+operator.Hex())
}

func TestValidatorApplyAdmitExit(t *testing.T) {
	chain, url := fakeNetwork(t)
	home := initHome(t, url)
	_, keys := loadHome(t, home)
	operator := ethcrypto.PubkeyToAddress(keys.Operator.PublicKey)
	chain.Fund(operator, big.NewInt(1e18))

	// status before apply: no identity, the genesis committee
	out, err := runValidator(t, home, "status")
	require.NoError(t, err, out)
	require.Contains(t, out, "no VR identity for this operator")
	require.Contains(t, out, "committee: root epoch 1, 4 members [1 2 3 4]")
	require.Contains(t, out, "local ureth "+url+": in sync")

	// dry run: both transactions previewed, nothing sent
	out, err = runValidator(t, home, "apply", "--dry-run")
	require.NoError(t, err, out)
	require.Contains(t, out, "ValidatorRegistry.register(")
	require.Contains(t, out, "PoaElection.submitApplication(")
	require.Contains(t, out, "apply identity 5 (predicted)")
	require.Contains(t, out, "simulation: ok")
	require.Contains(t, out, "simulation: not run: it applies the identity the registration creates")
	require.Contains(t, out, "dry run: nothing sent")
	require.Zero(t, chain.Sends())

	out, err = runValidator(t, home, "apply")
	require.NoError(t, err, out)
	require.Equal(t, 2, chain.Sends(), out)
	require.Contains(t, out, "registered identity 5")
	require.Equal(t, uint64(5), readConfig(t, home).ID)
	require.Equal(t, vrclient.PoaApplied, chain.State(5))
	require.Equal(t, operator, chain.Identity(5).Owner)

	// a second apply: the module refuses Applied, before anything is sent
	_, err = runValidator(t, home, "apply")
	require.ErrorContains(t, err, "identity 5 is Applied; apply needs None or Exited")
	require.Equal(t, 2, chain.Sends())

	// the Foundation admits (a test-side state change): status shows Admitted, the queued change and the local keys
	chain.SetState(5, vrclient.PoaAdmitted)
	payload, err := vrclient.EncodeModuleAction(chain.Module, vrclient.ActionConfirmExit, 5)
	require.NoError(t, err)
	chain.Mu.Lock()
	chain.Changes[7] = vrclient.ChangeView{Kind: vrclient.KindModuleAction, State: 1, NotBeforeProgress: 7000, NotBeforeTime: 1_700_003_600, Payload: payload}
	chain.Pending = []uint64{7}
	chain.Mu.Unlock()
	out, err = runValidator(t, home, "status")
	require.NoError(t, err, out)
	require.Contains(t, out, "validator 5 (owner "+operator.Hex())
	require.Contains(t, out, "PoA state   Admitted")
	require.Contains(t, out, "local keys  match the current binding")
	require.Contains(t, out, "governance  change 7 ModuleAction ConfirmExit: Queued, executable at progress 7000")
	require.Contains(t, out, "member      false")
	out, err = runValidator(t, home, "status", "--json")
	require.NoError(t, err, out)
	var rep validatorStatusReport
	require.NoError(t, json.Unmarshal([]byte(out), &rep))
	require.Equal(t, "Admitted", rep.PoaState)
	require.Equal(t, []uint64{1, 2, 3, 4}, rep.Committee)

	// exit while Admitted: the owner cannot; it says who can
	_, err = runValidator(t, home, "exit")
	require.ErrorContains(t, err, "ask the Foundation for ModuleAction Remove")

	// Active (after a boundary): exit requests it
	chain.SetState(5, vrclient.PoaActive)
	out, err = runValidator(t, home, "exit", "--dry-run")
	require.NoError(t, err, out)
	require.Contains(t, out, "PoaElection.requestExit(")
	require.Equal(t, vrclient.PoaActive, chain.State(5))
	out, err = runValidator(t, home, "exit")
	require.NoError(t, err, out)
	require.Equal(t, vrclient.PoaExitRequested, chain.State(5))
	_, err = runValidator(t, home, "exit")
	require.ErrorContains(t, err, "already requested")
}

func TestValidatorWithdrawRejoinRotate(t *testing.T) {
	chain, url := fakeNetwork(t)
	home := initHome(t, url)
	_, keys := loadHome(t, home)
	chain.Fund(ethcrypto.PubkeyToAddress(keys.Operator.PublicKey), big.NewInt(1e18))
	out, err := runValidator(t, home, "apply")
	require.NoError(t, err, out)

	// exit before admission withdraws the application
	out, err = runValidator(t, home, "exit")
	require.NoError(t, err, out)
	require.Contains(t, out, "PoaElection.withdrawApplication(")
	require.Equal(t, vrclient.PoaNone, chain.State(5))
	// apply again reuses the registered identity: one transaction
	sent := chain.Sends()
	out, err = runValidator(t, home, "apply")
	require.NoError(t, err, out)
	require.Contains(t, out, "already registered with these keys: applying only")
	require.Equal(t, sent+1, chain.Sends())

	// rejoin only from Parked
	_, err = runValidator(t, home, "rejoin")
	require.ErrorContains(t, err, "rejoin needs Parked")
	chain.SetState(5, vrclient.PoaParked)
	out, err = runValidator(t, home, "rejoin")
	require.NoError(t, err, out)
	require.Equal(t, vrclient.PoaAdmitted, chain.State(5))

	// rotate the EVM node's keys: staged, with both PoPs over the binding digest
	newEVM := filepath.Join(t.TempDir(), "keys.json")
	_, _, err = ensureKeyConf(newEVM)
	require.NoError(t, err)
	_, err = runValidator(t, home, "rotate")
	require.ErrorContains(t, err, "--new-root-keys")
	out, err = runValidator(t, home, "rotate", "--new-evm-keys", newEVM, "--dry-run")
	require.NoError(t, err, out)
	require.Contains(t, out, "ValidatorRegistry.proposeBinding(")
	require.Nil(t, chain.Identity(5).Staged)
	out, err = runValidator(t, home, "rotate", "--new-evm-keys", newEVM, "--new-payee", "0x00000000000000000000000000000000000000bb")
	require.NoError(t, err, out)
	require.NotNil(t, chain.Identity(5).Staged)
	require.Equal(t, uint64(1), chain.Identity(5).BindingNonce)
	out, err = runValidator(t, home, "status")
	require.NoError(t, err, out)
	require.Contains(t, strings.ToLower(out), "payee 0x00000000000000000000000000000000000000bb (installed at the next boundary")
	require.Contains(t, out, "local keys  match the current binding")
	// the same proposal again is a new nonce and the same keys: VR allows it (it replaces the staged one)
	out, err = runValidator(t, home, "rotate", "--new-evm-keys", newEVM, "--dry-run")
	require.NoError(t, err, out)
	require.Contains(t, out, "note: a staged binding")
	// the root node's key as the EVM node's: refused before anything is built
	other := filepath.Join(home, "root", keyConfFileName)
	out, err = runValidator(t, home, "rotate", "--new-evm-keys", other, "--dry-run")
	require.ErrorContains(t, err, "keys are shared between services", out)
}

func TestValidatorRefusalsAreDecoded(t *testing.T) {
	chain, url := fakeNetwork(t)
	home := initHome(t, url)
	_, keys := loadHome(t, home)
	// a genesis member already holds this validator's root key: VR refuses register, and the preview names the refusal
	root, err := nodeKeys(keys.Root)
	require.NoError(t, err)
	ek, _ := ethcrypto.GenerateKey()
	chain.AddMember(ethcommon.HexToAddress("0x1111111111111111111111111111111111111111"), vrclient.Registration{RootNodeID: "x", RootKey: root.Public(),
		EvmNodeID: "y", EvmKey: ethcrypto.CompressPubkey(&ek.PublicKey), Payee: ethcommon.HexToAddress("0x01")})
	out, err := runValidator(t, home, "apply")
	require.Error(t, err)
	require.Contains(t, out, "simulation: REFUSED")
	require.Contains(t, err.Error(), "RegistrationRefused(6): a key is already registered")
	require.Zero(t, chain.Sends())

	// an endpoint that refuses log queries: the operator is asked for --id
	chain.With(func(c *vrfake.Chain) { c.NoLogs = true })
	_, err = runValidator(t, home, "exit")
	require.ErrorContains(t, err, "pass --id")

	// a module that is not PoaElection
	chain.With(func(c *vrfake.Chain) { c.Tag = [32]byte{1} })
	_, err = runValidator(t, home, "exit", "--id", "1")
	require.ErrorContains(t, err, "is not PoaElection v1")

	// an RPC of another chain
	home2 := initHome(t, url, "--chain-id", "7")
	_, err = runValidator(t, home2, "status")
	require.ErrorContains(t, err, "the RPC serves chain 3, the config expects 7")

	// --id of an identity the operator does not own
	chain.With(func(c *vrfake.Chain) { c.Tag = vrclient.ModuleTagPoA })
	_, err = runValidator(t, home, "exit", "--id", "2")
	require.ErrorContains(t, err, "identity 2 is owned by")
}

func TestValidatorDoctor(t *testing.T) {
	chain, url := fakeNetwork(t)
	home := initHome(t, url)
	_, keys := loadHome(t, home)
	host := hostFacts{OS: "linux", Cores: 6, Threads: 12, MemBytes: 66_500_000_000, NVMe: []uint64{1_000_204_886_016, 1_000_204_886_016},
		FreeBytes: func(string) (uint64, error) { return 900e9, nil }, NTPSynced: func() (bool, string) { return true, "NTPSynchronized=yes" },
		CanListen: func(p int) error {
			if p == 30303 {
				return fmt.Errorf("address already in use")
			}
			return nil
		},
		Now: func() time.Time { return time.Unix(1_700_000_010, 0) }, HTTPTimeout: 2 * time.Second}
	run := func(h hostFacts) (string, error) {
		var out bytes.Buffer
		f := &validatorDoctorFlags{validatorFlags: validatorFlags{baseFlags: &baseFlags{HomeDir: home}}}
		err := validatorDoctor(context.Background(), &out, f, h)
		return out.String(), err
	}
	// the head block is 10 s old by the fake clock, while the HTTP Date is the real one: use the real clock for the skew
	host.Now = time.Now
	chain.Mu.Lock()
	chain.HeadTime = uint64(time.Now().Unix())
	chain.Mu.Unlock()
	out, err := run(host)
	require.NoError(t, err, out)
	for _, want := range []string{"[PASS] cpu              6 cores, 12 threads", "[PASS] memory           66 GB", "[PASS] nvme             2 NVMe devices",
		"[WARN] port 30303", "[PASS] port 8000", "[PASS] key separation", "[PASS] public RPC", "[PASS] clock skew", "[PASS] VR",
		"[WARN] operator funds", "fix: fund the operator account"} {
		require.Contains(t, out, want)
	}
	chain.Fund(ethcrypto.PubkeyToAddress(keys.Operator.PublicKey), big.NewInt(1))

	chain.With(func(c *vrfake.Chain) {
		c.Tag = vrclient.ModuleTagPoS
		c.Custody = ethcommon.HexToAddress("0x80")
	})
	out, err = run(host)
	require.Error(t, err)
	require.Contains(t, out, "names no P85 election")

	chain.With(func(c *vrfake.Chain) { c.Election = c.Seal })
	out, err = run(host)
	require.Error(t, err)
	require.Contains(t, out, "does not serve openResult")

	chain.With(func(c *vrfake.Chain) { c.Election = ethcommon.HexToAddress("0x81") })
	out, err = run(host)
	require.NoError(t, err)
	require.Contains(t, out, "PoS module")
	chain.With(func(c *vrfake.Chain) { c.Tag = vrclient.ModuleTagPoA })

	weak := host
	weak.Cores, weak.Threads, weak.MemBytes, weak.NVMe = 4, 8, 32e9, []uint64{512e9}
	weak.NTPSynced = func() (bool, string) { return false, "NTPSynchronized=no" }
	weak.Now = func() time.Time { return time.Now().Add(-time.Minute) }
	out, err = run(weak)
	require.ErrorContains(t, err, "6 of")
	for _, want := range []string{"[FAIL] cpu", "[FAIL] memory", "[FAIL] nvme", "[FAIL] clock sync", "[FAIL] clock skew", "[FAIL] VR"} {
		require.Contains(t, out, want)
	}

	require.NoError(t, os.Chmod(filepath.Join(home, "operator/key"), 0o644))
	require.NoError(t, os.Remove(filepath.Join(home, "jwt/jwt.hex")))
	out, err = run(host)
	require.Error(t, err)
	require.Contains(t, out, "[WARN] operator key")
	require.Contains(t, out, "chmod 600")
	require.Contains(t, out, "[FAIL] engine JWT")
}

func TestHostFactParsers(t *testing.T) {
	dir := t.TempDir()
	cpuinfo := ""
	for p := 0; p < 12; p++ {
		cpuinfo += fmt.Sprintf("processor\t: %d\nphysical id\t: 0\ncore id\t\t: %d\n\n", p, p%6)
	}
	require.NoError(t, os.WriteFile(filepath.Join(dir, "cpuinfo"), []byte(cpuinfo), 0o600))
	require.Equal(t, 6, linuxPhysicalCores(filepath.Join(dir, "cpuinfo")))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "meminfo"), []byte("MemTotal:       65748716 kB\nMemFree: 1 kB\n"), 0o600))
	require.Equal(t, uint64(65748716*1024), linuxMemTotal(filepath.Join(dir, "meminfo")))
	for _, d := range []string{"nvme0n1", "nvme1n1", "sda"} {
		require.NoError(t, os.MkdirAll(filepath.Join(dir, "block", d), 0o700))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "block", d, "size"), []byte("1953525168\n"), 0o600))
	}
	require.Equal(t, []uint64{1953525168 * 512, 1953525168 * 512}, linuxNVMe(filepath.Join(dir, "block")))
}
