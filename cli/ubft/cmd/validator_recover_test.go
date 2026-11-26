package cmd

import (
	"bytes"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	ethcommon "github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/vrclient"
	"github.com/unicitynetwork/bft-core/vrclient/vrfake"
)

// recoverFixture is a bonded PoS identity owned by the home's operator, registered and delegated with the home's keys at custody
// generation 1, a fresh EVM key file and the lost authority's preserved volume with its fail-stop marker.
type recoverFixture struct {
	chain  *vrfake.Chain
	home   string
	id     uint64
	old    vrclient.Registration
	want   vrclient.Registration
	newEVM string
	marker string
}

func newRecoverFixture(t *testing.T) *recoverFixture {
	t.Helper()
	chain, url := fakeNetwork(t)
	home := initHome(t, url)
	v, keys := loadHome(t, home)
	operator := ethcrypto.PubkeyToAddress(keys.Operator.PublicKey)
	chain.Fund(operator, big.NewInt(1e18))
	reg, _, _, err := registration(v, keys, 0)
	require.NoError(t, err)
	id := chain.AddMember(operator, reg)
	newEVM := filepath.Join(t.TempDir(), "keys.json")
	_, _, err = ensureKeyConf(newEVM)
	require.NoError(t, err)
	kc, err := readKeyConf(newEVM)
	require.NoError(t, err)
	nk, err := nodeKeys(kc)
	require.NoError(t, err)
	want := reg
	want.EvmNodeID, want.EvmKey = nk.NodeID, nk.Public()
	marker := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(marker, authorityLifetimeMarker), []byte("fail-stop\n"), 0o600))
	chain.With(func(c *vrfake.Chain) {
		c.Tag = vrclient.ModuleTagPoS
		c.Custody = ethcommon.Address{0xc1}
		c.Election = ethcommon.Address{0xe1}
		c.Evidence = ethcommon.Address{0xe2}
		c.Pos = vrfake.NewPos()
		c.Pos.Positions[id] = &vrfake.Position{RootKeyHash: [32]byte(ethcrypto.Keccak256(reg.RootKey)), Generation: 1, OpenLots: 1}
		c.Pos.Delegations[[2]uint64{id, 1}] = &vrfake.Delegated{Binding: delegationOf(reg), NextNonce: 1}
	})
	return &recoverFixture{chain: chain, home: home, id: id, old: reg, want: want, newEVM: newEVM, marker: marker}
}

func (f *recoverFixture) recover(t *testing.T, extra ...string) (string, error) {
	t.Helper()
	args := append([]string{"recover", "--id", fmt.Sprint(f.id), "--new-evm-keys", f.newEVM, "--old-authority-home", f.marker}, extra...)
	return runValidator(t, f.home, args...)
}

func (f *recoverFixture) delegation() vrclient.Delegation {
	var d vrclient.Delegation
	f.chain.With(func(c *vrfake.Chain) { d = c.Pos.Delegations[[2]uint64{f.id, 1}].Binding })
	return d
}

func selector(abiMethod []byte) []byte { return abiMethod[:4] }

// The delegation is sent and confirmed before VR's binding; a second run sends nothing.
func TestValidatorRecoverSendsTheDelegationFirstThenTheBinding(t *testing.T) {
	f := newRecoverFixture(t)
	out, err := f.recover(t, "--dry-run")
	require.NoError(t, err, out)
	require.Zero(t, f.chain.Sends())
	ia, is := strings.Index(out, "[1] admit identity"), strings.Index(out, "[2] stage the identical binding")
	require.True(t, ia >= 0 && is > ia, "delegation first, then VR: %s", out)
	require.Contains(t, out, "simulation: not run: it is sent after the delegation confirms")

	out, err = f.recover(t)
	require.NoError(t, err, out)
	require.Equal(t, 2, f.chain.Sends(), out)
	f.chain.With(func(c *vrfake.Chain) {
		require.Equal(t, selector(vrclient.PosElectionABI.Methods["admitDelegation"].ID), c.Sent[0][:4], "admitDelegation first")
		require.Equal(t, selector(vrclient.VRABI.Methods["proposeBinding"].ID), c.Sent[1][:4], "then proposeBinding")
	})
	require.True(t, sameDelegation(f.delegation(), delegationOf(f.want)), "the delegation is the new words at custody's generation")
	staged := f.chain.Identity(f.id).Staged
	require.NotNil(t, staged)
	require.Equal(t, f.want.EvmKey, staged.EvmKey, "VR stages the identical words")
	require.Equal(t, f.want.RootKey, staged.RootKey)
	require.Contains(t, out, "confirmed: identity")

	out, err = f.recover(t)
	require.NoError(t, err, out)
	require.Equal(t, 2, f.chain.Sends(), "a re-run sends nothing")
	require.Contains(t, out, "nothing to do")
}

// A run interrupted after the delegation resumes with the binding only; one where VR was staged first (an old-style rotate) sends only
// the delegation.
func TestValidatorRecoverResumesFromEitherStep(t *testing.T) {
	f := newRecoverFixture(t)
	f.chain.With(func(c *vrfake.Chain) {
		c.Pos.Delegations[[2]uint64{f.id, 1}] = &vrfake.Delegated{Binding: delegationOf(f.want), NextNonce: 2}
	})
	out, err := f.recover(t)
	require.NoError(t, err, out)
	require.Equal(t, 1, f.chain.Sends(), out)
	require.Contains(t, out, "already done: identity")
	f.chain.With(func(c *vrfake.Chain) {
		require.Equal(t, selector(vrclient.VRABI.Methods["proposeBinding"].ID), c.Sent[0][:4])
		require.Zero(t, c.Pos.Admitted)
	})

	g := newRecoverFixture(t)
	g.chain.With(func(c *vrfake.Chain) {
		w := g.want
		c.Identities[g.id].Staged = &w
		c.KeyOwner[ethcrypto.Keccak256Hash(w.EvmKey)] = g.id
	})
	out, err = g.recover(t)
	require.NoError(t, err, out)
	require.Equal(t, 1, g.chain.Sends(), out)
	g.chain.With(func(c *vrfake.Chain) {
		require.Equal(t, selector(vrclient.PosElectionABI.Methods["admitDelegation"].ID), c.Sent[0][:4])
	})
	require.True(t, sameDelegation(g.delegation(), delegationOf(g.want)))
}

// Each refusal sends nothing.
func TestValidatorRecoverRefusals(t *testing.T) {
	for name, c := range map[string]struct {
		setup func(f *recoverFixture)
		args  func(f *recoverFixture) []string
		want  string
	}{
		"no marker volume": {args: func(f *recoverFixture) []string {
			return []string{"recover", "--id", fmt.Sprint(f.id), "--new-evm-keys", f.newEVM}
		}, want: "--old-authority-home is required"},
		"no fail-stop marker": {setup: func(f *recoverFixture) {
			require.NoError(t, os.Remove(filepath.Join(f.marker, authorityLifetimeMarker)))
		}, want: "no fail-stop marker"},
		"another custody owner": {setup: func(f *recoverFixture) {
			f.chain.With(func(c *vrfake.Chain) { c.Pos.Positions[f.id].Owner = ethcommon.Address{0x99} })
		}, want: "not the operator"},
		"not bonded": {setup: func(f *recoverFixture) {
			f.chain.With(func(c *vrfake.Chain) { c.Pos.Positions[f.id].OpenLots = 0 })
		}, want: "no open lots"},
		"retirement requested": {setup: func(f *recoverFixture) {
			f.chain.With(func(c *vrfake.Chain) { c.Pos.Positions[f.id].RetirementRequested = true })
		}, want: "requested retirement"},
		"excluded": {setup: func(f *recoverFixture) {
			f.chain.With(func(c *vrfake.Chain) { c.Pos.Positions[f.id].Excluded = true })
		}, want: "excluded by evidence"},
		"root key changed": {setup: func(f *recoverFixture) {
			f.chain.With(func(c *vrfake.Chain) { c.Pos.Positions[f.id].RootKeyHash = [32]byte{7} })
		}, want: "root-key change is refused"},
		"payee changed": {setup: func(f *recoverFixture) {
			out, err := runValidator(t, f.home, "init", "--force", "--rpc", readConfig(t, f.home).RPC, "--payee", "0x00000000000000000000000000000000000000aa")
			require.NoError(t, err, out)
		}, want: "changes the EVM key only"},
		"a frozen staged binding": {setup: func(f *recoverFixture) {
			f.chain.With(func(c *vrfake.Chain) {
				other := f.want
				other.EvmNodeID = "frozen-evm"
				k, _ := ethcrypto.GenerateKey()
				other.EvmKey = ethcrypto.CompressPubkey(&k.PublicKey)
				c.Identities[f.id].Staged = &other
				c.Pos.OpenResult = [32]byte{0x0f}
				c.Pos.Frozen = []vrclient.FrozenMember{{Id: f.id, Generation: 1, Weight: 1, Raw: 1, BindingHash: vrfake.BindingHash(f.id, 1, delegationOf(other))}}
			})
		}, want: "froze identity"},
		"not PoS": {setup: func(f *recoverFixture) {
			f.chain.With(func(c *vrfake.Chain) { c.Tag = vrclient.ModuleTagPoA })
		}, want: "recover is the PoS adapter's"},
		"new authority in the marked volume": {args: func(f *recoverFixture) []string {
			return []string{"recover", "--id", fmt.Sprint(f.id), "--old-authority-home", f.marker, "--new-evm-authority-socket", filepath.Join(f.marker, "operator.sock"),
				"--new-evm-authority-credential", filepath.Join(f.marker, "operator.cred"), "--new-evm-node-info", filepath.Join(f.marker, "node-info.json")}
		}, want: "use a fresh authority volume"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newRecoverFixture(t)
			if c.setup != nil {
				c.setup(f)
			}
			var out string
			var err error
			if c.args != nil {
				out, err = runValidator(t, f.home, c.args(f)...)
			} else {
				out, err = f.recover(t)
			}
			require.ErrorContains(t, err, c.want, out)
			require.Zero(t, f.chain.Sends(), "refused before any transaction")
		})
	}
}

// A staged binding that is not the open result's frozen one may be replaced.
func TestValidatorRecoverReplacesAnUnfrozenStagedBinding(t *testing.T) {
	f := newRecoverFixture(t)
	f.chain.With(func(c *vrfake.Chain) {
		other := f.want
		other.EvmNodeID = "dead-evm"
		k, _ := ethcrypto.GenerateKey()
		other.EvmKey = ethcrypto.CompressPubkey(&k.PublicKey)
		c.Identities[f.id].Staged = &other
		c.Pos.OpenResult = [32]byte{0x0f}
		c.Pos.Frozen = []vrclient.FrozenMember{{Id: f.id, Generation: 1, Weight: 1, Raw: 1, BindingHash: vrfake.BindingHash(f.id, 1, delegationOf(f.old))}}
	})
	out, err := f.recover(t)
	require.NoError(t, err, out)
	require.Equal(t, 2, f.chain.Sends(), out)
	require.Equal(t, f.want.EvmKey, f.chain.Identity(f.id).Staged.EvmKey)
}

// rotate on the PoS adapter is the same two transactions (no fail-stop preflight); a root-key change is refused.
func TestValidatorRotatePoSIsDelegationThenBinding(t *testing.T) {
	f := newRecoverFixture(t)
	newRoot := filepath.Join(t.TempDir(), "keys.json")
	_, _, err := ensureKeyConf(newRoot)
	require.NoError(t, err)
	out, err := runValidator(t, f.home, "rotate", "--id", fmt.Sprint(f.id), "--new-root-keys", newRoot)
	require.ErrorContains(t, err, "root-key loss or change takes the exit path", out)
	require.Zero(t, f.chain.Sends())

	out, err = runValidator(t, f.home, "rotate", "--id", fmt.Sprint(f.id), "--new-evm-keys", f.newEVM)
	require.NoError(t, err, out)
	require.Equal(t, 2, f.chain.Sends(), out)
	f.chain.With(func(c *vrfake.Chain) {
		require.Equal(t, selector(vrclient.PosElectionABI.Methods["admitDelegation"].ID), c.Sent[0][:4])
		require.Equal(t, selector(vrclient.VRABI.Methods["proposeBinding"].ID), c.Sent[1][:4])
	})
	require.True(t, sameDelegation(f.delegation(), delegationOf(f.want)))
}

// apply on a bonded identity refuses a delegation that is not VR's current or staged binding and names rotate and recover.
func TestValidatorApplyPoSRefusesADelegationOtherThanVRsBinding(t *testing.T) {
	f := newRecoverFixture(t)
	// the configured EVM key is now another one than VR's binding
	evmKeys := filepath.Join(f.home, "evm", keyConfFileName)
	raw, err := os.ReadFile(f.newEVM)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(evmKeys, raw, 0o600))
	f.chain.With(func(c *vrfake.Chain) { c.Pos.Delegations[[2]uint64{f.id, 1}].NextNonce = 1 })
	out, err := runValidator(t, f.home, "apply", "--id", fmt.Sprint(f.id))
	require.ErrorContains(t, err, "ubft validator rotate", out)
	require.ErrorContains(t, err, "validator recover", out)
	require.Zero(t, f.chain.Sends())

	// the identical words staged in VR: apply admits them (the delegation follows VR)
	f.chain.With(func(c *vrfake.Chain) {
		w := f.want
		c.Identities[f.id].Staged = &w
		c.KeyOwner[ethcrypto.Keccak256Hash(w.EvmKey)] = f.id
	})
	out, err = runValidator(t, f.home, "apply", "--id", fmt.Sprint(f.id))
	require.NoError(t, err, out)
	require.Equal(t, 1, f.chain.Sends(), out)
	require.True(t, bytes.Equal(f.delegation().EvmKey, f.want.EvmKey))
}

// delegationBindingHash is ElectionPolicy._bindingHash: keccak256(abi.encode(BINDING_DOMAIN, id, generation, rootNodeID, keccak(rootKey),
// evmNodeID, keccak(evmKey), payee)).
func TestDelegationBindingHashIsTheElectionsFormula(t *testing.T) {
	d := vrclient.Delegation{RootNodeID: [32]byte{1}, RootKey: []byte{2}, EvmNodeID: [32]byte{3}, EvmKey: []byte{4}, OperatorPayee: [20]byte{5}}
	ty := func(s string) abi.Type { x, err := abi.NewType(s, "", nil); require.NoError(t, err); return x }
	b32 := ty("bytes32")
	args := abi.Arguments{{Type: b32}, {Type: ty("uint64")}, {Type: ty("uint64")}, {Type: b32}, {Type: b32}, {Type: b32}, {Type: b32}, {Type: ty("address")}}
	enc, err := args.Pack([32]byte(ethcrypto.Keccak256([]byte("unicity.p85.delegation-binding"))), uint64(9), uint64(2), d.RootNodeID,
		[32]byte(ethcrypto.Keccak256(d.RootKey)), d.EvmNodeID, [32]byte(ethcrypto.Keccak256(d.EvmKey)), ethcommon.Address(d.OperatorPayee))
	require.NoError(t, err)
	require.Equal(t, [32]byte(ethcrypto.Keccak256(enc)), delegationBindingHash(9, 2, d))
	require.Equal(t, vrfake.BindingHash(9, 2, d), delegationBindingHash(9, 2, d))
}

// A new EVM key is a new EVM node identity: a new key under the old EVM node id is refused.
func TestPlanPosKeyChangeRefusesANewKeyUnderTheOldNodeID(t *testing.T) {
	f := newRecoverFixture(t)
	var st posBindingState
	f.chain.With(func(c *vrfake.Chain) {
		idn := c.Identities[f.id]
		st = posBindingState{ID: f.id, Position: custodyPosition{Owner: idn.Owner, RootKeyHash: [32]byte(ethcrypto.Keccak256(f.old.RootKey)), Generation: 1, OpenLots: 1},
			Delegation: delegationOf(f.old), DelegationNonce: 1,
			Identity: vrclient.IdentityView{Owner: idn.Owner, Generation: 1, CurrentRef: [32]byte{1}, Current: vrclient.Binding{RootNodeID: f.old.RootNodeID,
				RootKey: f.old.RootKey, EvmNodeID: f.old.EvmNodeID, EvmKey: f.old.EvmKey, Payee: f.old.Payee}}}
	})
	same := f.want
	same.EvmNodeID = f.old.EvmNodeID
	_, err := planPosKeyChange(st, st.Position.Owner, same, true)
	require.ErrorContains(t, err, "a new EVM key is a new EVM node identity")
	p, err := planPosKeyChange(st, st.Position.Owner, f.want, true)
	require.NoError(t, err)
	require.Equal(t, posKeyChange{Admit: true, Stage: true}, p)
}

// #1303: status shows a PoS identity's park while it lasts, and nothing once root progress has reached its end.
func TestValidatorStatusShowsAPoSPark(t *testing.T) {
	f := newRecoverFixture(t)
	f.chain.With(func(c *vrfake.Chain) {
		c.Progress = 1_000
		c.Pos.ParkedUntil = map[uint64]uint64{f.id: 33_768}
	})
	out, err := runValidator(t, f.home, "status", "--id", fmt.Sprint(f.id))
	require.NoError(t, err, out)
	require.Contains(t, out, "parked      until progress 33768 (32768 rounds left)")
	out, err = runValidator(t, f.home, "status", "--id", fmt.Sprint(f.id), "--json")
	require.NoError(t, err, out)
	require.Contains(t, out, `"parkedUntilProgress": 33768`)

	f.chain.With(func(c *vrfake.Chain) { c.Progress = 33_768 })
	out, err = runValidator(t, f.home, "status", "--id", fmt.Sprint(f.id))
	require.NoError(t, err, out)
	require.NotContains(t, out, "parked ")
}
