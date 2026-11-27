package cmd

import (
	"bytes"
	"context"
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

	"github.com/unicitynetwork/bft-core/signingauthority"
	"github.com/unicitynetwork/bft-core/vrclient"
	"github.com/unicitynetwork/bft-core/vrclient/vrfake"
	"github.com/unicitynetwork/bft-core/vrschema"
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

// #1222 (astra's REORDER): VR's binding is sent and confirmed before the delegation; a second run sends nothing.
func TestValidatorRecoverStagesTheBindingFirstThenTheDelegation(t *testing.T) {
	f := newRecoverFixture(t)
	out, err := f.recover(t, "--dry-run")
	require.NoError(t, err, out)
	require.Zero(t, f.chain.Sends())
	is, ia := strings.Index(out, "[1] stage the identical binding"), strings.Index(out, "then: admit identity")
	require.True(t, is >= 0 && ia > is, "VR first, then the delegation: %s", out)
	require.Contains(t, out, "after VR's binding confirms")

	out, err = f.recover(t)
	require.NoError(t, err, out)
	require.Equal(t, 2, f.chain.Sends(), out)
	f.chain.With(func(c *vrfake.Chain) {
		require.Equal(t, selector(vrclient.VRABI.Methods["proposeBinding"].ID), c.Sent[0][:4], "proposeBinding first")
		require.Equal(t, selector(vrclient.PosElectionABI.Methods["admitDelegation"].ID), c.Sent[1][:4], "then admitDelegation")
	})
	require.Less(t, strings.Index(out, "confirmed: VR stages identity"), strings.Index(out, "confirmed: identity"), out)
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

// A run interrupted after VR's binding resumes with the delegation only; one where the delegation was admitted first (the earlier
// delegation-first order) sends only the binding.
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

// rotate on the PoS adapter is the same two transactions, VR's binding first (no fail-stop preflight); a root-key change is refused.
func TestValidatorRotatePoSIsBindingThenDelegation(t *testing.T) {
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
		require.Equal(t, selector(vrclient.VRABI.Methods["proposeBinding"].ID), c.Sent[0][:4])
		require.Equal(t, selector(vrclient.PosElectionABI.Methods["admitDelegation"].ID), c.Sent[1][:4])
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

// chainPosSource is the fresh authority's execution client over the fake chain (#1222): an id is bound once VR's current or staged binding
// names the authority's node and key. It records the binding state each pin saw.
type chainPosSource struct {
	chain *vrfake.Chain
	view  signingauthority.PosDeploymentView
	seen  []bool
	// onBound runs when a read finds the id bound: a concurrent change while the pin is verified
	onBound func()
}

func (s *chainPosSource) ReadPosDeployment(_ context.Context, q signingauthority.PosQuery) (signingauthority.PosDeploymentView, error) {
	v := s.view
	for _, id := range q.IDs {
		idn := s.chain.Identity(id)
		bound := idn != nil && ((idn.Current.EvmNodeID == q.NodeID && bytes.Equal(idn.Current.EvmKey, q.EVMKey)) ||
			(idn.Staged != nil && idn.Staged.EvmNodeID == q.NodeID && bytes.Equal(idn.Staged.EvmKey, q.EVMKey)))
		s.seen = append(s.seen, bound)
		if bound && s.onBound != nil {
			s.onBound()
		}
		if !bound {
			v.Unbound = map[uint64][20]byte{id: idn.Owner}
		}
	}
	return v, nil
}

// freshAuthorityRecover is a recover fixture whose new EVM key is a fresh in-process signing authority over the fake chain, with a binding
// authorization for the identity and a P85 source reading VR; args runs recover onto it with the release's pin template.
type freshAuthorityRecover struct {
	*recoverFixture
	src  *chainPosSource
	a    *evmAuthority
	args []string
}

func newFreshAuthorityRecover(t *testing.T) *freshAuthorityRecover {
	f := newRecoverFixture(t)
	v, keys := loadHome(t, f.home)
	operator := ethcrypto.PubkeyToAddress(keys.Operator.PublicKey)
	root, err := nodeKeys(keys.Root)
	require.NoError(t, err)
	payee, err := v.payee()
	require.NoError(t, err)
	var network [32]byte
	var chainID *big.Int
	var election ethcommon.Address
	f.chain.With(func(c *vrfake.Chain) { network, chainID, election = c.Network, c.ChainID, c.Election })
	src := &chainPosSource{chain: f.chain, view: signingauthority.PosDeploymentView{Network: network, ChainID: vrschema.U64(chainID.Uint64()), Election: [20]byte(election)}}
	policy := signingauthority.RegistrationPolicy{Deployment: signingauthority.RegistrationDeployment{Network: network, ChainID: vrschema.U64(chainID.Uint64()), Registry: vrclient.DefaultRegistry},
		Authorized: []signingauthority.RegistrationAuthorization{{Domain: vrschema.BindingDomainText, Owner: operator, ID: f.id, RootNodeID: root.NodeID, RootKey: root.Public(), Payee: payee}}}
	socket, cred, info := startAuthority(t, policy, signingauthority.WithPosSource(src, chainID.Uint64()), signingauthority.WithRequirePosPolicy())
	a, err := loadEVMAuthority(evmAuthorityConfig{Socket: socket, Credential: cred, NodeInfo: info})
	require.NoError(t, err)
	pin := writePin(t, fmt.Sprintf(`{"network":"0x%x","chainId":%d,"election":"%s"}`, network, chainID.Uint64(), election.Hex()))
	return &freshAuthorityRecover{recoverFixture: f, src: src, a: a, args: []string{"recover", "--id", fmt.Sprint(f.id), "--old-authority-home", f.marker,
		"--new-evm-authority-socket", socket, "--new-evm-authority-credential", cred, "--new-evm-node-info", info, "--pin-pos-policy", pin}}
}

// #1222: recover onto a fresh signing authority stages VR's binding (the authority's proof by op 110, its P85 signing gated), and only
// after it confirms pins the authority (which verifies that binding) and signs the delegation possession. A pin before is refused.
func TestValidatorRecoverOntoAFreshAuthorityPinsAfterTheBinding(t *testing.T) {
	f := newFreshAuthorityRecover(t)
	require.ErrorContains(t, f.a.PinPosPolicy(context.Background(), signingauthority.PosPolicy{IDs: []uint64{f.id}}), "signing-pos-policy-refused",
		"VR does not bind the fresh key yet")
	out, err := runValidator(t, f.home, f.args...)
	require.NoError(t, err, out)
	require.Equal(t, 2, f.chain.Sends(), out)
	f.chain.With(func(c *vrfake.Chain) {
		require.Equal(t, selector(vrclient.VRABI.Methods["proposeBinding"].ID), c.Sent[0][:4])
		require.Equal(t, selector(vrclient.PosElectionABI.Methods["admitDelegation"].ID), c.Sent[1][:4])
	})
	require.Equal(t, []bool{false, true}, f.src.seen, "refused before VR's binding, verified after it")
	ib, ip, id := strings.Index(out, "confirmed: VR stages"), strings.Index(out, "pinned the new signing authority"), strings.Index(out, "confirmed: identity")
	require.True(t, ib >= 0 && ip > ib && id > ip, "binding, pin, delegation: %s", out)
	require.Equal(t, "e2e-evm-auth", f.chain.Identity(f.id).Staged.EvmNodeID)

	out, err = runValidator(t, f.home, f.args...)
	require.NoError(t, err, out)
	require.Equal(t, 2, f.chain.Sends(), "a re-run re-reads both contracts and sends nothing")
	require.Contains(t, out, "nothing to do")
}

// Both contracts are read again after the pin is verified (sol's review of #1328): a matching admission that landed while the authority
// verified the pin is not sent again, and no delegation possession is asked for it.
func TestValidatorRecoverRereadsAfterThePin(t *testing.T) {
	f := newFreshAuthorityRecover(t)
	f.src.onBound = func() {
		f.chain.With(func(c *vrfake.Chain) {
			c.Pos.Delegations[[2]uint64{f.id, 1}] = &vrfake.Delegated{Binding: delegationOf(registrationOfStaged(c, f.id)), NextNonce: 2}
		})
	}
	out, err := runValidator(t, f.home, f.args...)
	require.NoError(t, err, out)
	require.Equal(t, 1, f.chain.Sends(), "only VR's binding: %s", out)
	require.Contains(t, out, "already done: VR's binding and identity")
	f.chain.With(func(c *vrfake.Chain) { require.Zero(t, c.Pos.Admitted) })
}

// registrationOfStaged is VR's staged registration of id (the fake chain's lock held).
func registrationOfStaged(c *vrfake.Chain, id uint64) vrclient.Registration {
	return *c.Identities[id].Staged
}

// A step is skipped only on a fresh read of the latest state (sol's review of #1328): a certified view whose delegation is already the
// new words, while the latest one is not, still sends the delegation; the reverse skips it.
func TestValidatorRecoverDecidesFromTheLatestState(t *testing.T) {
	f := newRecoverFixture(t)
	f.chain.With(func(c *vrfake.Chain) {
		c.FinalizedDelegations = map[[2]uint64]*vrfake.Delegated{{f.id, 1}: {Binding: delegationOf(f.want), NextNonce: 2}}
	})
	out, err := f.recover(t)
	require.NoError(t, err, out)
	require.Equal(t, 2, f.chain.Sends(), "the certified view's delegation does not skip the latest one: %s", out)
	require.True(t, sameDelegation(f.delegation(), delegationOf(f.want)))

	g := newRecoverFixture(t)
	g.chain.With(func(c *vrfake.Chain) {
		c.FinalizedDelegations = map[[2]uint64]*vrfake.Delegated{{g.id, 1}: {Binding: delegationOf(g.old), NextNonce: 1}}
		c.Pos.Delegations[[2]uint64{g.id, 1}] = &vrfake.Delegated{Binding: delegationOf(g.want), NextNonce: 2}
	})
	out, err = g.recover(t)
	require.NoError(t, err, out)
	require.Equal(t, 1, g.chain.Sends(), out)
	g.chain.With(func(c *vrfake.Chain) {
		require.Equal(t, selector(vrclient.VRABI.Methods["proposeBinding"].ID), c.Sent[0][:4], "the latest delegation is the new words: only VR's binding")
	})
}

// otherWords is a registration of the identity's root binding with another fresh EVM node and key.
func otherWords(t *testing.T, base vrclient.Registration, node string) vrclient.Registration {
	k, err := ethcrypto.GenerateKey()
	require.NoError(t, err)
	o := base
	o.EvmNodeID, o.EvmKey = node, ethcrypto.CompressPubkey(&k.PublicKey)
	return o
}

// sol's round 2 on #1328, probe 1: while the pin is verified, VR's staged binding is replaced and a delegation of the new words is
// installed. The delegation alone is no success: VR's binding is not the new words, so recover stops instead of advising a relink.
func TestValidatorRecoverStopsWhenVRChangesDuringThePin(t *testing.T) {
	f := newFreshAuthorityRecover(t)
	once := false
	f.src.onBound = func() {
		if once {
			return
		}
		once = true
		f.chain.With(func(c *vrfake.Chain) {
			want := *c.Identities[f.id].Staged
			c.Pos.Delegations[[2]uint64{f.id, 1}] = &vrfake.Delegated{Binding: delegationOf(want), NextNonce: 2}
			other := otherWords(t, want, "replaced-evm")
			c.Identities[f.id].Staged = &other
		})
	}
	out, err := runValidator(t, f.home, f.args...)
	require.ErrorContains(t, err, "are not the new words: stop and re-run", out)
	require.NotContains(t, out, "run the nodes on the new EVM key", "no relink advice")
	require.Equal(t, 1, f.chain.Sends(), "only VR's binding was sent")
}

// sol's round 2 on #1328, probe 2: the delegation already held the new words when the run planned (so the plan had no delegation), and
// it is replaced in the block that confirms proposeBinding. The receipt handler decides from that fresh read and sends the delegation.
func TestValidatorRecoverDecidesAfterTheBindingFromAFreshRead(t *testing.T) {
	f := newRecoverFixture(t)
	f.chain.With(func(c *vrfake.Chain) {
		c.Pos.Delegations[[2]uint64{f.id, 1}] = &vrfake.Delegated{Binding: delegationOf(f.want), NextNonce: 2}
		c.AfterSend = func(c *vrfake.Chain, data []byte) {
			if bytes.Equal(data[:4], selector(vrclient.VRABI.Methods["proposeBinding"].ID)) {
				c.Pos.Delegations[[2]uint64{f.id, 1}] = &vrfake.Delegated{Binding: delegationOf(f.old), NextNonce: 3}
			}
		}
	})
	out, err := runValidator(t, f.home, "recover", "--id", fmt.Sprint(f.id), "--new-evm-keys", f.newEVM, "--old-authority-home", f.marker)
	require.NoError(t, err, out)
	require.Equal(t, 2, f.chain.Sends(), out)
	f.chain.With(func(c *vrfake.Chain) {
		require.Equal(t, selector(vrclient.VRABI.Methods["proposeBinding"].ID), c.Sent[0][:4])
		require.Equal(t, selector(vrclient.PosElectionABI.Methods["admitDelegation"].ID), c.Sent[1][:4], "the replaced delegation is sent again")
	})
	require.True(t, sameDelegation(f.delegation(), delegationOf(f.want)))
}

// After the delegation confirms, success needs VR's binding too: a binding replaced in the delegation's block stops the run.
func TestValidatorRecoverChecksVRAfterTheDelegation(t *testing.T) {
	f := newRecoverFixture(t)
	f.chain.With(func(c *vrfake.Chain) {
		c.AfterSend = func(c *vrfake.Chain, data []byte) {
			if bytes.Equal(data[:4], selector(vrclient.PosElectionABI.Methods["admitDelegation"].ID)) {
				other := otherWords(t, f.want, "replaced-evm")
				c.Identities[f.id].Staged = &other
			}
		}
	})
	out, err := runValidator(t, f.home, "recover", "--id", fmt.Sprint(f.id), "--new-evm-keys", f.newEVM, "--old-authority-home", f.marker)
	require.ErrorContains(t, err, "after the confirmed delegation VR's bindings", out)
}

// A confirmed matching pair (VR's staged binding and the delegation are the new words) skips every signature and transaction, the pin too.
func TestValidatorRecoverAConfirmedPairSendsAndSignsNothing(t *testing.T) {
	f := newFreshAuthorityRecover(t)
	out, err := runValidator(t, f.home, f.args...)
	require.NoError(t, err, out)
	sends, reads := f.chain.Sends(), len(f.src.seen)
	out, err = runValidator(t, f.home, f.args...)
	require.NoError(t, err, out)
	require.Equal(t, sends, f.chain.Sends())
	require.Equal(t, reads, len(f.src.seen), "the authority was not asked to pin or sign")
	require.Contains(t, out, "nothing to do")
}
