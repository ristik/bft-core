package cmd

import (
	"context"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/signingauthority"
	"github.com/unicitynetwork/bft-core/vrclient"
	"github.com/unicitynetwork/bft-core/vrclient/vrfake"
	"github.com/unicitynetwork/bft-core/vrschema"
)

const pinNetwork = "0x00000000000000000000000000000000000000000000000000000000000000aa"

func writePin(t *testing.T, body string) string {
	path := filepath.Join(t.TempDir(), "pin.json")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	return path
}

// #1323: apply's --pin-pos-policy is a pin without ids, and it must name the election apply delegates to.
func TestApplyPinTemplate(t *testing.T) {
	election := common.HexToAddress("0x00000000000000000000000000000000000000e1")
	tmpl := `{"network":"` + pinNetwork + `","chainId":3,"election":"` + election.Hex() + `"}`
	p, err := readPosPolicyTemplate(writePin(t, tmpl))
	require.NoError(t, err)
	require.Empty(t, p.IDs)
	var network [32]byte
	network[31] = 0xaa
	require.NoError(t, checkPosPolicyTemplate(p, network, big.NewInt(3), election))
	require.ErrorContains(t, checkPosPolicyTemplate(p, [32]byte{1}, big.NewInt(3), election), "network word")
	require.ErrorContains(t, checkPosPolicyTemplate(p, network, big.NewInt(4), election), "names chain 3")
	require.ErrorContains(t, checkPosPolicyTemplate(p, network, big.NewInt(3), common.Address{0xe2}), "names election")

	_, err = readPosPolicyTemplate(writePin(t, `{"network":"`+pinNetwork+`","chainId":3,"election":"`+election.Hex()+`","ids":[5]}`))
	require.ErrorContains(t, err, "leave them out")
}

// The authority takes the pin apply makes for the identity it registered; the same pin again is a no-op (a resumed apply), another is
// refused (the pin is fixed for the authority's lifetime).
func TestPinPosPolicyOnALateAuthority(t *testing.T) {
	key, err := ethcrypto.GenerateKey()
	require.NoError(t, err)
	reg := signingauthority.RegistrationPolicy{Deployment: signingauthority.RegistrationDeployment{Network: [32]byte{1}, ChainID: vrschema.U64(3), Registry: common.Address{0x03}},
		Authorized: []signingauthority.RegistrationAuthorization{{Domain: vrschema.RegisterDomainText, Owner: common.Address{0x0a}, RootNodeID: "root", RootKey: ethcrypto.CompressPubkey(&key.PublicKey), Payee: common.Address{0x0b}}}}
	socket, cred, info := startAuthority(t, reg, signingauthority.WithLatePosPolicy(), signingauthority.WithRequirePosPolicy())
	a, err := loadEVMAuthority(evmAuthorityConfig{Socket: socket, Credential: cred, NodeInfo: info})
	require.NoError(t, err)
	var network [32]byte
	network[31] = 0xaa
	pin := signingauthority.PosPolicy{Network: network, ChainID: vrschema.U64(3), Election: common.Address{0xe1}, IDs: []uint64{5}}
	ctx := context.Background()
	require.NoError(t, a.PinPosPolicy(ctx, pin))
	require.NoError(t, a.PinPosPolicy(ctx, pin), "a resumed apply pins the same scope again")
	other := pin
	other.IDs = []uint64{6}
	err = a.PinPosPolicy(ctx, other)
	require.ErrorContains(t, err, "signing-pos-policy-conflict")
	require.ErrorContains(t, err, "identities [6]")
}

// #1323: a fresh identity's delegation is admitted before its first bond, so no election sees it bonded without a delegation; a retired
// identity's new bond opens a new generation, so its delegation follows the bond; an interrupted run with the delegation staged only bonds.
func TestValidatorApplyPoSAdmitsTheDelegationBeforeTheFirstBond(t *testing.T) {
	for name, c := range map[string]struct {
		edit       func(p *vrfake.Position, ds map[[2]uint64]*vrfake.Delegated, id uint64)
		order      []string
		generation uint64
	}{
		"registered, not bonded": {func(p *vrfake.Position, ds map[[2]uint64]*vrfake.Delegated, id uint64) {
			p.OpenLots = 0
			delete(ds, [2]uint64{id, 1})
		}, []string{"admit", "bond"}, 1},
		"the delegation is staged, the bond is not": {func(p *vrfake.Position, _ map[[2]uint64]*vrfake.Delegated, _ uint64) {
			p.OpenLots = 0
		}, []string{"bond"}, 1},
		"a re-bond after retirement": {func(p *vrfake.Position, _ map[[2]uint64]*vrfake.Delegated, _ uint64) {
			p.OpenLots, p.LotCount, p.RetirementRequested = 0, 3, true
		}, []string{"bond", "admit"}, 2},
	} {
		t.Run(name, func(t *testing.T) {
			f := newRecoverFixture(t)
			f.chain.With(func(ch *vrfake.Chain) { c.edit(ch.Pos.Positions[f.id], ch.Pos.Delegations, f.id) })
			out, err := runValidator(t, f.home, "apply", "--id", fmt.Sprint(f.id))
			require.NoError(t, err, out)
			f.chain.With(func(ch *vrfake.Chain) {
				require.Equal(t, c.order, ch.Pos.Order, out)
				require.Equal(t, c.generation, ch.Pos.Positions[f.id].Generation)
				require.EqualValues(t, 1, ch.Pos.Positions[f.id].LotCount)
				require.NotNil(t, ch.Pos.Delegations[[2]uint64{f.id, c.generation}], "the delegation is at the bonded generation")
			})
		})
	}
}

func TestFreshValidatorApplyPinsAndBondsThroughTheAuthority(t *testing.T) {
	for _, resumed := range []bool{false, true} {
		t.Run(fmt.Sprintf("resumed=%t", resumed), func(t *testing.T) {
			chain, url := fakeNetwork(t)
			home := initHome(t, url)
			v, keys := loadHome(t, home)
			owner := ethcrypto.PubkeyToAddress(keys.Operator.PublicKey)
			chain.Fund(owner, new(big.Int).Mul(big.NewInt(2), big.NewInt(1e18)))
			root, err := nodeKeys(keys.Root)
			require.NoError(t, err)
			payee, err := v.payee()
			require.NoError(t, err)
			custody, election := common.Address{0xc1}, common.Address{0xe1}
			chain.With(func(c *vrfake.Chain) {
				c.Tag, c.Custody, c.Election, c.Evidence = vrclient.ModuleTagPoS, custody, election, common.Address{0xe2}
				c.Pos = vrfake.NewPos()
			})
			socket, cred, info := startAuthority(t, signingauthority.RegistrationPolicy{
				Deployment: signingauthority.RegistrationDeployment{Network: chain.Network, ChainID: vrschema.U64(3), Registry: chain.Registry},
				Authorized: []signingauthority.RegistrationAuthorization{
					{Domain: vrschema.RegisterDomainText, Owner: owner, Payee: payee, RootNodeID: root.NodeID, RootKey: root.Public()},
				},
			}, signingauthority.WithLatePosPolicy(), signingauthority.WithRequirePosPolicy())
			v.cfg.EVMAuthority = &evmAuthorityConfig{Socket: socket, Credential: cred, NodeInfo: info}
			v.cfg.EVMKeys = ""
			require.NoError(t, v.save())
			pin := writePin(t, fmt.Sprintf(`{"network":"0x%x","chainId":3,"election":"%s"}`, chain.Network, election.Hex()))

			if resumed {
				v, keys := loadHome(t, home)
				reg, _, _, err := registration(v, keys, 0)
				require.NoError(t, err)
				id := chain.AddMember(owner, reg)
				chain.With(func(c *vrfake.Chain) {
					c.Pos.Positions[id] = &vrfake.Position{Generation: 1, RootKeyHash: ethcrypto.Keccak256Hash(root.Public())}
				})
				v.cfg.ID = id
				require.NoError(t, v.save())

				out, err := runValidator(t, home, "apply", "--dry-run", "--pin-pos-policy", pin)
				require.ErrorContains(t, err, "A dry run cannot set the P85 pin", out)
				require.Zero(t, chain.Sends())
				return
			}

			out, err := runValidator(t, home, "apply", "--pin-pos-policy", pin)
			require.NoError(t, err, out)
			id := readConfig(t, home).ID
			require.EqualValues(t, 5, id)
			require.Contains(t, out, "pinned the signing authority's P85 scope to identity 5")
			require.Equal(t, "e2e-evm-auth", chain.Identity(id).Current.EvmNodeID)
			chain.With(func(c *vrfake.Chain) {
				require.Len(t, c.Sent, 4)
				require.Equal(t, vrclient.VRABI.Methods["register"].ID, selector(c.Sent[0]))
				require.Equal(t, vrclient.CustodyABI.Methods["register"].ID, selector(c.Sent[1]))
				require.Equal(t, vrclient.PosElectionABI.Methods["admitDelegation"].ID, selector(c.Sent[2]))
				require.Equal(t, vrclient.CustodyABI.Methods["bond"].ID, selector(c.Sent[3]))
				require.EqualValues(t, 1, c.Pos.Positions[id].OpenLots)
				require.EqualValues(t, 1, c.Pos.Positions[id].LotCount)
				require.NotNil(t, c.Pos.Delegations[[2]uint64{id, 1}])
			})
		})
	}
}
