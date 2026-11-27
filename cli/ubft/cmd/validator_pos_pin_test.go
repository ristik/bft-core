package cmd

import (
	"context"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/signingauthority"
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
	var network [32]byte
	network[31] = 0xaa
	// #1222: the authority verifies the pin against its execution client; the first read finds the id not registered yet
	src := &pinSource{view: signingauthority.PosDeploymentView{Network: network, ChainID: vrschema.U64(3), Election: common.Address{0xe1}}, pending: 1}
	socket, cred, info := startAuthority(t, reg, signingauthority.WithPosSource(src, 3), signingauthority.WithRequirePosPolicy())
	a, err := loadEVMAuthority(evmAuthorityConfig{Socket: socket, Credential: cred, NodeInfo: info})
	require.NoError(t, err)
	defer func(w time.Duration) { posPinWait = w }(posPinWait)
	posPinWait = 10 * time.Second
	pin := signingauthority.PosPolicy{Network: network, ChainID: vrschema.U64(3), Election: common.Address{0xe1}, IDs: []uint64{5}}
	ctx := context.Background()
	require.NoError(t, a.PinPosPolicy(ctx, pin), "a pin the authority cannot verify yet is sent again")
	require.Equal(t, 2, src.calls)
	require.NoError(t, a.PinPosPolicy(ctx, pin), "a resumed apply pins the same scope again")
	wrong := pin
	wrong.Election = common.Address{0xe2}
	require.ErrorContains(t, a.PinPosPolicy(ctx, wrong), "signing-pos-policy-conflict")
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
			p.OpenLots, p.RetirementRequested = 0, true
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
				require.NotNil(t, ch.Pos.Delegations[[2]uint64{f.id, c.generation}], "the delegation is at the bonded generation")
			})
		})
	}
}

// pinSource is an authority's execution client view of the P85 deployment: the first `pending` reads find nothing yet.
type pinSource struct {
	mu      sync.Mutex
	view    signingauthority.PosDeploymentView
	pending int
	calls   int
}

func (p *pinSource) ReadPosDeployment(context.Context, signingauthority.PosQuery) (signingauthority.PosDeploymentView, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	if p.calls <= p.pending {
		return signingauthority.PosDeploymentView{}, fmt.Errorf("%w: the id is not registered at the block read", signingauthority.ErrPosPending)
	}
	return p.view, nil
}
