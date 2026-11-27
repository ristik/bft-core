package cmd

import (
	"context"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/signingauthority"
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
