package cmd

// The authority-held EVM key against the real ValidatorRegistry bytecode (VT-10, #1201): `ubft validator apply` and `rotate` take the EVM
// proof of possession from the signing authority's registration operation and VR's own KeyLib verifies it on chain.
//
//	UBFT_VALIDATOR_E2E_ANVIL=$(which anvil) go test ./cli/ubft/cmd -run TestValidatorE2EAuthority -v

import (
	"context"
	"crypto"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	ethcommon "github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	"github.com/unicitynetwork/bft-core/signingauthority"
	"github.com/unicitynetwork/bft-core/signingauthority/service"
	"github.com/unicitynetwork/bft-core/vrschema"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

type staticTrustBases struct{ tb *types.RootTrustBaseV1 }

func (s staticTrustBases) GetByEpoch(context.Context, uint64) (*types.RootTrustBaseV1, error) {
	return s.tb, nil
}

// startAuthority runs an authority in this process (enrolled as node "e2e-evm-auth") with a registration policy, and returns its operator
// socket, its operator credential file and its node info file.
func startAuthority(t *testing.T, policy signingauthority.RegistrationPolicy) (socket, credFile, infoFile string) {
	t.Helper()
	rootSigner, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	tb, ok := trustbase.NewTrustBase(t, rootSigner).(*types.RootTrustBaseV1)
	require.True(t, ok)
	pdr := &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: 8}
	confHash, err := pdr.Hash(crypto.SHA256)
	require.NoError(t, err)
	a, err := signingauthority.New(signingauthority.Enrollment{AuthorityID: "e2e", NodeID: "e2e-evm-auth", NetworkID: 5, PartitionID: 8, ShardID: types.ShardID{},
		RootEpoch: signingauthority.PinRootEpoch(1), ShardConfHash: confHash, Profile: signingauthority.ProfileLegacyBCRv1},
		staticTrustBases{tb}, signingauthority.WithRegistrationPolicy(policy))
	require.NoError(t, err)
	t.Cleanup(a.Close)
	cred, err := service.NewCredential()
	require.NoError(t, err)
	srv, err := service.NewServer(a, service.Config{OperatorCredential: cred})
	require.NoError(t, err)
	t.Cleanup(srv.Close)
	dir, err := os.MkdirTemp("/tmp", "e2e-sa-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket = filepath.Join(dir, "op.sock")
	l, err := service.ListenUnix(socket)
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Close() })
	go func() { _ = srv.Serve(l, service.OperatorEndpoint) }()
	credFile = filepath.Join(dir, "operator.cred")
	require.NoError(t, writeCredentialFile(credFile, cred, false))
	pub, err := a.SigningPublicKey()
	require.NoError(t, err)
	infoFile = filepath.Join(dir, "node-info.json")
	b, err := json.Marshal(&types.NodeInfo{NodeID: "e2e-evm-auth", SigKey: pub, Stake: 1})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(infoFile, b, 0o600))
	return socket, credFile, infoFile
}

func TestValidatorE2EAuthority(t *testing.T) {
	bin := os.Getenv("UBFT_VALIDATOR_E2E_ANVIL")
	if bin == "" {
		t.Skip("set UBFT_VALIDATOR_E2E_ANVIL to the anvil binary to run the end-to-end check")
	}
	a := startAnvil(t, bin)
	a.load(filepath.Join("testdata", "validator-e2e"))
	ctx := context.Background()
	cfg, err := a.vr.Config(ctx)
	require.NoError(t, err)

	home := initHome(t, a.url)
	v, keys := loadHome(t, home)
	operator := ethcrypto.PubkeyToAddress(keys.Operator.PublicKey)
	a.fund(operator)
	root, err := nodeKeys(keys.Root)
	require.NoError(t, err)
	payee, err := v.payee()
	require.NoError(t, err)
	newPayee := ethcommon.HexToAddress("0x00000000000000000000000000000000000000c7")
	chain := vrschema.U64(3)

	// the operator authorizes: the registration of this owner, root binding and payee, and one rotation of the predicted identity 5
	policy := signingauthority.RegistrationPolicy{Deployment: signingauthority.RegistrationDeployment{Network: cfg.Network, ChainID: chain, Registry: a.vr.Registry},
		Authorized: []signingauthority.RegistrationAuthorization{
			{Domain: vrschema.RegisterDomainText, Owner: operator, RootNodeID: root.NodeID, RootKey: root.Public(), Payee: payee},
			{Domain: vrschema.BindingDomainText, Owner: operator, ID: 5, RootNodeID: root.NodeID, RootKey: root.Public(), Payee: newPayee},
		}}
	socket, cred, info := startAuthority(t, policy)

	// the validator config selects the authority and its enrolled identity; there is no EVM key file on this host
	c := readConfig(t, home)
	c.EVMAuthority = &evmAuthorityConfig{Socket: socket, Credential: cred, NodeInfo: info}
	c.EVMKeys = ""
	b, err := configBytes(c)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(home, validatorConfigFile), b, 0o600))
	require.NoError(t, os.RemoveAll(filepath.Join(home, "evm")))

	out, err := runValidator(t, home, "apply")
	require.NoError(t, err, out)
	require.Contains(t, out, "held by the signing authority")
	require.Equal(t, uint64(5), readConfig(t, home).ID)
	_, k := loadHome(t, home)
	idn, err := a.vr.Identity(ctx, 5)
	require.NoError(t, err)
	require.Equal(t, k.EVMAuth.pub, idn.Current.EvmKey, "VR's KeyLib accepted the authority's registration proof; the binding names its key")
	require.Equal(t, "e2e-evm-auth", idn.Current.EvmNodeID)

	// rotation to an authorized payee: the authority signs the binding domain; VR stages it
	out, err = runValidator(t, home, "rotate", "--new-payee", newPayee.Hex())
	require.NoError(t, err, out)
	idn, err = a.vr.Identity(ctx, 5)
	require.NoError(t, err)
	require.NotEqual(t, [32]byte{}, idn.StagedRef)

	// a rotation the operator did not authorize is refused by the authority, by name
	out, err = runValidator(t, home, "rotate", "--new-payee", "0x00000000000000000000000000000000000000d8")
	require.Error(t, err)
	require.Contains(t, err.Error()+out, "signing-registration-unauthorized")
}
