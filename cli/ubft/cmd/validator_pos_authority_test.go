package cmd

import (
	"testing"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/vrclient"
)

func TestParseEVMAuthorityArg(t *testing.T) {
	for _, bad := range []string{"", "5", "=a,b,c", "0=a,b,c", "x=a,b,c", "5=a,b", "5=a,b,c,d"} {
		_, _, err := parseEVMAuthorityArg(bad)
		require.Error(t, err, bad)
	}
}

func TestCheckRecovers(t *testing.T) {
	key, err := ethcrypto.GenerateKey()
	require.NoError(t, err)
	d := [32]byte{1, 2, 3}
	sig, err := vrclient.SignDigest(key, d)
	require.NoError(t, err)
	pub := ethcrypto.CompressPubkey(&key.PublicKey)
	require.NoError(t, checkRecovers(d, sig, pub))
	require.Error(t, checkRecovers([32]byte{9}, sig, pub), "another digest")
	require.Error(t, checkRecovers(d, sig[:64], pub), "a short signature")
}

// The authority's delegation digest is the election's: the admitDelegation payload converts field for field.
func TestDelegationRequestOfKeepsEveryField(t *testing.T) {
	r := vrclient.DelegationRequest{Id: 5, Generation: 2, RoleNonce: 3, DelegationNonce: 4, Expiry: 9,
		Binding: vrclient.Delegation{RootNodeID: [32]byte{1}, RootKey: []byte{2}, EvmNodeID: [32]byte{3}, EvmKey: []byte{4}, OperatorPayee: [20]byte{5}}}
	e := delegationRequestOf(r)
	require.Equal(t, r.Id, e.Id)
	require.Equal(t, r.Generation, e.Generation)
	require.Equal(t, r.RoleNonce, e.RoleNonce)
	require.Equal(t, r.DelegationNonce, e.DelegationNonce)
	require.Equal(t, r.Expiry, e.Expiry)
	require.Equal(t, r.Binding.RootNodeID, e.Binding.RootNodeID)
	require.Equal(t, r.Binding.EvmKey, e.Binding.EvmKey)
	require.Equal(t, r.Binding.OperatorPayee, e.Binding.OperatorPayee)
}
