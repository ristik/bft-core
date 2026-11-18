package vrclient

import (
	"math/big"
	"testing"

	ethcommon "github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
)

func TestApprovalsAreOrderedAndChecked(t *testing.T) {
	gov := ethcommon.HexToAddress("0xff00000000000000000000000000000000000009")
	data, err := ForceRemovePayload(3)
	require.NoError(t, err)
	call, err := QueueCalldata(KindForceRemove, data)
	require.NoError(t, err)
	d, err := CallDigest(big.NewInt(3), gov, DefaultRegistry, call, 7)
	require.NoError(t, err)
	d2, _ := CallDigest(big.NewInt(3), gov, DefaultRegistry, call, 8)
	require.NotEqual(t, d, d2, "the nonce is signed")
	var as []Approval
	for i := 0; i < 4; i++ {
		k, _ := ethcrypto.GenerateKey()
		sig, err := SignCall(k, d)
		require.NoError(t, err)
		as = append(as, Approval{Signer: ethcrypto.PubkeyToAddress(k.PublicKey), Signature: sig})
	}
	out, err := OrderApprovals(d, as)
	require.NoError(t, err)
	for i := 1; i < len(out); i++ {
		require.Less(t, string(out[i-1].Signer[:]), string(out[i].Signer[:]))
	}
	_, err = OrderApprovals(d2, as)
	require.ErrorContains(t, err, "claimed for", "approvals of another nonce do not verify")
	_, err = OrderApprovals(d, append(as, as[0]))
	require.ErrorContains(t, err, "twice")
	cd, err := ExecuteCalldata(DefaultRegistry, call, out)
	require.NoError(t, err)
	dc, err := DecodeCall(cd)
	require.NoError(t, err)
	require.Equal(t, "FoundationMultisig", dc.Contract)
	require.Contains(t, DescribeChange(KindForceRemove, data), "ForceRemove(id=3)")
	qr := VRABI.Errors["QueueRefused"].ID
	arg := make([]byte, 32)
	arg[31] = 16
	require.Contains(t, DecodeRevert(append(qr[:4:4], arg...)).Error(), "not in the committee")
}
