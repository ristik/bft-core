package vrclient

import (
	"context"
	"math/big"
	"testing"

	ethcommon "github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
)

type badProver struct {
	NodeKeys
}

func (b badProver) Prove(_ context.Context, req ProofRequest) ([]byte, error) {
	var d [32]byte // not the registration digest
	return SignDigest(b.Key, d)
}

// SignWith verifies both proofs against the digest it computed: a prover that signs another digest is caught before submission.
func TestSignWithVerifiesTheProversProof(t *testing.T) {
	rk, _ := ethcrypto.GenerateKey()
	ek, _ := ethcrypto.GenerateKey()
	root, evm := NodeKeys{NodeID: "r", Key: rk}, NodeKeys{NodeID: "e", Key: ek}
	r, err := NewRegistration(root, evm, ethcommon.Address{1}, 3)
	require.NoError(t, err)
	d := Domain{ChainID: big.NewInt(3), Registry: ethcommon.Address{9}}
	got, err := SignWith(context.Background(), d, ethcommon.Address{2}, false, 0, r, root, evm)
	require.NoError(t, err)
	want, err := Sign(d, ethcommon.Address{2}, false, 0, r, root, evm)
	require.NoError(t, err)
	require.Equal(t, want, got)
	_, err = SignWith(context.Background(), d, ethcommon.Address{2}, false, 0, r, root, badProver{NodeKeys: evm})
	require.ErrorIs(t, err, ErrVR)
}
