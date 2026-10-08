package evmassign

import (
	"bytes"
	"crypto/ecdsa"
	"testing"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
)

type popFx struct {
	c    Candidate
	keys []*ecdsa.PrivateKey
	d    ElectionDeployment
}

func newPoPFx(t *testing.T, n int) popFx {
	f := popFx{d: ElectionDeployment{Election: [20]byte{19: 7}}}
	f.d.NetworkWord = [32]byte{1}
	f.d.Custody = [20]byte{19: 5}
	f.d.ChainID = [32]byte{31: 1}
	c := Candidate{Kind: KindPrimary, Authorization: &Authorization{ResultID: bytes.Repeat([]byte{4}, 32), SnapshotDigest: bytes.Repeat([]byte{5}, 32)}}
	for i := 0; i < n; i++ {
		k, err := ethcrypto.GenerateKey()
		require.NoError(t, err)
		f.keys = append(f.keys, k)
		sid := make([]byte, StakingIDLen)
		sid[StakingIDLen-1] = byte(i + 1)
		c.Identities = append(c.Identities, Identity{StakingID: sid, Generation: uint64(i), EVMKey: ethcrypto.CompressPubkey(&k.PublicKey)})
	}
	f.c = c
	return f
}

func TestSignedPoPsAssembleAndEachBreakageIsRefused(t *testing.T) {
	f := newPoPFx(t, 3)
	var pops []EVMPoP
	for _, k := range f.keys {
		p, err := SignEVMPoP(k, f.c, f.d, 9)
		require.NoError(t, err)
		pops = append(pops, p)
	}
	// collected out of order, assembled in identity order
	got, set, err := AssemblePoPs(f.c, f.d, 9, []EVMPoP{pops[2], pops[0], pops[1]})
	require.NoError(t, err)
	require.Equal(t, pops, got)
	ids, _ := idsOf(f.c.Identities)
	require.Equal(t, PoPSetDigest(ids, [][]byte{pops[0].Signature, pops[1].Signature, pops[2].Signature}), set)

	stranger, _ := ethcrypto.GenerateKey()
	_, err = SignEVMPoP(stranger, f.c, f.d, 9)
	require.ErrorIs(t, err, ErrPoPSigning, "only a member's own key signs")
	rec := f.c
	rec.Kind = KindRecovery
	_, err = SignEVMPoP(f.keys[0], rec, f.d, 9)
	require.ErrorIs(t, err, ErrPoPSigning, "a recovery takes no proofs")

	_, _, err = AssemblePoPs(f.c, f.d, 10, pops)
	require.ErrorIs(t, err, ErrPoPSigning, "proofs of another attempt")
	other := f.d
	other.Election[0] = 1
	_, _, err = AssemblePoPs(f.c, other, 9, pops)
	require.ErrorIs(t, err, ErrPoPSigning, "proofs of another election")
	_, _, err = AssemblePoPs(f.c, f.d, 9, pops[:2])
	require.ErrorIs(t, err, ErrPoPSigning, "a member missing")
	_, _, err = AssemblePoPs(f.c, f.d, 9, append(append([]EVMPoP{}, pops...), pops[0]))
	require.ErrorIs(t, err, ErrPoPSigning, "a duplicate")
	extra := append(append([]EVMPoP{}, pops...), EVMPoP{ID: 99, EVMKey: pops[0].EVMKey, Signature: pops[0].Signature})
	_, _, err = AssemblePoPs(f.c, f.d, 9, extra)
	require.ErrorIs(t, err, ErrPoPSigning, "a non-member")
	swapped := append([]EVMPoP{}, pops...)
	swapped[0].Signature = pops[1].Signature
	_, _, err = AssemblePoPs(f.c, f.d, 9, swapped)
	require.ErrorIs(t, err, ErrPoPSigning, "another member's signature")
	high := append([]EVMPoP{}, pops...)
	high[1].Signature = append(bytes.Clone(pops[1].Signature[:64]), 29)
	_, _, err = AssemblePoPs(f.c, f.d, 9, high)
	require.ErrorIs(t, err, ErrPoPSigning, "a bad recovery byte")
}
