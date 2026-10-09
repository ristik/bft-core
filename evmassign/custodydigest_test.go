package evmassign

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
)

func abiArgs(t *testing.T, kinds ...string) abi.Arguments {
	t.Helper()
	var a abi.Arguments
	for _, k := range kinds {
		ty, err := abi.NewType(k, "", nil)
		require.NoError(t, err)
		a = append(a, abi.Argument{Type: ty})
	}
	return a
}

func k256(b []byte) [32]byte { var o [32]byte; copy(o[:], ethcrypto.Keccak256(b)); return o }

func dep() Deployment {
	return Deployment{NetworkWord: k256([]byte("network")), ChainID: [32]byte{31: 7}, Custody: [20]byte{0xc0, 0x57, 19: 0x01}}
}

func idRec(id uint64, weight uint64, payee byte, lots []uint64, rootKey, evmKey byte) Identity {
	sid := make([]byte, 32)
	copy(sid[24:], w64(id)[24:])
	ld := LotsDigest(lots)
	return Identity{StakingID: sid, Generation: 1, RootNodeID: "r", RootKey: bytes.Repeat([]byte{rootKey}, KeyLen), EVMNodeID: "e",
		EVMKey: bytes.Repeat([]byte{evmKey}, KeyLen), Weight: weight, RawWeight: weight, OperatorPayee: bytes.Repeat([]byte{payee}, PayeeLen), ExposureDigest: ld[:]}
}

func TestLotsDigestIsKeccakOfAbiEncodedUint256Array(t *testing.T) {
	lots := []uint64{3, 4, 9}
	big3 := []*big.Int{big.NewInt(3), big.NewInt(4), big.NewInt(9)}
	enc, err := abiArgs(t, "uint256[]").Pack(big3)
	require.NoError(t, err)
	want := k256(enc)
	require.Equal(t, want, LotsDigest(lots))
	empty, err := abiArgs(t, "uint256[]").Pack([]*big.Int{})
	require.NoError(t, err)
	require.Equal(t, k256(empty), LotsDigest(nil))
}

func TestExposureIDMatchesAbiEncode(t *testing.T) {
	d := dep()
	asg := k256([]byte("assignment"))
	enc, err := abiArgs(t, "bytes32", "bytes32", "uint256", "address", "bytes32", "uint64").Pack(
		k256([]byte("unicity.p85.exposure")), d.NetworkWord, new(big.Int).SetBytes(d.ChainID[:]), common.Address(d.Custody), asg, uint64(5))
	require.NoError(t, err)
	require.Equal(t, k256(enc), ExposureID(d, asg, 5))
	require.NotEqual(t, ExposureID(d, asg, 5), ExposureID(d, asg, 6))
	require.NotEqual(t, ExposureID(d, asg, 5), ExposureID(d, k256([]byte("other")), 5))
	other := d
	other.Custody[19] = 2
	require.NotEqual(t, ExposureID(d, asg, 5), ExposureID(other, asg, 5))
}

func TestAssignmentExposureDigestMatchesAbiEncode(t *testing.T) {
	d := dep()
	asg := k256([]byte("assignment"))
	ids := []Identity{idRec(1, 6, 0xa1, []uint64{1, 2}, 0x11, 0x21), idRec(7, 1, 0xa2, []uint64{5}, 0x12, 0x22)}
	args := abiArgs(t, "bytes32", "bytes32", "uint64", "uint64", "uint64", "address", "bytes32")
	digest := k256([]byte("unicity.p85.exposure-digest"))
	for _, x := range ids {
		cid, err := CustodyID(x.StakingID)
		require.NoError(t, err)
		enc, err := args.Pack(digest, [32]byte(ExposureID(d, asg, cid)), cid, x.Weight, x.RawWeight, common.BytesToAddress(x.OperatorPayee), [32]byte(x.ExposureDigest))
		require.NoError(t, err)
		digest = k256(enc)
	}
	got, err := AssignmentExposureDigest(d, asg, ids)
	require.NoError(t, err)
	require.Equal(t, digest, got)
	// every field of every member is in the digest
	for name, mut := range map[string]func(x []Identity){
		"weight": func(x []Identity) { x[1].Weight++ },
		"payee":  func(x []Identity) { x[0].OperatorPayee = bytes.Repeat([]byte{0xee}, PayeeLen) },
		"lots":   func(x []Identity) { l := LotsDigest([]uint64{1, 3}); x[0].ExposureDigest = l[:] },
		"id":     func(x []Identity) { x[1] = idRec(8, 1, 0xa2, []uint64{5}, 0x12, 0x22) },
	} {
		c := append([]Identity(nil), ids...)
		mut(c)
		other, err := AssignmentExposureDigest(d, asg, c)
		require.NoError(t, err, name)
		require.NotEqual(t, got, other, name)
	}
	moved, err := AssignmentExposureDigest(d, k256([]byte("another assignment")), ids)
	require.NoError(t, err)
	require.NotEqual(t, got, moved, "the assignment id is in every exposure id")
}

func TestKeyHistoryDigestMatchesAbiEncode(t *testing.T) {
	ids := []Identity{idRec(1, 6, 0xa1, []uint64{1}, 0x11, 0x21), idRec(7, 1, 0xa2, []uint64{5}, 0x12, 0x22)}
	args := abiArgs(t, "bytes32", "uint64", "bytes32", "bytes32")
	digest := k256([]byte("unicity.p85.key-history-digest"))
	for _, x := range ids {
		cid, _ := CustodyID(x.StakingID)
		enc, err := args.Pack(digest, cid, k256(x.RootKey), k256(x.EVMKey))
		require.NoError(t, err)
		digest = k256(enc)
	}
	got, err := KeyHistoryDigest(ids)
	require.NoError(t, err)
	require.Equal(t, digest, got)
	// the payee and weight are not part of the key history; a rotated root key or EVM key is
	c := append([]Identity(nil), ids...)
	c[0].Weight, c[0].OperatorPayee = 9, bytes.Repeat([]byte{0xee}, PayeeLen)
	same, err := KeyHistoryDigest(c)
	require.NoError(t, err)
	require.Equal(t, got, same)
	c[0].RootKey = bytes.Repeat([]byte{0x99}, KeyLen)
	rot, _ := KeyHistoryDigest(c)
	require.NotEqual(t, got, rot)
	c = append([]Identity(nil), ids...)
	c[1].EVMKey = bytes.Repeat([]byte{0x98}, KeyLen)
	rot, _ = KeyHistoryDigest(c)
	require.NotEqual(t, got, rot)
}

func TestExposureChainMatchesAbiEncode(t *testing.T) {
	enc, err := abiArgs(t, "bytes32", "bytes32", "bytes32").Pack(k256([]byte("unicity.p85.exposure-chain")), [32]byte{}, k256([]byte("e1")))
	require.NoError(t, err)
	first := ExposureChainStep([32]byte{}, k256([]byte("e1")))
	require.Equal(t, k256(enc), first)
	second := ExposureChainStep(first, k256([]byte("e2")))
	reordered := ExposureChainStep(ExposureChainStep([32]byte{}, k256([]byte("e2"))), k256([]byte("e1")))
	require.NotEqual(t, second, reordered, "the chain keeps creation order")
}

func TestCustodyDigestRefusals(t *testing.T) {
	d, asg := dep(), k256([]byte("a"))
	good := []Identity{idRec(1, 6, 0xa1, []uint64{1}, 0x11, 0x21), idRec(7, 1, 0xa2, []uint64{5}, 0x12, 0x22)}
	high := idRec(2, 1, 0xa3, []uint64{9}, 0x13, 0x23)
	high.StakingID[0] = 1 // a staking id that does not fit a uint64
	zero := idRec(0, 1, 0xa3, []uint64{9}, 0x13, 0x23)
	short := idRec(2, 1, 0xa3, []uint64{9}, 0x13, 0x23)
	short.StakingID = short.StakingID[:31]
	badPayee := idRec(3, 1, 0xa3, []uint64{9}, 0x13, 0x23)
	badPayee.OperatorPayee = badPayee.OperatorPayee[:19]
	badKey := idRec(3, 1, 0xa3, []uint64{9}, 0x13, 0x23)
	badKey.RootKey = badKey.RootKey[:32]
	cases := map[string][]Identity{
		"descending ids":     {good[1], good[0]},
		"a duplicate id":     {good[0], good[0]},
		"id above uint64":    {good[0], high},
		"id zero":            {zero},
		"a short staking id": {short},
		"a short payee":      {good[0], badPayee},
		"a short key":        {good[0], badKey},
	}
	for name, ids := range cases {
		_, err := AssignmentExposureDigest(d, asg, ids)
		if name != "a short key" {
			require.ErrorIs(t, err, ErrCustodyDigest, name)
		}
		_, err = KeyHistoryDigest(ids)
		if name != "a short payee" {
			require.ErrorIs(t, err, ErrCustodyDigest, name)
		}
	}
	_, err := KeyHistoryDigestFromHashes([]uint64{1}, nil, nil)
	require.ErrorIs(t, err, ErrCustodyDigest)
}
