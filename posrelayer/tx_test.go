package posrelayer

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common/hexutil"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/rootchain/evmstate/evmstatetest"
)

type writesFixture struct {
	Deployment struct {
		NetworkWord string
		ChainId     int64
		Custody     string
		Election    string
	}
	ResultId      string
	RelayerWrites struct {
		SubmitPops string
		Finalize   string
		Joiner     struct {
			Id                             uint64
			OwnerKey, RootKey, EvmKey      string
			Withdrawal, Payee              string
			RootNodeId, EvmNodeId          string
			Expiry                         uint64
			RegisterDigest, Register, Bond string
			DelegationDigest, Admit        string
		}
	}
}

func loadWrites(t *testing.T) writesFixture {
	raw, err := os.ReadFile(fixturePath)
	require.NoError(t, err)
	var f writesFixture
	require.NoError(t, json.Unmarshal(raw, &f))
	return f
}

func mustHex(t *testing.T, s string) []byte {
	b, err := hexutil.Decode(s)
	require.NoError(t, err)
	return b
}

func key(t *testing.T, s string) *ecdsa.PrivateKey {
	k, err := ethcrypto.ToECDSA(mustHex(t, s))
	require.NoError(t, err)
	return k
}

// chainStub answers what the onboarding reads: the network word, the owner's register nonce, the next staking id and the election's
// delegationDigest (the fixture's recorded one, so the test fails if the locally computed digest differs from the contract's).
type chainStub struct {
	t             *testing.T
	network       [32]byte
	nextID, nonce uint64
	digest        [32]byte
}

func (c chainStub) Call(_ context.Context, _ [20]byte, data []byte) ([]byte, error) {
	switch hex.EncodeToString(data[:4]) {
	case hex.EncodeToString(writes.Methods["network"].ID):
		return c.network[:], nil
	case hex.EncodeToString(writes.Methods["registerNonce"].ID):
		return new(big.Int).SetUint64(c.nonce).FillBytes(make([]byte, 32)), nil
	case hex.EncodeToString(writes.Methods["nextStakingID"].ID):
		return new(big.Int).SetUint64(c.nextID).FillBytes(make([]byte, 32)), nil
	case hex.EncodeToString(writes.Methods["delegationDigest"].ID):
		return c.digest[:], nil
	}
	c.t.Fatalf("unexpected call %x", data[:4])
	return nil, nil
}

// The calldata of the relayer's transactions is byte-identical to what the real contracts' tests built and executed (the fixture's
// relayerWrites: signatures are RFC 6979, so equal inputs give equal bytes); a flipped input gives different bytes.
func TestRelayerCalldataIsByteIdenticalToTheContractsTests(t *testing.T) {
	f := loadWrites(t)
	p := evmstatetest.Load(t, fixturePath)
	var resultID [32]byte
	copy(resultID[:], mustHex(t, f.ResultId))

	t.Run("submitAssignmentPoPs and finalizeCandidate", func(t *testing.T) {
		got, err := SubmitPoPsCalldata(resultID, p.PoPs)
		require.NoError(t, err)
		require.Equal(t, f.RelayerWrites.SubmitPops, hexutil.Encode(got))
		fin, err := FinalizeCalldata(resultID)
		require.NoError(t, err)
		require.Equal(t, f.RelayerWrites.Finalize, hexutil.Encode(fin))

		swapped := append(p.PoPs[:0:0], p.PoPs...)
		swapped[0], swapped[1] = swapped[1], swapped[0]
		other, err := SubmitPoPsCalldata(resultID, swapped)
		require.NoError(t, err)
		require.NotEqual(t, hexutil.Encode(got), hexutil.Encode(other), "the proofs' order is part of the calldata")
	})

	j := f.RelayerWrites.Joiner
	joiner := Joiner{OwnerKey: key(t, j.OwnerKey), RootKey: key(t, j.RootKey), EVMKey: key(t, j.EvmKey),
		RootNodeID: j.RootNodeId, EVMNodeID: j.EvmNodeId, Expiry: j.Expiry}
	copy(joiner.Withdrawal[:], mustHex(t, j.Withdrawal))
	copy(joiner.Payee[:], mustHex(t, j.Payee))
	var m Modules
	copy(m.Custody[:], mustHex(t, f.Deployment.Custody))
	copy(m.Election[:], mustHex(t, f.Deployment.Election))
	chain := big.NewInt(f.Deployment.ChainId)
	stub := chainStub{t: t, nextID: j.Id - 1}
	copy(stub.network[:], mustHex(t, f.Deployment.NetworkWord))
	copy(stub.digest[:], mustHex(t, j.DelegationDigest))

	t.Run("register", func(t *testing.T) {
		data, id, err := joiner.RegisterCalldata(context.Background(), stub, m, chain)
		require.NoError(t, err)
		require.Equal(t, j.Id, id)
		require.Equal(t, j.Register, hexutil.Encode(data))
		owner := ethcrypto.PubkeyToAddress(joiner.OwnerKey.PublicKey)
		d := RegisterDigest(stub.network, chain, m.Custody, owner, joiner.Withdrawal, compressed(joiner.RootKey), 0)
		require.Equal(t, j.RegisterDigest, hexutil.Encode(d[:]))
		stub.nonce = 1
		other, _, err := joiner.RegisterCalldata(context.Background(), stub, m, chain)
		require.NoError(t, err)
		require.NotEqual(t, j.Register, hexutil.Encode(other), "the register nonce is signed over")
	})
	t.Run("bond", func(t *testing.T) {
		data, err := BondCalldata(j.Id)
		require.NoError(t, err)
		require.Equal(t, j.Bond, hexutil.Encode(data))
	})
	t.Run("admitDelegation", func(t *testing.T) {
		data, err := joiner.AdmitCalldata(context.Background(), stub, m, chain, j.Id)
		require.NoError(t, err)
		require.Equal(t, j.Admit, hexutil.Encode(data))
	})
	t.Run("admitDelegation refuses a digest the election does not agree with", func(t *testing.T) {
		bad := stub
		bad.digest[0] ^= 1
		_, err := joiner.AdmitCalldata(context.Background(), bad, m, chain, j.Id)
		require.ErrorIs(t, err, ErrBuild)
		require.True(t, strings.Contains(err.Error(), "delegation digest"))
	})
}
