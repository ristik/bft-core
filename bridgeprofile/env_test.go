package bridgeprofile

import (
	"math/big"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"
)

// env is the deterministic deployment of the lock and composition tests.
type env struct{ *Deployment }

const (
	testChain = DevChainID
	testRound = DevRootRound
)

func newEnv(t testing.TB) *env {
	t.Helper()
	d, err := NewDeployment()
	require.NoError(t, err)
	require.Equal(t, d.F.Cfg.EVMShard, d.EVMPDR.ShardID.Bytes(), "native empty shard is 0x80")
	return &env{d}
}

func (e *env) lockDigest(n uint64, amount *big.Int, p0 Predicate) [32]byte {
	return e.LockDigestFor(n, amount, p0)
}

func (e *env) backedToken(t testing.TB, n uint64, amount *big.Int, keys []*secp256k1.PrivateKey) (*History, *LockProof) {
	t.Helper()
	h, lp, err := e.Backed(n, amount, keys)
	require.NoError(t, err)
	return h, lp
}
