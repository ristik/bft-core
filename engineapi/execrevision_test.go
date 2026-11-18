package engineapi

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/b1state"
)

// nativeRev2 is the native set of the current execution revision, as ExpectUnicityPrecompiles enforces it.
var nativeRev2 = func() map[string]string {
	m, err := unicityNativePrecompiles(b1state.CurrentExecutionRevision)
	if err != nil {
		panic(err)
	}
	return m
}()

// legacyUreth is the native set of the frozen product's client (ureth 10552af2, before ureth#97): the current one plus 0x0105.
func legacyUreth() map[string]string {
	m := map[string]string{"unicity-bridge-compose-v2": "0x0000000000000000000000000000000000000105"}
	for k, v := range nativeRev2 {
		m[k] = v
	}
	return m
}

func ethConfigWith(t *testing.T, natives map[string]string) json.RawMessage {
	m := loadConfig(t, "eth_config_cancun_at_genesis.json")
	p := current(m)["precompiles"].(map[string]any)
	for k, v := range natives {
		p[k] = v
	}
	return mustJSON(t, m)
}

func TestExpectUnicityPrecompilesRefusesAnyRevisionButTheCurrentOne(t *testing.T) {
	for _, rev := range []uint64{0, 2, 1 << 40} {
		a := &Adapter{}
		require.ErrorIs(t, a.ExpectUnicityPrecompiles(rev), b1state.ErrExecutionRevision, "revision %d", rev)
		require.Nil(t, a.unicityPrecompiles, "a refused revision must not leave an expectation behind")
	}
	a := &Adapter{}
	require.NoError(t, a.ExpectUnicityPrecompiles(b1state.CurrentExecutionRevision))
	require.Equal(t, nativeRev2, a.unicityPrecompiles)
}

// The BFT/ureth half of the #1199 startup matrix: new BFT (this binary at the current revision) against new and old (0x0105) ureth. The converse
// (old BFT + new ureth) is the frozen binary's own check, which requires 0x0105; it is exercised by scripts/ci/lane-product.sh selftest.
func TestExecutionRevisionStartupMatrix_BFTUrethPairs(t *testing.T) {
	newBFT := func() map[string]string {
		a := &Adapter{}
		require.NoError(t, a.ExpectUnicityPrecompiles(b1state.CurrentExecutionRevision))
		return a.unicityPrecompiles
	}
	_, err := checkProfileWith(ethConfigWith(t, nativeRev2), 31337, newBFT())
	require.NoError(t, err, "new BFT with new ureth participates")
	_, err = checkProfileWith(ethConfigWith(t, legacyUreth()), 31337, newBFT())
	require.ErrorContains(t, err, "unexpected unicity-bridge-compose-v2", "new BFT with old ureth is refused")
	m := legacyUreth()
	delete(m, "unicity-bridge-compose-v2")
	delete(m, "unicity-b2-sdk3")
	_, err = checkProfileWith(ethConfigWith(t, m), 31337, newBFT())
	require.ErrorContains(t, err, "missing unicity-b2-sdk3")
}
