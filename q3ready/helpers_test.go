package q3ready

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/q3format"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
)

const testNetwork = 5

func fill(b byte) (a [32]byte) { copy(a[:], bytes.Repeat([]byte{b}, 32)); return }

func fb(b byte) []byte { a := fill(b); return a[:] }

func newSigner(t *testing.T) (abcrypto.Signer, []byte) {
	t.Helper()
	s, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	v, err := s.Verifier()
	require.NoError(t, err)
	key, err := v.MarshalPublicKey()
	require.NoError(t, err)
	return s, key
}

// testBody is a valid V3 body with weights (6,1,1,1) and the signers of its members, keyed by node id.
func testBody(t *testing.T) (q3format.BodyV3, map[string]abcrypto.Signer) {
	t.Helper()
	b := q3format.BodyV3{Network: testNetwork, Epoch: 2, EarliestActivation: 10, StateSummary: fb(1), ChangeRecordHash: fb(2),
		PredecessorHash: fb(3), Config: q3format.Q3Config(testNetwork, fill(9))}
	signers := map[string]abcrypto.Signer{}
	var total uint64
	for i, w := range []uint64{6, 1, 1, 1} {
		s, key := newSigner(t)
		id := fmt.Sprintf("n%d", i+1)
		signers[id] = s
		b.Members = append(b.Members, evmroot.Member{StakingID: "s" + id, NodeID: id, ConsensusKey: key, Weight: w})
		total += w
	}
	b.RootThreshold = 2*total/3 + 1
	require.NoError(t, b.Validate())
	return b, signers
}
