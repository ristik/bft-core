package gettrustbase

import (
	"bytes"
	"testing"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/keyvaluedb/memorydb"
	"github.com/unicitynetwork/bft-core/utb"
	"github.com/unicitynetwork/bft-core/utbstore"
)

const testNetwork = 5

type node struct {
	id     string
	key    []byte
	signer abcrypto.Signer
}

func nodes(t *testing.T, n int) []node {
	out := make([]node, n)
	for i := range out {
		s, err := abcrypto.NewInMemorySecp256K1SignerFromKey(bytes.Repeat([]byte{byte(i + 1)}, 32))
		require.NoError(t, err)
		v, _ := s.Verifier()
		pk, _ := v.MarshalPublicKey()
		pub, err := crypto.UnmarshalSecp256k1PublicKey(pk)
		require.NoError(t, err)
		id, err := peer.IDFromPublicKey(pub)
		require.NoError(t, err)
		out[i] = node{id.String(), pk, s}
	}
	return out
}

func facts(ns []node, epoch, start uint64) utb.SuccessorFacts {
	ms := make([]utb.Member, len(ns))
	for i, n := range ns {
		ms[i] = utb.Member{NodeID: n.id, Key: n.key, Weight: 1}
	}
	return utb.SuccessorFacts{Network: testNetwork, Epoch: epoch, EpochStart: start, Members: ms, Threshold: uint64(len(ns))*2/3 + 1,
		StateHash: bytes.Repeat([]byte{0x22}, 32), ChangeRecordHash: bytes.Repeat([]byte{0x33}, 32)}
}

// chain is genesis plus k successors, each signed by the first three members of the previous one.
func chain(t *testing.T, ns []node, k int) []*types.RootTrustBaseV2 {
	g, err := utb.BuildUnsigned(nil, facts(ns, 1, 1))
	require.NoError(t, err)
	out := []*types.RootTrustBaseV2{g}
	for i := 0; i < k; i++ {
		e, err := utb.BuildUnsigned(out[i], facts(ns, uint64(i+2), uint64(100*(i+1))))
		require.NoError(t, err)
		for _, s := range ns[:3] {
			require.NoError(t, e.Sign(s.id, s.signer))
		}
		out = append(out, e)
	}
	return out
}

func raw(t *testing.T, es []*types.RootTrustBaseV2) [][]byte {
	out := make([][]byte, len(es))
	for i, e := range es {
		b, err := e.MarshalCBOR()
		require.NoError(t, err)
		out[i] = b
	}
	return out
}

func idOf(t *testing.T, e *types.RootTrustBaseV2) [32]byte {
	id, err := e.EntryID()
	require.NoError(t, err)
	return id
}

// store opens a store holding the genesis and the first `held` successors of the chain.
func store(t *testing.T, es []*types.RootTrustBaseV2, held int) *utbstore.Store {
	s, err := utbstore.Open(memorydb.New(), es[0], idOf(t, es[0]))
	require.NoError(t, err)
	for _, b := range raw(t, es)[1 : held+1] {
		_, err := s.Append(b)
		require.NoError(t, err)
	}
	return s
}

func u64(v uint64) *uint64 { return &v }
