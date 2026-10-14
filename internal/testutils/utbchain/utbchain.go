// Package utbchain builds a chain of signed trust-base entries for tests: a committee of four fixed keys, a genesis entry and successors signed by the
// first three members.
package utbchain

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

type Member struct {
	ID     string
	Key    []byte
	Signer abcrypto.Signer
}

type Chain struct {
	Members []Member
	Genesis *types.RootTrustBaseV2
	// Entries[i] is the canonical signed bytes of epoch i+2 (the genesis is epoch 1 and has no signed bytes of its own)
	Entries [][]byte
}

func Committee(t *testing.T) []Member {
	var out []Member
	for i := 0; i < 4; i++ {
		s, err := abcrypto.NewInMemorySecp256K1SignerFromKey(bytes.Repeat([]byte{byte(i + 1)}, 32))
		require.NoError(t, err)
		v, _ := s.Verifier()
		pk, _ := v.MarshalPublicKey()
		pub, err := crypto.UnmarshalSecp256k1PublicKey(pk)
		require.NoError(t, err)
		id, err := peer.IDFromPublicKey(pub)
		require.NoError(t, err)
		out = append(out, Member{id.String(), pk, s})
	}
	return out
}

func Facts(ms []Member, epoch, start uint64) utb.SuccessorFacts {
	var members []utb.Member
	for _, m := range ms {
		members = append(members, utb.Member{NodeID: m.ID, Key: m.Key, Weight: 1})
	}
	return utb.SuccessorFacts{Network: 5, Epoch: epoch, EpochStart: start, Members: members, Threshold: 3,
		StateHash: bytes.Repeat([]byte{0x22}, 32), ChangeRecordHash: bytes.Repeat([]byte{0x33}, 32)}
}

// New builds the genesis and the entries of epochs 2..upTo.
func New(t *testing.T, upTo uint64) *Chain {
	c := &Chain{Members: Committee(t)}
	g, err := utb.BuildUnsigned(nil, Facts(c.Members, 1, 1))
	require.NoError(t, err)
	c.Genesis = g
	prev := g
	for e := uint64(2); e <= upTo; e++ {
		next, err := utb.BuildUnsigned(prev, Facts(c.Members, e, e*100))
		require.NoError(t, err)
		for _, m := range c.Members[:3] {
			require.NoError(t, next.Sign(m.ID, m.Signer))
		}
		raw, err := next.MarshalCBOR()
		require.NoError(t, err)
		c.Entries = append(c.Entries, raw)
		prev = next
	}
	return c
}

// Pin is the genesis EntryID.
func (c *Chain) Pin(t *testing.T) [32]byte {
	id, err := c.Genesis.EntryID()
	require.NoError(t, err)
	return id
}

// Store opens a fresh store holding the genesis and the entries of epochs 2..upTo (upTo 1: the genesis alone).
func (c *Chain) Store(t *testing.T, upTo uint64) *utbstore.Store {
	s, err := utbstore.Open(memorydb.New(), c.Genesis, c.Pin(t))
	require.NoError(t, err)
	for e := uint64(2); e <= upTo; e++ {
		_, err := s.Append(c.Entries[e-2])
		require.NoError(t, err)
	}
	return s
}
