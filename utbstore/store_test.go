package utbstore

import (
	"bytes"
	"path/filepath"
	"sort"
	"testing"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/keyvaluedb"
	"github.com/unicitynetwork/bft-core/keyvaluedb/boltdb"
	"github.com/unicitynetwork/bft-core/keyvaluedb/memorydb"
	"github.com/unicitynetwork/bft-core/utb"
)

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

func facts(ns []node, epoch, start uint64, state byte) utb.SuccessorFacts {
	ms := make([]utb.Member, len(ns))
	for i, n := range ns {
		ms[i] = utb.Member{NodeID: n.id, Key: n.key, Weight: 1}
	}
	return utb.SuccessorFacts{Network: 5, Epoch: epoch, EpochStart: start, Members: ms, Threshold: uint64(len(ns))*2/3 + 1,
		StateHash: bytes.Repeat([]byte{state}, 32), ChangeRecordHash: bytes.Repeat([]byte{0x33}, 32)}
}

// chain builds genesis plus k signed successors; every entry is signed by the first three members of the previous one (all epochs share the committee).
func chain(t *testing.T, ns []node, k int, signers []node) []*types.RootTrustBaseV2 {
	g, err := utb.BuildUnsigned(nil, facts(ns, 1, 1, 0x11))
	require.NoError(t, err)
	out := []*types.RootTrustBaseV2{g}
	for i := 0; i < k; i++ {
		e, err := utb.BuildUnsigned(out[i], facts(ns, uint64(i+2), uint64(100*(i+1)), 0x22))
		require.NoError(t, err)
		for _, s := range signers {
			require.NoError(t, e.Sign(s.id, s.signer))
		}
		out = append(out, e)
	}
	return out
}

func enc(t *testing.T, e *types.RootTrustBaseV2) []byte {
	b, err := e.MarshalCBOR()
	require.NoError(t, err)
	return b
}

func pin(t *testing.T, e *types.RootTrustBaseV2) [32]byte {
	id, err := e.EntryID()
	require.NoError(t, err)
	return id
}

func open(t *testing.T, db keyvaluedb.KeyValueDB, g *types.RootTrustBaseV2) *Store {
	s, err := Open(db, g, pin(t, g))
	require.NoError(t, err)
	return s
}

func TestAppendKeepsEveryEntryAndServesStoredBytes(t *testing.T) {
	ns := nodes(t, 4)
	c := chain(t, ns, 5, ns[:3])
	s := open(t, memorydb.New(), c[0])
	for _, e := range c[1:] {
		added, err := s.Append(enc(t, e))
		require.NoError(t, err)
		require.True(t, added)
	}
	require.EqualValues(t, 6, s.Tip().Epoch)
	for i, e := range c {
		got, err := s.Get(uint64(i + 1))
		require.NoError(t, err)
		require.Equal(t, enc(t, e), got)
	}
	_, err := s.Get(7)
	require.ErrorIs(t, err, ErrNotFound)
	_, err = s.Get(0)
	require.ErrorIs(t, err, ErrNotFound)
}

func TestRefusals(t *testing.T) {
	ns := nodes(t, 4)
	c := chain(t, ns, 3, ns[:3])
	s := open(t, memorydb.New(), c[0])
	_, err := s.Append(enc(t, c[1]))
	require.NoError(t, err)

	t.Run("a gap", func(t *testing.T) {
		_, err := s.Append(enc(t, c[3]))
		require.ErrorIs(t, err, ErrGap)
		require.EqualValues(t, 2, s.Tip().Epoch)
	})
	t.Run("an unsigned entry", func(t *testing.T) {
		u, err := utb.BuildUnsigned(c[1], facts(ns, 3, 500, 0x22))
		require.NoError(t, err)
		_, err = s.Append(enc(t, u))
		require.ErrorIs(t, err, ErrEntry)
	})
	t.Run("below quorum", func(t *testing.T) {
		weak := chain(t, ns, 2, ns[:2])
		_, err := s.Append(enc(t, weak[2]))
		require.ErrorIs(t, err, ErrEntry)
	})
	t.Run("an invalid extra signature after quorum", func(t *testing.T) {
		e, err := utb.BuildUnsigned(c[1], facts(ns, 3, 200, 0x22))
		require.NoError(t, err)
		for _, n := range ns[:3] {
			require.NoError(t, e.Sign(n.id, n.signer))
		}
		bad := bytes.Clone(e.Signatures[ns[0].id])
		bad[5] ^= 1
		e.Signatures[ns[3].id] = bad
		_, err = s.Append(enc(t, e))
		require.ErrorIs(t, err, ErrEntry)
	})
	t.Run("garbage and trailing bytes", func(t *testing.T) {
		_, err := s.Append([]byte{1, 2, 3})
		require.ErrorIs(t, err, ErrEntry)
		_, err = s.Append(append(enc(t, c[2]), 0))
		require.ErrorIs(t, err, ErrEntry)
	})
	t.Run("more members than the deployment admits", func(t *testing.T) {
		many := nodes(t, utb.MaxMembers+1)
		g, err := types.DecodeRootTrustBaseV2(mustBig(t, many))
		require.NoError(t, err)
		_, err = Open(memorydb.New(), g, pin(t, g))
		require.ErrorIs(t, err, ErrGenesis)
	})
	t.Run("a successor with more members than the deployment admits", func(t *testing.T) {
		many := nodes(t, utb.MaxMembers+1)
		var ms []*types.NodeInfo
		for _, n := range many {
			ms = append(ms, &types.NodeInfo{NodeID: n.id, SigKey: n.key, Stake: 1})
		}
		sort.Slice(ms, func(i, j int) bool { return ms[i].NodeID < ms[j].NodeID })
		id, _ := c[1].EntryID()
		e := &types.RootTrustBaseV2{Version: 2, NetworkID: 5, Epoch: 3, EpochStart: 900, RootNodes: ms, QuorumThreshold: 12, PreviousEntryID: id[:]}
		for _, n := range ns[:3] {
			require.NoError(t, e.Sign(n.id, n.signer))
		}
		require.NoError(t, e.VerifySuccessor(c[1]), "go-base accepts it")
		_, err := s.Append(enc(t, e))
		require.ErrorIs(t, err, ErrEntry)
	})
	t.Run("the wrong genesis pin", func(t *testing.T) {
		_, err := Open(memorydb.New(), c[0], [32]byte{1})
		require.ErrorIs(t, err, ErrGenesis)
	})
	t.Run("a non-genesis entry as genesis", func(t *testing.T) {
		_, err := Open(memorydb.New(), c[1], pin(t, c[1]))
		require.ErrorIs(t, err, ErrGenesis)
	})
}

func mustBig(t *testing.T, ns []node) []byte {
	var ms []*types.NodeInfo
	for _, n := range ns {
		ms = append(ms, &types.NodeInfo{NodeID: n.id, SigKey: n.key, Stake: 1})
	}
	// sort by id as the entry requires
	for i := range ms {
		for j := i + 1; j < len(ms); j++ {
			if ms[j].NodeID < ms[i].NodeID {
				ms[i], ms[j] = ms[j], ms[i]
			}
		}
	}
	e := &types.RootTrustBaseV2{Version: 2, NetworkID: 5, Epoch: 1, EpochStart: 1, RootNodes: ms, QuorumThreshold: uint64(len(ms))*2/3 + 1, PreviousEntryID: make([]byte, 32)}
	return enc(t, e)
}

func TestReplayRules(t *testing.T) {
	ns := nodes(t, 4)
	abc := chain(t, ns, 2, ns[:3])
	bcd := chain(t, ns, 2, ns[1:])
	s := open(t, memorydb.New(), abc[0])
	for _, e := range abc[1:] {
		_, err := s.Append(enc(t, e))
		require.NoError(t, err)
	}
	t.Run("the same entry is idempotent", func(t *testing.T) {
		added, err := s.Append(enc(t, abc[1]))
		require.NoError(t, err)
		require.False(t, added)
	})
	t.Run("another valid witness for the same unsigned entry is idempotent and the first is kept", func(t *testing.T) {
		require.Equal(t, pin(t, abc[1]), pin(t, bcd[1]), "same EntryID")
		require.NotEqual(t, enc(t, abc[1]), enc(t, bcd[1]), "different full bytes")
		added, err := s.Append(enc(t, bcd[1]))
		require.NoError(t, err)
		require.False(t, added)
		got, _ := s.Get(2)
		require.Equal(t, enc(t, abc[1]), got)
	})
	t.Run("a cached EntryID does not excuse an invalid witness", func(t *testing.T) {
		bad := chain(t, ns, 1, ns[1:])[1]
		sig := bytes.Clone(bad.Signatures[ns[1].id])
		sig[5] ^= 1
		bad.Signatures[ns[1].id] = sig
		require.Equal(t, pin(t, abc[1]), pin(t, bad))
		_, err := s.Append(enc(t, bad))
		require.ErrorIs(t, err, ErrEntry)
	})
	t.Run("a different unsigned entry of a stored epoch is a conflict", func(t *testing.T) {
		other, err := utb.BuildUnsigned(abc[0], facts(ns, 2, 100, 0x99))
		require.NoError(t, err)
		for _, n := range ns[:3] {
			require.NoError(t, other.Sign(n.id, n.signer))
		}
		_, err = s.Append(enc(t, other))
		require.ErrorIs(t, err, ErrConflict)
	})
	t.Run("the genesis replays", func(t *testing.T) {
		added, err := s.Append(enc(t, abc[0]))
		require.NoError(t, err)
		require.False(t, added)
	})
}

func TestPersistenceAndLoadValidation(t *testing.T) {
	ns := nodes(t, 4)
	c := chain(t, ns, 4, ns[:3])
	path := filepath.Join(t.TempDir(), "utb.db")
	db, err := boltdb.New(path)
	require.NoError(t, err)
	s := open(t, db, c[0])
	for _, e := range c[1:3] {
		_, err := s.Append(enc(t, e))
		require.NoError(t, err)
	}
	require.NoError(t, db.Close())

	db, err = boltdb.New(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	s = open(t, db, c[0])
	require.EqualValues(t, 3, s.Tip().Epoch, "the history survives a restart")
	_, err = s.Append(enc(t, c[3]))
	require.NoError(t, err)

	t.Run("another genesis is refused", func(t *testing.T) {
		other := chain(t, nodes(t, 5), 0, nil)[0]
		_, err := Open(db, other, pin(t, other))
		require.ErrorIs(t, err, ErrIncompatible)
	})
	t.Run("a corrupted stored entry is refused", func(t *testing.T) {
		m := memorydb.New()
		s := open(t, m, c[0])
		_, err := s.Append(enc(t, c[1]))
		require.NoError(t, err)
		b := enc(t, c[1])
		b[len(b)-3] ^= 1
		require.NoError(t, m.Write(key(2), b))
		_, err = Open(m, c[0], pin(t, c[0]))
		require.ErrorIs(t, err, ErrIncompatible)
	})
	t.Run("a stored entry that does not chain is refused", func(t *testing.T) {
		m := memorydb.New()
		open(t, m, c[0])
		require.NoError(t, m.Write(key(2), enc(t, c[2])))
		_, err := Open(m, c[0], pin(t, c[0]))
		require.ErrorIs(t, err, ErrIncompatible)
	})
	t.Run("an entry beyond a gap is refused", func(t *testing.T) {
		m := memorydb.New()
		s := open(t, m, c[0])
		_, err := s.Append(enc(t, c[1]))
		require.NoError(t, err)
		require.NoError(t, m.Write(key(4), enc(t, c[3])))
		_, err = Open(m, c[0], pin(t, c[0]))
		require.ErrorIs(t, err, ErrIncompatible)
	})
}

func TestRangePaging(t *testing.T) {
	ns := nodes(t, 4)
	c := chain(t, ns, 5, ns[:3])
	s := open(t, memorydb.New(), c[0])
	for _, e := range c[1:] {
		_, err := s.Append(enc(t, e))
		require.NoError(t, err)
	}
	got, next, more, err := s.Range(2, 100, 2, 1<<20)
	require.NoError(t, err)
	require.Len(t, got, 2)
	require.True(t, more)
	require.EqualValues(t, 4, next, "the first unsent epoch")
	got, _, more, err = s.Range(next, 100, 10, 1<<20)
	require.NoError(t, err)
	require.Len(t, got, 3)
	require.False(t, more, "to is clamped to the tip")
	_, _, _, err = s.Range(2, 3, 10, 10)
	require.ErrorIs(t, err, ErrBudget, "never an empty page with a continuation")
	_, _, _, err = s.Range(7, 9, 10, 1<<20)
	require.ErrorIs(t, err, ErrNotFound)
	one := len(enc(t, c[1])) + len(enc(t, c[2])) - 1
	got, next, more, err = s.Range(2, 6, 10, one)
	require.NoError(t, err)
	require.Len(t, got, 1, "the byte budget bounds the page")
	require.True(t, more)
	require.EqualValues(t, 3, next)
}
