package utb

import (
	"bytes"
	stdcrypto "crypto"
	"fmt"
	"math/rand"
	"testing"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/q3format"
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
		pk, err := v.MarshalPublicKey()
		require.NoError(t, err)
		pub, err := crypto.UnmarshalSecp256k1PublicKey(pk)
		require.NoError(t, err)
		id, err := peer.IDFromPublicKey(pub)
		require.NoError(t, err)
		out[i] = node{id.String(), pk, s}
	}
	return out
}

func facts(ns []node, epoch, start uint64) SuccessorFacts {
	ms := make([]Member, len(ns))
	for i, n := range ns {
		ms[i] = Member{NodeID: n.id, Key: n.key, Weight: 1}
	}
	total := uint64(len(ns))
	return SuccessorFacts{Network: 5, Epoch: epoch, EpochStart: start, Members: ms, Threshold: total*2/3 + 1,
		StateHash: bytes.Repeat([]byte{0x22}, 32), ChangeRecordHash: bytes.Repeat([]byte{0x33}, 32)}
}

func signed(t *testing.T, e *types.RootTrustBaseV2, by []node) {
	for _, n := range by {
		require.NoError(t, e.Sign(n.id, n.signer))
	}
}

func TestBuildGenesisAndSuccessorChain(t *testing.T) {
	ns := nodes(t, 4)
	g, err := BuildUnsigned(nil, facts(ns, 1, 1))
	require.NoError(t, err)
	require.NoError(t, g.VerifyGenesis())
	e2, err := BuildUnsigned(g, facts(ns, 2, 100))
	require.NoError(t, err)
	gid, _ := g.EntryID()
	require.Equal(t, gid[:], []byte(e2.PreviousEntryID), "the link is the predecessor's unsigned EntryID")
	signed(t, e2, ns[:3])
	require.NoError(t, e2.VerifySuccessor(g))
}

func TestBuilderRefusesFactsThatDoNotExtendThePredecessor(t *testing.T) {
	ns := nodes(t, 4)
	g, err := BuildUnsigned(nil, facts(ns, 1, 10))
	require.NoError(t, err)
	for name, mut := range map[string]func(f *SuccessorFacts){
		"other network":  func(f *SuccessorFacts) { f.Network = 6 },
		"epoch skipped":  func(f *SuccessorFacts) { f.Epoch = 3 },
		"epoch repeated": func(f *SuccessorFacts) { f.Epoch = 1 },
		"start equal":    func(f *SuccessorFacts) { f.EpochStart = 10 },
		"start earlier":  func(f *SuccessorFacts) { f.EpochStart = 9 },
	} {
		t.Run(name, func(t *testing.T) {
			f := facts(ns, 2, 100)
			mut(&f)
			_, err := BuildUnsigned(g, f)
			require.ErrorIs(t, err, ErrChain)
		})
	}
	t.Run("an invalid predecessor", func(t *testing.T) {
		bad := *g
		bad.QuorumThreshold = 1
		_, err := BuildUnsigned(&bad, facts(ns, 2, 100))
		require.ErrorIs(t, err, ErrChain)
	})
}

func TestBuilderEnforcesTheDeploymentMemberLimit(t *testing.T) {
	ns := nodes(t, MaxMembers+1)
	_, err := BuildUnsigned(nil, facts(ns[:MaxMembers], 1, 1))
	require.NoError(t, err, "16 members are admitted")
	_, err = BuildUnsigned(nil, facts(ns, 1, 1))
	require.ErrorIs(t, err, ErrFacts, "17 are not, although go-base would decode them")
	_, err = BuildUnsigned(nil, facts(nil, 1, 1))
	require.ErrorIs(t, err, ErrFacts)
}

func TestBuilderRefusesInvalidMembersAndThreshold(t *testing.T) {
	ns := nodes(t, 4)
	for name, mut := range map[string]func(f *SuccessorFacts){
		"threshold low":  func(f *SuccessorFacts) { f.Threshold = 2 },
		"threshold high": func(f *SuccessorFacts) { f.Threshold = 4 },
		"zero weight":    func(f *SuccessorFacts) { f.Members[0].Weight = 0 },
		"huge weight":    func(f *SuccessorFacts) { f.Members[0].Weight = types.MaxTrustBaseV2Weight + 1 },
		"id not key's peer id": func(f *SuccessorFacts) {
			f.Members[0].NodeID, f.Members[1].NodeID = f.Members[1].NodeID, f.Members[0].NodeID
		},
		"not a peer id":     func(f *SuccessorFacts) { f.Members[0].NodeID = "n1" },
		"bad key":           func(f *SuccessorFacts) { f.Members[0].Key = f.Members[0].Key[:32] },
		"duplicate member":  func(f *SuccessorFacts) { f.Members[1] = f.Members[0] },
		"state hash length": func(f *SuccessorFacts) { f.StateHash = []byte{1} },
		"network too large": func(f *SuccessorFacts) { f.Network = 1 << 33 },
	} {
		t.Run(name, func(t *testing.T) {
			f := facts(ns, 1, 1)
			mut(&f)
			_, err := BuildUnsigned(nil, f)
			require.ErrorIs(t, err, ErrFacts)
		})
	}
	t.Run("weighted threshold", func(t *testing.T) {
		f := facts(ns, 1, 1)
		f.Members[0].Weight, f.Members[1].Weight = 5, 3 // W = 10
		f.Threshold = 7
		_, err := BuildUnsigned(nil, f)
		require.NoError(t, err)
	})
}

func TestMemberOrderOfTheInputDoesNotChangeTheBytes(t *testing.T) {
	ns := nodes(t, 7)
	g1, err := BuildUnsigned(nil, facts(ns, 1, 1))
	require.NoError(t, err)
	f := facts(ns, 1, 1)
	rand.New(rand.NewSource(1)).Shuffle(len(f.Members), func(i, j int) { f.Members[i], f.Members[j] = f.Members[j], f.Members[i] })
	g2, err := BuildUnsigned(nil, f)
	require.NoError(t, err)
	b1, _ := g1.SigBytes()
	b2, _ := g2.SigBytes()
	require.Equal(t, b1, b2)
}

// The root's V2 handoff body and the Q3 body carry the same member/threshold/hash facts; both reach the same unsigned bytes and EntryID.
func TestV2AndQ3BodiesGiveTheSameUnsignedEntry(t *testing.T) {
	ns := nodes(t, 5)
	g, err := BuildUnsigned(nil, facts(ns, 1, 1))
	require.NoError(t, err)
	var ws evmroot.WeightSet
	for i, n := range ns {
		ws = append(ws, evmroot.Member{StakingID: fmt.Sprintf("s%d", i), NodeID: n.id, ConsensusKey: n.key, Weight: 1})
	}
	state, change := bytes.Repeat([]byte{0x22}, 32), bytes.Repeat([]byte{0x33}, 32)
	v2 := evmroot.TrustBaseBodyV2{Version: evmroot.TrustBaseVersion, NetworkID: 5, Epoch: 2, EarliestActivation: 50, Members: ws, RootThreshold: 4, StateSummary: state, ChangeRecordHash: change}
	q3 := q3format.BodyV3{Network: 5, Epoch: 2, EarliestActivation: 50, Members: ws, RootThreshold: 4, StateSummary: state, ChangeRecordHash: change}
	const activation = 120 // the committed record's actual ActivationRound, not EarliestActivation
	a, err := BuildUnsigned(g, FromBodyV2(v2, activation))
	require.NoError(t, err)
	b, err := BuildUnsigned(g, FromWeightSet(q3.Network, q3.Epoch, activation, q3.Members, q3.RootThreshold, q3.StateSummary, q3.ChangeRecordHash))
	require.NoError(t, err)
	ab, _ := a.SigBytes()
	bb, _ := b.SigBytes()
	require.Equal(t, ab, bb)
	require.EqualValues(t, activation, a.EpochStart)
	// the body identity is a different thing from the entry identity
	eid, _ := a.EntryID()
	bid := v2.Identity()
	require.NotEqual(t, eid[:], bid[:])
}

func TestProjectionCarriesKeysAndWeightsButNotTheLineage(t *testing.T) {
	ns := nodes(t, 4)
	g, _ := BuildUnsigned(nil, facts(ns, 1, 1))
	e2, err := BuildUnsigned(g, facts(ns, 2, 100))
	require.NoError(t, err)
	signed(t, e2, ns[:3])
	p, err := Projection(e2)
	require.NoError(t, err)
	require.EqualValues(t, 2, p.Epoch)
	require.EqualValues(t, 100, p.EpochStart)
	require.EqualValues(t, e2.QuorumThreshold, p.QuorumThreshold)
	require.Len(t, p.RootNodes, 4)
	require.Empty(t, p.PreviousEntryHash, "no lineage in the projection")
	h, err := p.Hash(stdcrypto.SHA256)
	require.NoError(t, err)
	id, _ := e2.EntryID()
	require.NotEqual(t, id[:], h, "the projection's Hash is not the entry identity")
	_, err = Projection(&types.RootTrustBaseV2{})
	require.Error(t, err)
}
