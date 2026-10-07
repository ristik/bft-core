package registryproof

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
)

var activeS1 = named("active-s1")

func v2Genesis() words {
	return genesisWords().with("layoutVersion", num(2), "assignment.activeConfHash", fullShardConfHash)
}

// afterAck is a v2 registry that imported an acknowledgement: the cursor counts the imports, the
// assignment words are the post-state of the privileged open.
func afterAck(cursor, rootEpoch, shardEpoch uint64, active, span common.Hash) words {
	return executed(1, 5, 0, "S0", "").with(
		"layoutVersion", num(2), "assignment.rootEpoch", num(rootEpoch), "assignment.epoch", num(shardEpoch),
		"assignment.activeConfHash", active, "assignment.spanCommitment", span, "transition.cursor", num(cursor),
		"transition.bodyID", named("body"), "transition.genesisID", named("genesis"), "transition.frozenID", named("frozen"),
		"transition.commitID", named("commit"), "transition.frozenParent", named("parent"), "transition.successorTR", named("tr"),
		"origin.rootEpoch", num(rootEpoch))
}

type v2Chain struct {
	genesis block
	ctx     Context
}

func newV2Chain(t *testing.T) v2Chain {
	g := build(t, spec{number: 0, words: v2Genesis(), fillers: 8, layout: 2})
	return v2Chain{genesis: g, ctx: Context{RegistryAddress: RegistryAddress, RegistryCodeHash: registryCodeHash,
		GenesisCommitment: genesisCommitment, FullShardConfHash: fullShardConfHash, ShardEpoch: 0, RootEpoch: 1,
		EVMGenesisHash: g.hash, Layout: 2}}
}

func (c v2Chain) at(t *testing.T, w words) block {
	return build(t, spec{number: 1, parent: c.genesis.hash, words: w, fillers: 8, layout: 2})
}

func TestV2LayoutMatchesTheArtifactOrderAndKeys(t *testing.T) {
	require.Len(t, SlotNamesV2, 30)
	for i, name := range SlotNamesV2 {
		k, err := SlotKeyFor(2, i)
		require.NoError(t, err)
		require.Equal(t, crypto_keccak(slotDomain+name), k, name)
	}
	// The two new keys are the ones the contract pins.
	require.Equal(t, common.HexToHash("0xbcc6e80fb08120fa6610a12120697a935440b6f731eb387496a45ae31fc4f093"), mustSlot(t, "assignment.activeConfHash"))
	require.Equal(t, common.HexToHash("0x1333275c0dde98dea1f7569da4a9013691786d62030b101d14f0f6d68f27fd66"), mustSlot(t, "assignment.spanCommitment"))
	n, err := FieldCountFor(1)
	require.NoError(t, err)
	require.Equal(t, FieldCount, n)
	_, err = FieldCountFor(FreshB1 + 1)
	require.ErrorIs(t, err, ErrContext)
}

func TestV2GenesisVerifiesAndKeepsTheGenesisHashImmutable(t *testing.T) {
	c := newV2Chain(t)
	s, err := Verify(c.ctx, c.genesis.hash, c.genesis.ev)
	require.NoError(t, err)
	f := s.Fields()
	require.EqualValues(t, 2, f.Layout)
	require.Equal(t, fullShardConfHash, f.ShardConfHash)
	require.Equal(t, fullShardConfHash, f.ActiveConfHash, "the active hash is initialized to the genesis hash")
	require.True(t, f.Genesis)

	t.Run("a v1 evidence is not read as v2", func(t *testing.T) {
		v1 := newChain(t)
		_, err := Verify(c.ctx, v1.genesis.hash, v1.genesis.ev)
		require.ErrorIs(t, err, ErrBounds)
	})
	t.Run("a v2 evidence is not read as v1", func(t *testing.T) {
		v1ctx := c.ctx
		v1ctx.Layout = 0
		_, err := Verify(v1ctx, c.genesis.hash, c.genesis.ev)
		require.ErrorIs(t, err, ErrBounds)
	})
	t.Run("genesis with an active hash different from the immutable one", func(t *testing.T) {
		g := build(t, spec{number: 0, words: v2Genesis().with("assignment.activeConfHash", activeS1), fillers: 8, layout: 2})
		ctx := c.ctx
		ctx.EVMGenesisHash = g.hash
		_, err := Verify(ctx, g.hash, g.ev)
		require.ErrorIs(t, err, ErrConfiguration)
		require.ErrorContains(t, err, "active configuration hash")
	})
	t.Run("a span commitment at genesis", func(t *testing.T) {
		g := build(t, spec{number: 0, words: v2Genesis().with("assignment.spanCommitment", named("x")), fillers: 8, layout: 2})
		ctx := c.ctx
		ctx.EVMGenesisHash = g.hash
		_, err := Verify(ctx, g.hash, g.ev)
		require.ErrorIs(t, err, ErrConfiguration)
		require.ErrorContains(t, err, "missing epoch transition")
	})
}

func TestV2AcknowledgedStates(t *testing.T) {
	c := newV2Chain(t)
	cases := []struct {
		name  string
		words words
		want  func(t *testing.T, f Fields)
	}{
		{"root only: epoch advances once, assignment unchanged", afterAck(1, 2, 0, fullShardConfHash, common.Hash{}),
			func(t *testing.T, f Fields) {
				require.EqualValues(t, 2, f.RootEpoch)
				require.EqualValues(t, 0, f.ShardEpoch)
				require.Equal(t, fullShardConfHash, f.ActiveConfHash)
			}},
		{"ordinary EVM change: both epochs advance once", afterAck(1, 2, 1, activeS1, common.Hash{}),
			func(t *testing.T, f Fields) {
				require.EqualValues(t, 1, f.ShardEpoch)
				require.Equal(t, activeS1, f.ActiveConfHash)
				require.Equal(t, fullShardConfHash, f.ShardConfHash, "the genesis hash word never changes")
			}},
		{"supersession: one acknowledgement folds two root epochs", afterAck(1, 3, 2, activeS1, named("span")),
			func(t *testing.T, f Fields) {
				require.EqualValues(t, 3, f.RootEpoch)
				require.EqualValues(t, 2, f.ShardEpoch)
				require.Equal(t, named("span"), f.SpanCommitment)
				require.EqualValues(t, 1, f.TransitionCursor)
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := c.at(t, tc.words)
			s, err := Verify(c.ctx, b.hash, b.ev)
			require.NoError(t, err)
			tc.want(t, s.Fields())
		})
	}
}

func TestV2AssignmentRefusalsFromOneElementChanges(t *testing.T) {
	c := newV2Chain(t)
	cases := []struct {
		name   string
		words  words
		reason string
	}{
		{"active hash zero", afterAck(1, 2, 1, common.Hash{}, common.Hash{}), "active configuration hash is zero"},
		{"shard epoch advanced but active hash still genesis", afterAck(1, 2, 1, fullShardConfHash, common.Hash{}), "active configuration hash"},
		{"active hash changed but shard epoch not", afterAck(1, 2, 0, activeS1, common.Hash{}), "active configuration hash"},
		{"shard epoch ahead of the root epoch delta", afterAck(1, 2, 2, activeS1, common.Hash{}), "not reachable"},
		{"root epoch behind the cursor", afterAck(2, 2, 0, fullShardConfHash, common.Hash{}), "invalid installed transition"},
		{"cursor zero but root epoch moved", genesisWords().with("layoutVersion", num(2), "assignment.activeConfHash", fullShardConfHash, "assignment.rootEpoch", num(2)), "missing epoch transition"},
		{"cursor positive without transition fields", afterAck(1, 2, 0, fullShardConfHash, common.Hash{}).with("transition.bodyID", common.Hash{}), "invalid installed transition"},
		{"wrong layout word", afterAck(1, 2, 0, fullShardConfHash, common.Hash{}).with("layoutVersion", num(1)), "layout version"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := c.at(t, tc.words)
			_, err := Verify(c.ctx, b.hash, b.ev)
			require.ErrorIs(t, err, ErrConfiguration)
			require.ErrorContains(t, err, tc.reason)
		})
	}
}

func TestV2AuthenticatedActiveAssignmentIsolatedMutations(t *testing.T) {
	c := newV2Chain(t)
	b := c.at(t, afterAck(1, 3, 2, activeS1, named("span")))
	active := Assignment{Set: true, ShardEpoch: 2, RootEpoch: 3, ActiveConfHash: activeS1}
	ctx := c.ctx
	ctx.Active = active
	_, err := Verify(ctx, b.hash, b.ev)
	require.NoError(t, err, "the registry holds exactly the authenticated assignment")
	for name, mutate := range map[string]func(*Assignment){
		"shard epoch": func(a *Assignment) { a.ShardEpoch = 1 },
		"root epoch":  func(a *Assignment) { a.RootEpoch = 2 },
		"active hash": func(a *Assignment) { a.ActiveConfHash = named("other") },
	} {
		t.Run(name, func(t *testing.T) {
			bad := active
			mutate(&bad)
			ctx := c.ctx
			ctx.Active = bad
			_, err := Verify(ctx, b.hash, b.ev)
			require.ErrorIs(t, err, ErrConfiguration)
			require.ErrorContains(t, err, "authenticated")
		})
	}
	t.Run("an unset authenticated assignment accepts any internally consistent history", func(t *testing.T) {
		_, err := Verify(c.ctx, b.hash, b.ev)
		require.NoError(t, err)
	})
}

func mustSlot(t *testing.T, name string) common.Hash {
	t.Helper()
	for i, n := range SlotNamesV2 {
		if n == name {
			k, err := SlotKeyFor(2, i)
			require.NoError(t, err)
			return k
		}
	}
	t.Fatalf("no slot %s", name)
	return common.Hash{}
}

func crypto_keccak(s string) common.Hash { return crypto.Keccak256Hash([]byte(s)) }
