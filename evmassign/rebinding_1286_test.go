package evmassign

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"
)

// rebinding is #1286's case: the root committee o1..o4 is unchanged, and its incumbent K binds o1..o4 to the installed a..d. The
// successor replaces o2's delegate b by a fresh node e (a new node id and key); the other three bindings are kept.
type rebinding struct {
	cur, succ *types.PartitionDescriptionRecord
	root      []RootMember
	bindings  []Binding
	auth      *Authorization
	signers   map[string]keyed
	ctx       PoPContext
}

func newRebinding(t *testing.T, succKeys func(old []keyed, fresh keyed) []keyed, bind func(succ *types.PartitionDescriptionRecord) []Binding) rebinding {
	t.Helper()
	cur, old := currentPDR(t)
	root := rootOf("o", 9)
	k := identitiesFor(root, cur, bindingsFor(root, cur), "")
	base, err := AssignmentHash(cur, mustDigest(t, k))
	require.NoError(t, err)
	fresh := newKey(t, "e")
	keys := succKeys(old, fresh)
	infos := make([]*types.NodeInfo, len(keys))
	signers := map[string]keyed{}
	for i, x := range keys {
		infos[i] = x.info
		signers[x.id] = x
	}
	succ, err := NewSuccessor(cur, infos)
	require.NoError(t, err)
	r := rebinding{cur: cur, succ: succ, root: root, auth: authFor(5, bytes.Clone(append([]byte{1}, make([]byte, 31)...)), base, k), signers: signers}
	r.bindings = bind(succ)
	r.ctx = PoPContext{Network: 5, Predecessor: [32]byte{1}, Attempt: 2, Identities: mustDigest(t, identitiesFor(root, succ, r.bindings, ""))}
	return r
}

// replaceB keeps a, c, d and replaces b by the fresh e; o2 (b's entity) takes e.
func replaceB(old []keyed, fresh keyed) []keyed { return []keyed{old[0], fresh, old[2], old[3]} }

func bindExplicit(pairs ...string) func(*types.PartitionDescriptionRecord) []Binding {
	return func(*types.PartitionDescriptionRecord) []Binding {
		out := make([]Binding, 0, len(pairs)/2)
		for i := 0; i < len(pairs); i += 2 {
			out = append(out, Binding{RootNodeID: pairs[i], EVMNodeID: pairs[i+1]})
		}
		return out
	}
}

func (r rebinding) pops(t *testing.T, ctx PoPContext) []PoP {
	t.Helper()
	out := make([]PoP, 0, len(r.succ.Validators))
	for _, v := range r.succ.Validators {
		p, err := SignPoP(r.signers[v.NodeID].signer, ctx, r.succ, v.NodeID)
		require.NoError(t, err)
		out = append(out, p)
	}
	return out
}

func (r rebinding) candidate(t *testing.T, pops []PoP) Candidate {
	t.Helper()
	c, err := NewCandidate(r.ctx, r.root, r.cur, r.succ, pops, nil, r.bindings,
		Lifecycle{Kind: KindPrimary, Identities: identitiesFor(r.root, r.succ, r.bindings, ""), Authorization: r.auth}, nil)
	require.NoError(t, err)
	return c
}

func (r rebinding) verify(t *testing.T, c Candidate) error {
	t.Helper()
	raw, err := c.Encode()
	require.NoError(t, err)
	d := sha256.Sum256(raw)
	_, _, err = Verify(raw, VerifyContext{BindingContext: BindingContext{PoPContext: r.ctx, SuccessorRoot: r.root, Digest: d[:]}, Current: r.cur, CurrentRoot: r.root})
	return err
}

// #1286 (astra): a retained root entity replaces its delegated EVM node and key in an assignment handoff with the committee unchanged.
func TestABindingReplacementOfARetainedRootEntityIsAllowed(t *testing.T) {
	r := newRebinding(t, replaceB, bindExplicit("o1", "a", "o2", "e", "o3", "c", "o4", "d"))
	c := r.candidate(t, r.pops(t, r.ctx))
	require.True(t, RebindingOnly(c, r.succ, r.cur))
	require.NoError(t, VerifyInstalled(c, r.succ, r.cur, r.root))
	require.NoError(t, r.verify(t, c), "the whole binding path (digest, context, every successor key's PoP, coupling, installed)")
	// the retired key is not in the successor set: it carries no signing weight in s+1 and cannot count toward the successor's ack
	for _, v := range r.succ.Validators {
		require.NotEqual(t, "b", v.NodeID)
		require.False(t, bytes.Equal(r.signers["e"].info.SigKey, r.cur.Validators[1].SigKey))
	}
}

func TestEVMOnlyChangesOtherThanABindingReplacementStayRefused(t *testing.T) {
	t.Run("a swapped binding between equal-weight entities", func(t *testing.T) {
		// o2 takes c (o3's delegate) and o3 takes the fresh e: the same sizes and weights, but o2's replacement is another entity's node
		r := newRebinding(t, replaceB, bindExplicit("o1", "a", "o2", "c", "o3", "e", "o4", "d"))
		c := r.candidate(t, r.pops(t, r.ctx))
		require.False(t, RebindingOnly(c, r.succ, r.cur))
		require.ErrorIs(t, VerifyInstalled(c, r.succ, r.cur, r.root), ErrEVMOnly)
	})
	t.Run("a pure swap of two delegates with the EVM set unchanged", func(t *testing.T) {
		r := newRebinding(t, func(old []keyed, _ keyed) []keyed { return old }, bindExplicit("o1", "b", "o2", "a", "o3", "c", "o4", "d"))
		c := r.candidate(t, r.pops(t, r.ctx))
		require.ErrorIs(t, VerifyInstalled(c, r.succ, r.cur, r.root), ErrEVMOnly)
	})
	t.Run("the authorized bindings with the EVM set unchanged (a configuration-only boundary) are allowed", func(t *testing.T) {
		r := newRebinding(t, func(old []keyed, _ keyed) []keyed { return old }, bindExplicit("o1", "a", "o2", "b", "o3", "c", "o4", "d"))
		c := r.candidate(t, r.pops(t, r.ctx))
		require.NoError(t, VerifyInstalled(c, r.succ, r.cur, r.root))
	})
	t.Run("a weight change", func(t *testing.T) {
		r := newRebinding(t, replaceB, bindExplicit("o1", "a", "o2", "e", "o3", "c", "o4", "d"))
		c := r.candidate(t, r.pops(t, r.ctx))
		heavy := clonePDR(t, r.succ)
		for _, v := range heavy.Validators {
			if v.NodeID == "e" {
				v.Stake = 2
			}
		}
		require.False(t, RebindingOnly(c, heavy, r.cur))
	})
	t.Run("an EVM validator added without its root entity (a count change)", func(t *testing.T) {
		r := newRebinding(t, func(old []keyed, fresh keyed) []keyed { return append(append([]keyed{}, old...), fresh) },
			bindExplicit("o1", "a", "o2", "b", "o3", "c", "o4", "d"))
		c := Candidate{RootMembers: r.root, Bindings: r.bindings, Authorization: r.auth}
		require.False(t, RebindingOnly(c, r.succ, r.cur))
		require.ErrorIs(t, VerifyInstalled(c, r.succ, r.cur, r.root), ErrEVMOnly)
	})
	t.Run("an EVM validator removed without its root entity", func(t *testing.T) {
		r := newRebinding(t, func(old []keyed, _ keyed) []keyed { return old[:3] }, bindExplicit("o1", "a", "o2", "b", "o3", "c"))
		c := Candidate{RootMembers: r.root, Bindings: r.bindings, Authorization: r.auth}
		require.False(t, RebindingOnly(c, r.succ, r.cur))
		require.ErrorIs(t, VerifyInstalled(c, r.succ, r.cur, r.root), ErrEVMOnly)
	})
	t.Run("a key change under a kept node id", func(t *testing.T) {
		r := newRebinding(t, func(old []keyed, _ keyed) []keyed {
			b2 := newKey(t, "b") // the same node id b with another key
			return []keyed{old[0], b2, old[2], old[3]}
		}, bindExplicit("o1", "a", "o2", "b", "o3", "c", "o4", "d"))
		c := r.candidate(t, r.pops(t, r.ctx))
		require.ErrorIs(t, VerifyInstalled(c, r.succ, r.cur, r.root), ErrEVMOnly)
	})
	t.Run("without the frozen incumbent authorization (the legacy path stays fenced)", func(t *testing.T) {
		r := newRebinding(t, replaceB, bindExplicit("o1", "a", "o2", "e", "o3", "c", "o4", "d"))
		c := r.candidate(t, r.pops(t, r.ctx))
		c.Authorization = nil
		require.ErrorIs(t, VerifyInstalled(c, r.succ, r.cur, r.root), ErrEVMOnly)
	})
	t.Run("an authorization whose K is not the installed assignment", func(t *testing.T) {
		r := newRebinding(t, replaceB, bindExplicit("o1", "a", "o2", "e", "o3", "c", "o4", "d"))
		c := r.candidate(t, r.pops(t, r.ctx))
		a := *c.Authorization
		a.BaseAssignmentHash = bytes.Repeat([]byte{7}, 32)
		c.Authorization = &a
		require.ErrorIs(t, VerifyInstalled(c, r.succ, r.cur, r.root), ErrEVMOnly)
	})
}

// The replacement's possession proof is VerifyBinding's: every successor key, the new one included, signs for this attempt.
func TestABindingReplacementNeedsFreshAttemptBoundProofs(t *testing.T) {
	r := newRebinding(t, replaceB, bindExplicit("o1", "a", "o2", "e", "o3", "c", "o4", "d"))
	t.Run("the new key's proof signed by the retired key", func(t *testing.T) {
		pops := r.pops(t, r.ctx)
		for i, v := range r.succ.Validators {
			if v.NodeID == "e" {
				p, err := SignPoP(newKey(t, "b").signer, r.ctx, r.succ, "e")
				require.NoError(t, err)
				pops[i] = p
			}
		}
		c := r.candidate(t, r.pops(t, r.ctx))
		c.PoPs = pops
		require.ErrorIs(t, r.verify(t, c), ErrPoP)
	})
	t.Run("a proof replayed from an earlier attempt", func(t *testing.T) {
		earlier := r.ctx
		earlier.Attempt = r.ctx.Attempt - 1
		c := r.candidate(t, r.pops(t, r.ctx))
		c.PoPs = r.pops(t, earlier)
		require.ErrorIs(t, r.verify(t, c), ErrPoP)
	})
}
