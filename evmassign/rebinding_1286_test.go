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
	// the retired node and key are not in the successor set (that they count nothing in s+1 is the storage test
	// TestTheRetiredEVMKeyOfARebindingCountsNothingInTheNextShardEpoch)
	for _, v := range r.succ.Validators {
		require.NotEqual(t, "b", v.NodeID)
		require.False(t, bytes.Equal(v.SigKey, r.cur.Validators[1].SigKey))
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

// rebindingPrimaryWorld is the review's P1-1 world: K binds r1..r4 to a..d; the committed primary J keeps the committee and rebinds r4
// to the fresh e; J is installed (activated) and unacknowledged.
func rebindingPrimaryWorld(t *testing.T) *lifecycleWorld {
	t.Helper()
	w := &lifecycleWorld{keys: map[string]keyed{}, policy: testPolicy, body: [32]byte{1}}
	old := []keyed{newKey(t, "a"), newKey(t, "b"), newKey(t, "c"), newKey(t, "d")}
	infos := make([]*types.NodeInfo, len(old))
	for i, k := range old {
		infos[i] = k.info
		w.keys[k.id] = k
	}
	cur, _ := currentPDR(t)
	cur.Validators = infos
	w.current = cur
	w.kRoot = []RootMember{{NodeID: "r1"}, {NodeID: "r2"}, {NodeID: "r3"}, {NodeID: "r4"}}
	for i := range w.kRoot {
		w.kRoot[i].Key, w.kRoot[i].Weight = bytes.Repeat([]byte{byte(10 + i)}, 33), 1
	}
	w.k = identitiesFor(w.kRoot, cur, []Binding{bind("r1", "a"), bind("r2", "b"), bind("r3", "c"), bind("r4", "d")}, "")
	w.baseHash = mustAssignment(t, cur, w.k)
	w.auth = authFor(5, w.body[:], w.baseHash, w.k)
	e := newKey(t, "e")
	w.keys["e"] = e
	w.jRoot, w.jBindings = w.kRoot, []Binding{bind("r1", "a"), bind("r2", "b"), bind("r3", "c"), bind("r4", "e")}
	succ, err := NewSuccessor(cur, []*types.NodeInfo{old[0].info, old[1].info, old[2].info, e.info})
	require.NoError(t, err)
	w.jSucc, w.jIDs = succ, identitiesFor(w.jRoot, succ, w.jBindings, "")
	w.j = w.primary(t, w.jIDs, w.jRoot, w.jBindings, succ, w.auth, 0)
	require.NoError(t, VerifyInstalled(w.j, succ, cur, w.kRoot))
	require.NoError(t, VerifyLifecycle(w.j, w.ctx(0, 0, false)))
	w.installed, err = Activate(succ, 40)
	require.NoError(t, err)
	return w
}

// Review P1-1: the recovery of a committed rebinding primary J reinstalls exactly K (the committee is unchanged, only the EVM set moves
// back from J to K) and is admitted; a recovery that is not exactly K stays refused.
func TestTheRecoveryOfARebindingPrimaryReinstallsK(t *testing.T) {
	w := rebindingPrimaryWorld(t)
	rec, rsucc := w.recovery(t)
	require.NoError(t, VerifyLifecycle(rec, w.ctx(1, 0, true)))
	require.True(t, RecoversK(rec, rsucc))
	require.NoError(t, VerifyInstalled(rec, rsucc, w.installed, w.kRoot))

	t.Run("a recovery whose bindings swap K's delegates", func(t *testing.T) {
		bad := rec
		bad.Bindings = append([]Binding(nil), rec.Bindings...)
		bad.Bindings[0].EVMNodeID, bad.Bindings[1].EVMNodeID = bad.Bindings[1].EVMNodeID, bad.Bindings[0].EVMNodeID
		require.False(t, RecoversK(bad, rsucc))
		require.ErrorIs(t, VerifyInstalled(bad, rsucc, w.installed, w.kRoot), ErrEVMOnly)
	})
	t.Run("a recovery whose EVM set is not K's", func(t *testing.T) {
		other := clonePDR(t, rsucc)
		other.Validators[0].SigKey = newKey(t, other.Validators[0].NodeID).info.SigKey
		require.False(t, RecoversK(rec, other))
	})
	t.Run("a recovery whose identities are not K", func(t *testing.T) {
		bad := rec
		bad.Identities = append([]Identity(nil), rec.Identities...)
		bad.Identities[0].OperatorPayee = append([]byte(nil), bad.Identities[0].OperatorPayee...)
		bad.Identities[0].OperatorPayee[0] ^= 1
		require.False(t, RecoversK(bad, rsucc))
		require.ErrorIs(t, VerifyInstalled(bad, rsucc, w.installed, w.kRoot), ErrEVMOnly)
	})
	t.Run("a primary is never a recovery", func(t *testing.T) {
		p := rec
		p.Kind = KindPrimary
		require.False(t, RecoversK(p, rsucc))
	})
}
