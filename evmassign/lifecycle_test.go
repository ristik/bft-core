package evmassign

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/continuity"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

// lifecycleWorld is a four-member incumbent committee K (root r1..r4, EVM a..d), a primary J that replaces r4 by r5 (EVM e) and the
// recovery of J: both boundaries are inside the continuity policy below.
type lifecycleWorld struct {
	keys     map[string]keyed
	current  *types.PartitionDescriptionRecord // installed, bound to K
	k        []Identity
	kRoot    []RootMember
	baseHash [32]byte
	body     [32]byte // the predecessor root body of J
	policy   continuity.Policy

	jRoot     []RootMember
	jBindings []Binding
	jIDs      []Identity
	jSucc     *types.PartitionDescriptionRecord
	auth      *Authorization
	j         Candidate
	installed *types.PartitionDescriptionRecord // J activated
}

func bind(r, e string) Binding { return Binding{RootNodeID: r, EVMNodeID: e} }

var testPolicy = continuity.Policy{MaxM: 4, MaxDistNum: 1, MaxDistDen: 2}

func newLifecycleWorld(t *testing.T) *lifecycleWorld { return newLifecycleWorldWith(t, newKey) }

// fixedKeyed is a deterministic keyed validator (RFC 6979 signatures are reproducible), for the cross-language vectors.
func fixedKeyed(first byte) func(t *testing.T, id string) keyed {
	seed := first - 1
	return func(t *testing.T, id string) keyed {
		t.Helper()
		seed++
		s, err := abcrypto.NewInMemorySecp256K1SignerFromKey(bytes.Repeat([]byte{seed}, 32))
		require.NoError(t, err)
		v, err := s.Verifier()
		require.NoError(t, err)
		pub, err := v.MarshalPublicKey()
		require.NoError(t, err)
		return keyed{id: id, signer: s, info: &types.NodeInfo{NodeID: id, SigKey: pub, Stake: 1}}
	}
}

// newLifecycleWorldWith builds the world with keys from mk (each call yields the key of one validator id, in a..e order).
func newLifecycleWorldWith(t *testing.T, mk func(t *testing.T, id string) keyed) *lifecycleWorld {
	t.Helper()
	w := &lifecycleWorld{keys: map[string]keyed{}, policy: testPolicy, body: [32]byte{1}}
	old := []keyed{mk(t, "a"), mk(t, "b"), mk(t, "c"), mk(t, "d")}
	infos := make([]*types.NodeInfo, len(old))
	for i, k := range old {
		infos[i] = k.info
	}
	cur := &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: 8, PartitionTypeID: 8,
		TypeIDLen: 8, UnitIDLen: 256, T2Timeout: 5 * time.Second, Epoch: 3, EpochStart: 11,
		PartitionParams: map[string]string{"seal_registry_genesis": "g", "chain": "1"}, Validators: infos}
	w.current = cur
	for _, k := range old {
		w.keys[k.id] = k
	}
	w.kRoot = []RootMember{{NodeID: "r1"}, {NodeID: "r2"}, {NodeID: "r3"}, {NodeID: "r4"}}
	for i := range w.kRoot {
		w.kRoot[i].Key, w.kRoot[i].Weight = bytes.Repeat([]byte{byte(10 + i)}, 33), 1
	}
	kb := []Binding{bind("r1", "a"), bind("r2", "b"), bind("r3", "c"), bind("r4", "d")}
	w.k = identitiesFor(w.kRoot, cur, kb, "")
	w.baseHash = mustAssignment(t, cur, w.k)
	w.auth = authFor(5, w.body[:], w.baseHash, w.k)

	// J: r5 (EVM e) takes r4's place.
	e := mk(t, "e")
	w.keys["e"] = e
	w.jRoot = append(append([]RootMember(nil), w.kRoot[:3]...), RootMember{NodeID: "r5", Key: bytes.Repeat([]byte{20}, 33), Weight: 1})
	w.jBindings = []Binding{bind("r1", "a"), bind("r2", "b"), bind("r3", "c"), bind("r5", "e")}
	succ, err := NewSuccessor(cur, []*types.NodeInfo{old[0].info, old[1].info, old[2].info, e.info})
	require.NoError(t, err)
	w.jSucc = succ
	w.jIDs = identitiesFor(w.jRoot, succ, w.jBindings, "")
	w.j = w.primary(t, w.jIDs, w.jRoot, w.jBindings, succ, w.auth, 0)
	w.installed, err = Activate(succ, 40)
	require.NoError(t, err)
	return w
}

func mustAssignment(t *testing.T, succ *types.PartitionDescriptionRecord, ids []Identity) [32]byte {
	t.Helper()
	h, err := AssignmentHash(succ, mustDigest(t, ids))
	require.NoError(t, err)
	return h
}

// primary builds and signs a primary candidate whose proofs are by the keys of the world.
func (w *lifecycleWorld) primary(t *testing.T, ids []Identity, root []RootMember, bindings []Binding, succ *types.PartitionDescriptionRecord, auth *Authorization, attempt uint64) Candidate {
	t.Helper()
	ctx := PoPContext{Network: 5, Predecessor: w.body, Attempt: attempt, Identities: mustDigest(t, ids)}
	var pops []PoP
	for _, v := range succ.Validators {
		p, err := SignPoP(w.keys[v.NodeID].signer, ctx, succ, v.NodeID)
		require.NoError(t, err)
		pops = append(pops, p)
	}
	raw, err := types.Cbor.Marshal(succ)
	require.NoError(t, err)
	old, err := PDRHash(w.current)
	require.NoError(t, err)
	return Candidate{Version: CandidateVersion, Kind: KindPrimary, Network: 5, Predecessor: bytes.Clone(w.body[:]), Attempt: attempt, RootMembers: root,
		OldShardEpoch: w.current.Epoch, OldActiveHash: old[:], Assignment: raw, PoPs: pops, Bindings: bindings, Identities: ids, Authorization: auth}
}

// recovery derives the recovery of J and wraps it as the second candidate of the frozen parent.
func (w *lifecycleWorld) recovery(t *testing.T) (Candidate, *types.PartitionDescriptionRecord) {
	t.Helper()
	lc, succ, root, bindings, err := DeriveRecovery(Head{Candidate: w.j, Successor: w.jSucc}, w.installed)
	require.NoError(t, err)
	raw, err := types.Cbor.Marshal(succ)
	require.NoError(t, err)
	old, err := PDRHash(w.installed)
	require.NoError(t, err)
	next := [32]byte{2}
	return Candidate{Version: CandidateVersion, Kind: KindRecovery, Network: 5, Predecessor: next[:], Attempt: 1, RootMembers: root,
		OldShardEpoch: w.installed.Epoch, OldActiveHash: old[:], Assignment: raw, Bindings: bindings, Identities: lc.Identities,
		Authorization: lc.Authorization, ReplacedAssignment: lc.ReplacedAssignment,
		Supersedes: &Supersession{SupersededH: bytes.Repeat([]byte{9}, 32), BaseRootEpoch: 1, BaseShardEpoch: 0, BaseActiveHash: bytes.Repeat([]byte{8}, 32), ChainLen: 1, ChainCommitment: bytes.Repeat([]byte{7}, 32)}}, succ
}

func (w *lifecycleWorld) ctx(pending, recoveries int, head bool) LifecycleContext {
	c := LifecycleContext{Incumbent: w.k, IncumbentAssignment: w.baseHash, Policy: w.policy, Pending: pending, CommittedRecoveries: recoveries}
	if head {
		c.Head = &Head{Candidate: w.j, Successor: w.jSucc}
	}
	return c
}

func (w *lifecycleWorld) binding(c Candidate) BindingContext {
	d, err := c.Digest()
	if err != nil {
		panic(err)
	}
	return BindingContext{PoPContext: PoPContext{Network: 5, Predecessor: [32]byte(c.Predecessor), Attempt: c.Attempt}, SuccessorRoot: c.RootMembers, Digest: d[:]}
}

func TestLifecycleAcceptanceControls(t *testing.T) {
	w := newLifecycleWorld(t)
	// the primary J: statically valid, and valid over the incumbent
	raw, err := w.j.Encode()
	require.NoError(t, err)
	_, _, err = VerifyBinding(raw, w.binding(w.j))
	require.NoError(t, err)
	require.NoError(t, VerifyLifecycle(w.j, w.ctx(0, 0, false)))
	// the recovery K: derived from J alone, carries no fresh proofs, valid over J as head
	rc, succ := w.recovery(t)
	require.Empty(t, rc.PoPs, "no fresh proof is collected for the exact incumbent")
	raw, err = rc.Encode()
	require.NoError(t, err)
	_, _, err = VerifyBinding(raw, w.binding(rc))
	require.NoError(t, err, "missing fresh proofs alone is not a rejection of the recovery kind")
	require.NoError(t, VerifyLifecycle(rc, w.ctx(1, 0, true)))
	require.NoError(t, VerifyInstalled(rc, succ, w.installed, w.jRoot))
	// derivation is deterministic
	again, succ2 := w.recovery(t)
	a, _ := rc.Encode()
	b, _ := again.Encode()
	require.Equal(t, a, b)
	require.Equal(t, succ.Validators, succ2.Validators)
}

func TestIdentityRecordIsolatedMutations(t *testing.T) {
	w := newLifecycleWorld(t)
	require.NoError(t, ValidateIdentities(w.jIDs, w.jRoot, w.jSucc, w.jBindings))
	cases := []struct {
		name   string
		mutate func(ids []Identity)
	}{
		{"zero payee", func(ids []Identity) { ids[1].OperatorPayee = make([]byte, PayeeLen) }},
		{"short payee", func(ids []Identity) { ids[1].OperatorPayee = ids[1].OperatorPayee[:19] }},
		{"zero exposure digest", func(ids []Identity) { ids[1].ExposureDigest = make([]byte, DigestLen) }},
		{"short staking id", func(ids []Identity) { ids[1].StakingID = ids[1].StakingID[:31] }},
		{"zero weight", func(ids []Identity) { ids[1].Weight = 0 }},
		{"empty root node id", func(ids []Identity) { ids[1].RootNodeID = "" }},
		{"empty EVM node id", func(ids []Identity) { ids[1].EVMNodeID = "" }},
		{"short root key", func(ids []Identity) { ids[1].RootKey = ids[1].RootKey[:32] }},
		{"short EVM key", func(ids []Identity) { ids[1].EVMKey = ids[1].EVMKey[:32] }},
		{"short exposure digest", func(ids []Identity) { ids[1].ExposureDigest = ids[1].ExposureDigest[:31] }},
		{"unordered", func(ids []Identity) { ids[0], ids[1] = ids[1], ids[0] }},
		{"duplicate staking id", func(ids []Identity) { ids[1].StakingID = bytes.Clone(ids[0].StakingID) }},
		{"another root key", func(ids []Identity) { ids[1].RootKey = bytes.Repeat([]byte{99}, 33) }},
		{"another EVM key", func(ids []Identity) { ids[1].EVMKey = bytes.Repeat([]byte{99}, 33) }},
		{"another weight", func(ids []Identity) { ids[1].Weight = 2 }},
		{"unknown root node", func(ids []Identity) { ids[1].RootNodeID = "nobody" }},
		{"unknown EVM node", func(ids []Identity) { ids[1].EVMNodeID = "nobody" }},
		{"unbound pair", func(ids []Identity) { ids[0].EVMNodeID, ids[1].EVMNodeID = ids[1].EVMNodeID, ids[0].EVMNodeID }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ids := cloneIdentities(w.jIDs)
			tc.mutate(ids)
			require.ErrorIs(t, ValidateIdentities(ids, w.jRoot, w.jSucc, w.jBindings), ErrIdentity)
		})
	}
	t.Run("missing record", func(t *testing.T) {
		require.ErrorIs(t, ValidateIdentities(w.jIDs[:3], w.jRoot, w.jSucc, w.jBindings), ErrIdentity)
	})
}

func cloneIdentities(ids []Identity) []Identity {
	out := make([]Identity, len(ids))
	for i, x := range ids {
		x.StakingID, x.RootKey, x.EVMKey = bytes.Clone(x.StakingID), bytes.Clone(x.RootKey), bytes.Clone(x.EVMKey)
		x.OperatorPayee, x.ExposureDigest = bytes.Clone(x.OperatorPayee), bytes.Clone(x.ExposureDigest)
		out[i] = x
	}
	return out
}

// The operator payee is committed by the assignment hash, so the possession proofs authenticate it: a candidate whose payee was
// swapped after the proofs were signed fails them, and the payee alone changes the hash.
func TestOperatorPayeeIsBoundByTheAssignmentHashAndProofs(t *testing.T) {
	w := newLifecycleWorld(t)
	base := mustAssignment(t, w.jSucc, w.jIDs)
	swapped := cloneIdentities(w.jIDs)
	swapped[2].OperatorPayee = bytes.Repeat([]byte{0xEE}, PayeeLen)
	require.NotEqual(t, base, mustAssignment(t, w.jSucc, swapped), "a payee-only change moves the assignment hash")
	require.NotEqual(t, mustDigest(t, w.jIDs), mustDigest(t, swapped))
	exposure, _ := ExposureCommit(w.jIDs)
	exposure2, _ := ExposureCommit(swapped)
	require.NotEqual(t, exposure, exposure2, "and the authenticated exposure commitment")

	c := w.j
	c.Identities = swapped
	raw, err := c.Encode()
	require.NoError(t, err)
	_, _, err = VerifyBinding(raw, w.binding(c))
	require.ErrorIs(t, err, ErrPoP, "the proofs were signed over the original payee")
	// control: re-signing over the swapped payee verifies
	resigned := w.primary(t, swapped, w.jRoot, w.jBindings, w.jSucc, w.auth, 0)
	raw, err = resigned.Encode()
	require.NoError(t, err)
	_, _, err = VerifyBinding(raw, w.binding(resigned))
	require.NoError(t, err)
}

func TestAuthorizationIsBoundToTheCandidateNetwork(t *testing.T) {
	w := newLifecycleWorld(t)
	c := w.j
	c.Authorization = authFor(6, w.body[:], w.baseHash, w.k)
	require.ErrorIs(t, VerifyAuthorization(c), ErrAuthorization)
	require.NoError(t, VerifyAuthorization(w.j))
}

func TestKindShapeIsolatedMutations(t *testing.T) {
	w := newLifecycleWorld(t)
	rc, _ := w.recovery(t)
	cases := []struct {
		name string
		c    func() Candidate
	}{
		{"primary without proofs", func() Candidate { c := w.j; c.PoPs = nil; return c }},
		{"primary without authorization", func() Candidate { c := w.j; c.Authorization = nil; return c }},
		{"primary naming a replaced assignment", func() Candidate { c := w.j; c.ReplacedAssignment = bytes.Repeat([]byte{1}, 32); return c }},
		{"recovery with a fresh proof", func() Candidate { c := rc; c.PoPs = w.j.PoPs[:1]; return c }},
		{"recovery without a replaced assignment", func() Candidate { c := rc; c.ReplacedAssignment = nil; return c }},
		{"recovery without authorization", func() Candidate { c := rc; c.Authorization = nil; return c }},
		{"unknown kind", func() Candidate { c := w.j; c.Kind = 7; return c }},
		{"no kind", func() Candidate { c := w.j; c.Kind = 0; return c }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.c().Encode()
			require.ErrorIs(t, err, ErrKind)
			require.ErrorIs(t, err, ErrCandidate)
		})
	}
}

// A recovery that differs from K in any single field of any member is not the exact incumbent; each change is isolated and the
// authorization digest stays internally consistent, so only the exact-K rule can refuse it.
func TestRecoveryMustBeExactlyTheIncumbent(t *testing.T) {
	w := newLifecycleWorld(t)
	rc, _ := w.recovery(t)
	mutations := map[string]func(ids []Identity){
		"payee":      func(ids []Identity) { ids[0].OperatorPayee = bytes.Repeat([]byte{0xAB}, PayeeLen) },
		"exposure":   func(ids []Identity) { ids[0].ExposureDigest = bytes.Repeat([]byte{0xAB}, DigestLen) },
		"weight":     func(ids []Identity) { ids[0].Weight = 2 },
		"root key":   func(ids []Identity) { ids[0].RootKey = bytes.Repeat([]byte{0xAB}, 33) },
		"EVM key":    func(ids []Identity) { ids[0].EVMKey = bytes.Repeat([]byte{0xAB}, 33) },
		"generation": func(ids []Identity) { ids[0].Generation++ },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			c := rc
			c.Identities = cloneIdentities(rc.Identities)
			mutate(c.Identities)
			require.ErrorIs(t, VerifyAuthorization(c), ErrNotIncumbent)
		})
	}
	t.Run("changed K inside the authorization is not the incumbent either", func(t *testing.T) {
		// A self-consistent authorization over another committee: the digest and exposure commitment are recomputed, the primary J
		// never committed to it, and the incumbent differs.
		other := cloneIdentities(w.k)
		other[0].OperatorPayee = bytes.Repeat([]byte{0xAB}, PayeeLen)
		forged := authFor(5, w.body[:], w.baseHash, other)
		c := rc
		c.Authorization, c.Identities = forged, other
		require.NoError(t, VerifyAuthorization(c), "statically self-consistent")
		require.ErrorIs(t, VerifyLifecycle(c, w.ctx(1, 0, true)), ErrNotIncumbent)
	})
	t.Run("member removed", func(t *testing.T) {
		c := rc
		c.Identities = rc.Identities[:3]
		require.ErrorIs(t, VerifyAuthorization(c), ErrNotIncumbent)
	})
}

func TestVerifyLifecycleIsolatedRefusals(t *testing.T) {
	w := newLifecycleWorld(t)
	rc, _ := w.recovery(t)
	t.Run("primary: K is not the incumbent", func(t *testing.T) {
		ctx := w.ctx(0, 0, false)
		ctx.Incumbent = cloneIdentities(w.k)
		ctx.Incumbent[2].OperatorPayee = bytes.Repeat([]byte{0xAB}, PayeeLen)
		require.ErrorIs(t, VerifyLifecycle(w.j, ctx), ErrNotIncumbent)
	})
	t.Run("primary: base assignment differs", func(t *testing.T) {
		ctx := w.ctx(0, 0, false)
		ctx.IncumbentAssignment[0] ^= 1
		require.ErrorIs(t, VerifyLifecycle(w.j, ctx), ErrNotIncumbent)
	})
	t.Run("primary: K based on another root body", func(t *testing.T) {
		c := w.j
		forged := authFor(5, bytes.Repeat([]byte{0x55}, 32), w.baseHash, w.k)
		c.Authorization = forged
		require.ErrorIs(t, VerifyLifecycle(c, w.ctx(0, 0, false)), ErrAuthorization)
	})
	t.Run("primary over a pending primary", func(t *testing.T) {
		c := w.j
		c.Supersedes = rc.Supersedes
		require.ErrorIs(t, VerifyLifecycle(c, w.ctx(1, 0, true)), ErrPendingPrimary)
	})
	t.Run("primary claiming a supersession with nothing pending", func(t *testing.T) {
		c := w.j
		c.Supersedes = rc.Supersedes
		require.ErrorIs(t, VerifyLifecycle(c, w.ctx(0, 0, false)), ErrRecoveryLineage)
	})
	t.Run("a pending chain without a supersession", func(t *testing.T) {
		c := w.j
		require.ErrorIs(t, VerifyLifecycle(c, w.ctx(1, 0, true)), ErrRecoveryLineage)
	})
	t.Run("third transition", func(t *testing.T) {
		require.ErrorIs(t, VerifyLifecycle(rc, w.ctx(2, 0, true)), ErrSpan)
	})
	t.Run("second committed recovery", func(t *testing.T) {
		require.ErrorIs(t, VerifyLifecycle(rc, w.ctx(1, 1, true)), ErrRecoveryUsed)
	})
	t.Run("recovery without a committed primary", func(t *testing.T) {
		require.ErrorIs(t, VerifyLifecycle(rc, w.ctx(1, 0, false)), ErrRecoveryLineage)
	})
	t.Run("recovery over a recovery head", func(t *testing.T) {
		ctx := w.ctx(1, 0, true)
		head := *ctx.Head
		head.Candidate = rc
		ctx.Head = &head
		require.ErrorIs(t, VerifyLifecycle(rc, ctx), ErrRecoveryLineage)
	})
	t.Run("recovery whose chain is not exactly the primary", func(t *testing.T) {
		require.ErrorIs(t, VerifyLifecycle(rc, w.ctx(0, 0, true)), ErrRecoveryLineage)
	})
	t.Run("foreign authorization", func(t *testing.T) {
		c := rc
		other := *w.auth
		other.ResultID = bytes.Repeat([]byte{0x66}, 32)
		c.Authorization = &other
		require.ErrorIs(t, VerifyLifecycle(c, w.ctx(1, 0, true)), ErrAuthorization)
	})
	t.Run("recovery K based on another root body (wrong P lineage)", func(t *testing.T) {
		ctx := w.ctx(1, 0, true)
		head := *ctx.Head
		hc := head.Candidate
		hc.Predecessor = bytes.Repeat([]byte{0x44}, 32)
		head.Candidate = hc
		ctx.Head = &head
		require.ErrorIs(t, VerifyLifecycle(rc, ctx), ErrAuthorization)
	})
	t.Run("replaced assignment is not the committed primary's", func(t *testing.T) {
		c := rc
		c.ReplacedAssignment = bytes.Repeat([]byte{0x33}, 32)
		require.ErrorIs(t, VerifyLifecycle(c, w.ctx(1, 0, true)), ErrRecoveryLineage)
	})
	t.Run("recovery base assignment differs", func(t *testing.T) {
		ctx := w.ctx(1, 0, true)
		ctx.IncumbentAssignment[0] ^= 1
		require.ErrorIs(t, VerifyLifecycle(rc, ctx), ErrNotIncumbent)
	})
}

// Both boundaries carry the same predicates with their own predecessor and successor: O to J for a primary, J to K for a recovery.
func TestContinuityAtBothBoundaries(t *testing.T) {
	w := newLifecycleWorld(t)
	rc, _ := w.recovery(t)
	t.Run("O to J: membership budget", func(t *testing.T) {
		ctx := w.ctx(0, 0, false)
		ctx.Policy.MaxM = 1
		err := VerifyLifecycle(w.j, ctx)
		require.ErrorIs(t, err, ErrContinuity)
		require.ErrorIs(t, err, continuity.ErrMembership)
		require.NotErrorIs(t, err, continuity.ErrTurnover)
	})
	t.Run("J to K: membership budget", func(t *testing.T) {
		ctx := w.ctx(1, 0, true)
		ctx.Policy.MaxM = 1
		err := VerifyLifecycle(rc, ctx)
		require.ErrorIs(t, err, ErrContinuity)
		require.ErrorIs(t, err, continuity.ErrMembership)
	})
	t.Run("O to J: weight distance", func(t *testing.T) {
		ctx := w.ctx(0, 0, false)
		ctx.Policy = continuity.Policy{MaxM: 4, MaxDistNum: 1, MaxDistDen: 4}
		err := VerifyLifecycle(w.j, ctx)
		require.ErrorIs(t, err, continuity.ErrWeightDistance)
		require.NotErrorIs(t, err, continuity.ErrMembership)
	})
	t.Run("J to K: weight distance", func(t *testing.T) {
		ctx := w.ctx(1, 0, true)
		ctx.Policy = continuity.Policy{MaxM: 4, MaxDistNum: 1, MaxDistDen: 4}
		require.ErrorIs(t, VerifyLifecycle(rc, ctx), continuity.ErrWeightDistance)
	})
	t.Run("a same-identity binding replacement counts once", func(t *testing.T) {
		// r3 keeps its identity but changes both its root key and its EVM node: r=1, removed=added=1, M=2, whatever the number of
		// changed fields.
		ids := cloneIdentities(w.k)
		for i := range ids {
			if ids[i].RootNodeID == "r3" {
				ids[i].RootKey, ids[i].EVMKey = bytes.Repeat([]byte{0x77}, 33), bytes.Repeat([]byte{0x78}, 33)
			}
		}
		r, err := continuity.Check(Members(w.k), Members(ids), testPolicy)
		require.NoError(t, err)
		require.Equal(t, [4]uint64{1, 1, 1, 2}, [4]uint64{r.Replaced, r.Removed, r.Added, r.M})
	})
	t.Run("a payee change alone is not a binding replacement", func(t *testing.T) {
		moved := cloneIdentities(w.k)
		moved[0].OperatorPayee = bytes.Repeat([]byte{0xCD}, PayeeLen)
		r, err := continuity.Check(Members(w.k), Members(moved), continuity.Policy{MaxM: 0, MaxDistNum: 0, MaxDistDen: 1})
		require.NoError(t, err)
		require.Zero(t, r.Replaced)
	})
}

// Staking-id order is the opposite of both node-id orders: the three arrays are matched by identifier, never positionally.
func TestArrayOrdersAreIndependent(t *testing.T) {
	w := newLifecycleWorld(t)
	// give the records staking ids that sort opposite to the root node ids
	ids := cloneIdentities(w.jIDs)
	sort.Slice(ids, func(a, b int) bool { return ids[a].RootNodeID > ids[b].RootNodeID })
	for i := range ids {
		sid := sha256.Sum256([]byte(fmt.Sprintf("order-%d", i)))
		ids[i].StakingID = sid[:]
	}
	sort.Slice(ids, func(a, b int) bool { return bytes.Compare(ids[a].StakingID, ids[b].StakingID) < 0 })
	require.NoError(t, ValidateIdentities(ids, w.jRoot, w.jSucc, w.jBindings))
	h1 := mustAssignment(t, w.jSucc, ids)
	// the same inputs presented to the verifier in another array order give the same hash and the same verdict
	root := append([]RootMember(nil), w.jRoot...)
	root[0], root[3] = root[3], root[0]
	bindings := append([]Binding(nil), w.jBindings...)
	bindings[1], bindings[2] = bindings[2], bindings[1]
	_ = bindings
	require.NoError(t, ValidateIdentities(ids, root, w.jSucc, w.jBindings), "root members are looked up by node id")
	require.Equal(t, h1, mustAssignment(t, w.jSucc, ids))
	// control: a misplaced binding (positional zip would pair r1 with b) is refused
	zipped := append([]Binding(nil), w.jBindings...)
	zipped[0].EVMNodeID, zipped[1].EVMNodeID = zipped[1].EVMNodeID, zipped[0].EVMNodeID
	require.ErrorIs(t, ValidateIdentities(ids, w.jRoot, w.jSucc, zipped), ErrIdentity)
	// and a proof placed at another validator's slot fails
	pops := append([]PoP(nil), w.j.PoPs...)
	pops[0], pops[1] = pops[1], pops[0]
	require.ErrorIs(t, VerifyPoPs(PoPContext{Network: 5, Predecessor: w.body, Identities: mustDigest(t, w.jIDs)}, w.jSucc, pops), ErrPoP)
}

// A changed-key primary still needs every fresh proof; only the recovery kind is exempt, and only for exactly K.
func TestPrimaryStillNeedsEveryFreshProof(t *testing.T) {
	w := newLifecycleWorld(t)
	c := w.j
	c.PoPs = c.PoPs[:3]
	raw, err := c.Encode()
	require.NoError(t, err)
	_, _, err = VerifyBinding(raw, w.binding(c))
	require.ErrorIs(t, err, ErrPoP)
	// a primary may not claim the recovery kind to skip proofs while changing a key: the shape refuses it
	c = w.j
	c.Kind, c.PoPs, c.ReplacedAssignment = KindRecovery, nil, bytes.Repeat([]byte{1}, 32)
	raw, err = c.Encode()
	require.NoError(t, err)
	_, _, err = VerifyBinding(raw, w.binding(c))
	require.ErrorIs(t, err, ErrNotIncumbent, "a recovery-kind candidate whose committee is not K is not exempt")
}

func TestRootAndEVMKeysStayDistinctInIdentityRecords(t *testing.T) {
	w := newLifecycleWorld(t)
	root := append([]RootMember(nil), w.jRoot...)
	root[0].Key = bytes.Clone(w.jSucc.Validators[0].SigKey) // a root key equal to an EVM key
	ids := identitiesFor(root, w.jSucc, w.jBindings, "")
	require.ErrorIs(t, ValidateCoupling(root, w.jSucc, w.jBindings), ErrCoupling)
	_ = ids
}

// The provenance index entry re-verifies the committed candidate it carries: every field is isolated against an accepted control.
func TestProvenanceIsolatedRefusals(t *testing.T) {
	w := newLifecycleWorld(t)
	raw, err := w.j.Encode()
	require.NoError(t, err)
	digest := sha256.Sum256(raw)
	good := Provenance{RecordID: bytes.Repeat([]byte{1}, 32), CandidateDigest: digest[:], RootEpoch: 2, Kind: KindPrimary, Preimage: raw}
	enc, err := good.Bytes()
	require.NoError(t, err)
	back, err := DecodeProvenance(enc)
	require.NoError(t, err)
	require.Equal(t, good, back)
	cases := map[string]func(p *Provenance){
		"short record id":        func(p *Provenance) { p.RecordID = p.RecordID[:31] },
		"short candidate digest": func(p *Provenance) { p.CandidateDigest = p.CandidateDigest[:31] },
		"root epoch below two":   func(p *Provenance) { p.RootEpoch = 1 },
		"digest of another preimage": func(p *Provenance) {
			d := sha256.Sum256([]byte("other"))
			p.CandidateDigest = d[:]
		},
		"kind that is not the candidate's": func(p *Provenance) { p.Kind = KindRecovery },
		"preimage that is not a candidate": func(p *Provenance) {
			p.Preimage = []byte{1, 2, 3}
			d := sha256.Sum256(p.Preimage)
			p.CandidateDigest = d[:]
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := good
			p.RecordID, p.CandidateDigest = bytes.Clone(good.RecordID), bytes.Clone(good.CandidateDigest)
			mutate(&p)
			_, err := p.Bytes()
			require.ErrorIs(t, err, ErrContext)
		})
	}
}

func TestAuthorizationIsolatedRefusals(t *testing.T) {
	w := newLifecycleWorld(t)
	_, err := w.auth.Digest()
	require.NoError(t, err)
	withK := func(mutate func(k []Identity)) *Authorization {
		k := cloneIdentities(w.k)
		mutate(k)
		return authFor(5, w.body[:], w.baseHash, k) // the exposure commitment follows K, so only the K rule can refuse
	}
	cases := map[string]*Authorization{
		"duplicate staking id": withK(func(k []Identity) { k[1].StakingID = bytes.Clone(k[0].StakingID) }),
		"unordered":            withK(func(k []Identity) { k[0], k[1] = k[1], k[0] }),
		"malformed member":     withK(func(k []Identity) { k[0].OperatorPayee = nil }),
		"empty K":              authFor(5, w.body[:], w.baseHash, nil),
	}
	for _, field := range []string{"contracts", "result", "snapshot", "base body", "base assignment", "exposure", "policies"} {
		a := *w.auth
		a.K = w.auth.K
		switch field {
		case "contracts":
			a.Contracts = a.Contracts[:31]
		case "result":
			a.ResultID = make([]byte, 32)
		case "snapshot":
			a.SnapshotDigest = nil
		case "base body":
			a.BaseRootBodyID = make([]byte, 32)
		case "base assignment":
			a.BaseAssignmentHash = a.BaseAssignmentHash[:1]
		case "exposure":
			a.ExposureDigest = bytes.Repeat([]byte{1}, 32) // a width-valid digest that is not ExposureCommit(K)
		case "policies":
			a.Policies = make([]byte, 32)
		}
		cases[field] = &a
	}
	for name, a := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := a.Digest()
			require.ErrorIs(t, err, ErrAuthorization)
		})
	}
}
