package evmassign

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

type keyed struct {
	id     string
	signer abcrypto.Signer
	info   *types.NodeInfo
}

func newKey(t *testing.T, id string) keyed {
	t.Helper()
	s, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	v, err := s.Verifier()
	require.NoError(t, err)
	pub, err := v.MarshalPublicKey()
	require.NoError(t, err)
	return keyed{id: id, signer: s, info: &types.NodeInfo{NodeID: id, SigKey: pub, Stake: 1}}
}

func currentPDR(t *testing.T) (*types.PartitionDescriptionRecord, []keyed) {
	t.Helper()
	old := []keyed{newKey(t, "a"), newKey(t, "b"), newKey(t, "c"), newKey(t, "d")}
	infos := make([]*types.NodeInfo, len(old))
	for i, k := range old {
		infos[i] = k.info
	}
	return &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: 8, PartitionTypeID: 8,
		TypeIDLen: 8, UnitIDLen: 256, T2Timeout: 5 * time.Second, Epoch: 3, EpochStart: 11,
		PartitionParams: map[string]string{"seal_registry_genesis": "g", "chain": "1"}, Validators: infos}, old
}

type fixture struct {
	current *types.PartitionDescriptionRecord
	next    []keyed
	succ    *types.PartitionDescriptionRecord
	ctx     PoPContext
	root    []RootMember
	// oldRoot is the committee being replaced: a different committee, so the fixture's change is a coupled one.
	oldRoot  []RootMember
	bindings []Binding
	ids      []Identity
	auth     *Authorization
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	cur, old := currentPDR(t)
	// One retained key and three new ones: retained keys must prove possession too.
	next := []keyed{old[0], newKey(t, "e"), newKey(t, "f"), newKey(t, "g")}
	infos := make([]*types.NodeInfo, len(next))
	for i, k := range next {
		infos[i] = k.info
	}
	succ, err := NewSuccessor(cur, infos)
	require.NoError(t, err)
	root, oldRoot := rootOf("r", 2), rootOf("o", 9)
	bindings := bindingsFor(root, succ)
	ids := identitiesFor(root, succ, bindings, "")
	// K is the incumbent committee: root members o1..o4 bound to the installed validators a..d
	incumbent := identitiesFor(oldRoot, cur, bindingsFor(oldRoot, cur), "")
	baseHash, err := AssignmentHash(cur, mustDigest(t, incumbent))
	require.NoError(t, err)
	digest := mustDigest(t, ids)
	return fixture{current: cur, next: next, succ: succ,
		ctx:  PoPContext{Network: 5, Predecessor: [32]byte{1}, Attempt: 2, Identities: digest},
		root: root, oldRoot: oldRoot, bindings: bindings, ids: ids, auth: authFor(5, bytes.Clone(append([]byte{1}, make([]byte, 31)...)), baseHash, incumbent)}
}

func mustDigest(t *testing.T, ids []Identity) [32]byte {
	t.Helper()
	d, err := IdentitiesDigest(ids)
	require.NoError(t, err)
	return d
}

// identitiesFor builds one record per binding, found by node id; payee, exposure and staking id derive from the root node id.
func identitiesFor(root []RootMember, succ *types.PartitionDescriptionRecord, bindings []Binding, payeeTag string) []Identity {
	byRoot := map[string]RootMember{}
	for _, m := range root {
		byRoot[m.NodeID] = m
	}
	byEVM := map[string]*types.NodeInfo{}
	for _, v := range succ.Validators {
		byEVM[v.NodeID] = v
	}
	sum := func(tag, id string) [32]byte { return sha256.Sum256([]byte(tag + "/" + id)) }
	out := make([]Identity, 0, len(bindings))
	for _, b := range bindings {
		m, v := byRoot[b.RootNodeID], byEVM[b.EVMNodeID]
		sid, payee, exp := sum("staking", b.RootNodeID), sum("payee"+payeeTag, b.RootNodeID), sum("exposure", b.RootNodeID)
		out = append(out, Identity{StakingID: sid[:], Generation: 1, RootNodeID: m.NodeID, RootKey: bytes.Clone(m.Key), EVMNodeID: v.NodeID,
			EVMKey: bytes.Clone(v.SigKey), Weight: m.Weight, RawWeight: m.Weight, OperatorPayee: payee[:20], ExposureDigest: exp[:]})
	}
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i].StakingID, out[j].StakingID) < 0 })
	return out
}

func authFor(network uint64, baseBody []byte, baseAssignment [32]byte, k []Identity) *Authorization {
	exposure, _ := ExposureCommit(k)
	h := func(tag string) []byte { s := sha256.Sum256([]byte(tag)); return s[:] }
	return &Authorization{Network: network, Chain: 1, Contracts: h("contracts"), ResultID: h("result"), SnapshotDigest: h("snapshot"),
		BaseRootBodyID: bytes.Clone(baseBody), BaseAssignmentHash: baseAssignment[:], K: k, ExposureDigest: exposure[:], Policies: h("policies")}
}

// rootOf is a four-member root committee; the EVM set of the fixture is the delegated image of it.
func rootOf(prefix string, seed byte) []RootMember {
	out := make([]RootMember, 4)
	for i := range out {
		out[i] = RootMember{NodeID: fmt.Sprintf("%s%d", prefix, i+1), Key: bytes.Repeat([]byte{seed + byte(i)}, 33), Weight: 1}
	}
	return out
}

// bindingsFor pairs the sorted root members with the successor validators in order.
func bindingsFor(root []RootMember, succ *types.PartitionDescriptionRecord) []Binding {
	out := make([]Binding, len(root))
	for i, m := range root {
		out[i] = Binding{RootNodeID: m.NodeID, EVMNodeID: succ.Validators[i].NodeID}
	}
	return out
}

func (f fixture) pops(t *testing.T) []PoP {
	t.Helper()
	out := make([]PoP, 0, len(f.succ.Validators))
	for _, v := range f.succ.Validators {
		for _, k := range f.next {
			if k.id == v.NodeID {
				p, err := SignPoP(k.signer, f.ctx, f.succ, k.id)
				require.NoError(t, err)
				out = append(out, p)
			}
		}
	}
	require.Len(t, out, len(f.succ.Validators))
	return out
}

func (f fixture) verifyCtx(c Candidate) VerifyContext {
	d, _ := c.Digest()
	return VerifyContext{BindingContext: BindingContext{PoPContext: f.ctx, SuccessorRoot: f.root, Digest: d[:]}, Current: f.current, CurrentRoot: f.oldRoot}
}

func (f fixture) candidate(t *testing.T) Candidate {
	t.Helper()
	c, err := NewCandidate(f.ctx, f.root, f.current, f.succ, f.pops(t), nil, f.bindings,
		Lifecycle{Kind: KindPrimary, Identities: f.ids, Authorization: f.auth}, nil)
	require.NoError(t, err)
	return c
}

func clonePDR(t *testing.T, p *types.PartitionDescriptionRecord) *types.PartitionDescriptionRecord {
	t.Helper()
	raw, err := types.Cbor.Marshal(p)
	require.NoError(t, err)
	var out types.PartitionDescriptionRecord
	require.NoError(t, types.Cbor.Unmarshal(raw, &out))
	return &out
}

func TestAssignmentHashBindsEachFieldIndependently(t *testing.T) {
	f := newFixture(t)
	base, err := AssignmentHash(f.succ, f.ctx.Identities)
	require.NoError(t, err)
	mutations := map[string]func(p *types.PartitionDescriptionRecord){
		"network":       func(p *types.PartitionDescriptionRecord) { p.NetworkID++ },
		"partition":     func(p *types.PartitionDescriptionRecord) { p.PartitionID++ },
		"shard":         func(p *types.PartitionDescriptionRecord) { p.ShardID, _ = (types.ShardID{}).Split() },
		"epoch":         func(p *types.PartitionDescriptionRecord) { p.Epoch++ },
		"validator id":  func(p *types.PartitionDescriptionRecord) { p.Validators[1].NodeID = "zz" },
		"validator key": func(p *types.PartitionDescriptionRecord) { p.Validators[1].SigKey = f.current.Validators[1].SigKey },
		"validator order": func(p *types.PartitionDescriptionRecord) {
			p.Validators[0], p.Validators[1] = p.Validators[1], p.Validators[0]
		},
		"validator count": func(p *types.PartitionDescriptionRecord) { p.Validators = p.Validators[:3] },
		"weight":          func(p *types.PartitionDescriptionRecord) { p.Validators[2].Stake = 2 },
		"config param":    func(p *types.PartitionDescriptionRecord) { p.PartitionParams["chain"] = "2" },
		"genesis param":   func(p *types.PartitionDescriptionRecord) { p.PartitionParams["seal_registry_genesis"] = "h" },
		"t2":              func(p *types.PartitionDescriptionRecord) { p.T2Timeout += time.Second },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			p := clonePDR(t, f.succ)
			mutate(p)
			h, err := AssignmentHash(p, f.ctx.Identities)
			require.NoError(t, err)
			require.NotEqual(t, base, h)
		})
	}
	// The activation round is not part of the assignment: it is fixed by the commit.
	p := clonePDR(t, f.succ)
	p.EpochStart = 99
	h, err := AssignmentHash(p, f.ctx.Identities)
	require.NoError(t, err)
	require.Equal(t, base, h)
}

func TestValidateSuccessorIsolatedMutations(t *testing.T) {
	f := newFixture(t)
	require.NoError(t, ValidateSuccessor(f.current, f.succ))
	cases := []struct {
		name   string
		mutate func(p *types.PartitionDescriptionRecord)
		want   error
	}{
		{"epoch repeats", func(p *types.PartitionDescriptionRecord) { p.Epoch = f.current.Epoch }, ErrEpoch},
		{"epoch skips", func(p *types.PartitionDescriptionRecord) { p.Epoch += 1 }, ErrEpoch},
		{"activation preset", func(p *types.PartitionDescriptionRecord) { p.EpochStart = 4 }, ErrEpoch},
		{"fee or execution setting", func(p *types.PartitionDescriptionRecord) { p.PartitionParams["chain"] = "7" }, ErrConfig},
		{"genesis commitment", func(p *types.PartitionDescriptionRecord) { p.PartitionParams["seal_registry_genesis"] = "x" }, ErrConfig},
		{"t2 timeout", func(p *types.PartitionDescriptionRecord) { p.T2Timeout = 9 * time.Second }, ErrConfig},
		{"unit id length", func(p *types.PartitionDescriptionRecord) { p.UnitIDLen = 128 }, ErrConfig},
		{"non unit weight", func(p *types.PartitionDescriptionRecord) { p.Validators[0].Stake = 2 }, ErrAssignment},
		{"unordered", func(p *types.PartitionDescriptionRecord) {
			p.Validators[0], p.Validators[1] = p.Validators[1], p.Validators[0]
		}, ErrValidators},
		{"duplicate key", func(p *types.PartitionDescriptionRecord) {
			p.Validators[2].SigKey = bytes.Clone(p.Validators[1].SigKey)
		}, ErrValidators},
		{"duplicate id", func(p *types.PartitionDescriptionRecord) { p.Validators[2].NodeID = p.Validators[1].NodeID }, ErrAssignment},
		{"empty set", func(p *types.PartitionDescriptionRecord) { p.Validators = nil }, ErrValidators},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := clonePDR(t, f.succ)
			tc.mutate(p)
			require.ErrorIs(t, ValidateSuccessor(f.current, p), tc.want)
		})
	}
	t.Run("set size bound", func(t *testing.T) {
		infos := make([]*types.NodeInfo, 0, MaxValidators+1)
		for i := 0; i <= MaxValidators; i++ {
			infos = append(infos, newKey(t, fmt.Sprintf("v%03d", i)).info)
		}
		require.ErrorIs(t, ValidateSet(infos), ErrValidators)
		require.NoError(t, ValidateSet(infos[:MaxValidators]))
	})
	t.Run("short key", func(t *testing.T) {
		infos := []*types.NodeInfo{{NodeID: "a", SigKey: []byte{2, 3}, Stake: 1}}
		require.ErrorIs(t, ValidateSet(infos), ErrValidators)
	})
}

func TestPoPIsolatedMutations(t *testing.T) {
	f := newFixture(t)
	good := f.pops(t)
	require.NoError(t, VerifyPoPs(f.ctx, f.succ, good))

	other := newKey(t, "x")
	signFor := func(idx int, ctx PoPContext, succ *types.PartitionDescriptionRecord, signer abcrypto.Signer) PoP {
		p, err := SignPoP(signer, ctx, succ, f.succ.Validators[idx].NodeID)
		require.NoError(t, err)
		p.Key = bytes.Clone(f.succ.Validators[idx].SigKey)
		return p
	}
	withIndex := func(idx int, p PoP) []PoP {
		out := append([]PoP(nil), good...)
		out[idx] = p
		return out
	}
	cases := []struct {
		name string
		pops []PoP
	}{
		{"missing proof", good[:len(good)-1]},
		{"no proofs", nil},
		{"extra proof", append(append([]PoP(nil), good...), good[0])},
		{"wrong key signs", withIndex(1, signFor(1, f.ctx, f.succ, other.signer))},
		{"retained key exempt-by-omission", withIndex(0, PoP{NodeID: good[0].NodeID, Key: good[0].Key, Signature: make([]byte, 65)})},
		{"wrong network", withIndex(1, signFor(1, PoPContext{Network: 6, Predecessor: f.ctx.Predecessor, Attempt: f.ctx.Attempt}, f.succ, f.next[1].signer))},
		{"wrong predecessor", withIndex(1, signFor(1, PoPContext{Network: 5, Predecessor: [32]byte{2}, Attempt: f.ctx.Attempt}, f.succ, f.next[1].signer))},
		{"replayed attempt", withIndex(1, signFor(1, PoPContext{Network: 5, Predecessor: f.ctx.Predecessor, Attempt: 1}, f.succ, f.next[1].signer))},
		{"reordered", func() []PoP { o := append([]PoP(nil), good...); o[1], o[2] = o[2], o[1]; return o }()},
		{"other node id", func() []PoP { p := good[1]; p.NodeID = "zz"; return withIndex(1, p) }()},
		{"short signature", func() []PoP { p := good[1]; p.Signature = p.Signature[:64]; return withIndex(1, p) }()},
		{"flipped recovery byte", func() []PoP {
			p := good[1]
			p.Signature = bytes.Clone(p.Signature)
			p.Signature[64] ^= 1
			return withIndex(1, p)
		}()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.ErrorIs(t, VerifyPoPs(f.ctx, f.succ, tc.pops), ErrPoP)
		})
	}
	t.Run("signed for another assignment", func(t *testing.T) {
		alt := clonePDR(t, f.succ)
		alt.Validators = alt.Validators[:3]
		p, err := SignPoP(f.next[1].signer, f.ctx, alt, "e")
		require.NoError(t, err)
		require.ErrorIs(t, VerifyPoPs(f.ctx, f.succ, withIndex(1, p)), ErrPoP)
	})
}

func TestCandidateRoundTripAndCanonical(t *testing.T) {
	f := newFixture(t)
	c := f.candidate(t)
	raw, err := c.Encode()
	require.NoError(t, err)
	d1, err := c.Digest()
	require.NoError(t, err)
	require.Equal(t, sha256.Sum256(raw), d1)
	got, succ, err := Verify(raw, f.verifyCtx(c))
	require.NoError(t, err)
	require.Equal(t, c.OldShardEpoch, got.OldShardEpoch)
	require.EqualValues(t, f.current.Epoch+1, succ.Epoch)

	for name, mutate := range map[string]func([]byte) []byte{
		"trailing byte": func(b []byte) []byte { return append(bytes.Clone(b), 0) },
		"truncated":     func(b []byte) []byte { return bytes.Clone(b[:len(b)-1]) },
		"empty":         func([]byte) []byte { return nil },
		"oversized":     func([]byte) []byte { return make([]byte, MaxCandidateBytes+1) },
	} {
		t.Run(name, func(t *testing.T) {
			_, err := DecodeCandidate(mutate(raw))
			require.ErrorIs(t, err, ErrCandidate)
		})
	}
}

func TestCandidateVerifyContextIsolatedMutations(t *testing.T) {
	f := newFixture(t)
	c := f.candidate(t)
	raw, err := c.Encode()
	require.NoError(t, err)
	digest := func(b []byte) []byte { d := sha256.Sum256(b); return d[:] }

	rebuild := func(mutate func(c *Candidate)) ([]byte, VerifyContext) {
		m := c
		m.RootMembers = append([]RootMember(nil), c.RootMembers...)
		mutate(&m)
		b, err := m.Encode()
		require.NoError(t, err)
		v := f.verifyCtx(m)
		v.Digest = digest(b)
		return b, v
	}
	cases := []struct {
		name   string
		mutate func(c *Candidate)
		ctx    func(v *VerifyContext)
		want   error
		reason string
	}{
		{"network", func(c *Candidate) { c.Network = 6 }, nil, ErrContext, "network"},
		{"predecessor", func(c *Candidate) { c.Predecessor = bytes.Repeat([]byte{7}, 32) }, nil, ErrContext, "predecessor"},
		{"attempt", func(c *Candidate) { c.Attempt++ }, nil, ErrContext, "attempt"},
		{"old shard epoch", func(c *Candidate) { c.OldShardEpoch++ }, nil, ErrContext, "installed assignment epoch"},
		{"old active hash", func(c *Candidate) { c.OldActiveHash = bytes.Repeat([]byte{7}, 32) }, nil, ErrContext, "installed assignment hash"},
		{"root members differ from body", func(c *Candidate) { c.RootMembers[0].NodeID = "r9" }, nil, ErrContext, "successor root members"},
		{"supersession shape", func(c *Candidate) {
			c.Supersedes = &Supersession{SupersededH: make([]byte, 31)}
		}, nil, ErrContext, "supersession shape"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, v := raw, f.verifyCtx(c)
			if tc.mutate != nil {
				b, v = rebuild(tc.mutate)
			}
			if tc.ctx != nil {
				tc.ctx(&v)
			}
			_, _, err := Verify(b, v)
			require.ErrorIs(t, err, tc.want)
			require.ErrorContains(t, err, tc.reason)
		})
	}
	t.Run("digest mismatch", func(t *testing.T) {
		v := f.verifyCtx(c)
		v.Digest = bytes.Repeat([]byte{1}, 32)
		_, _, err := Verify(raw, v)
		require.ErrorIs(t, err, ErrContext)
		require.ErrorContains(t, err, "candidate digest")
	})
	t.Run("a coupled committee change verifies", func(t *testing.T) {
		_, _, err := Verify(raw, f.verifyCtx(c))
		require.NoError(t, err)
	})
	t.Run("a root member without its EVM binding is refused", func(t *testing.T) {
		grown := append(append([]RootMember(nil), f.root...), RootMember{NodeID: "r5", Key: bytes.Repeat([]byte{9}, 33), Weight: 1})
		b, v := rebuild(func(c *Candidate) { c.RootMembers = grown })
		v.SuccessorRoot = grown
		_, _, err := Verify(b, v)
		require.ErrorIs(t, err, ErrCoupling)
	})
	t.Run("coupling is one-to-one, equal weight and distinct keys", func(t *testing.T) {
		for name, mutate := range map[string]func(c *Candidate){
			"missing binding":   func(c *Candidate) { c.Bindings = c.Bindings[:3] },
			"duplicate evm id":  func(c *Candidate) { c.Bindings[1].EVMNodeID = c.Bindings[0].EVMNodeID },
			"unknown evm id":    func(c *Candidate) { c.Bindings[0].EVMNodeID = "nobody" },
			"unknown root id":   func(c *Candidate) { c.Bindings[0].RootNodeID = "r0" },
			"unsorted bindings": func(c *Candidate) { c.Bindings[0], c.Bindings[1] = c.Bindings[1], c.Bindings[0] },
			"shared key":        func(c *Candidate) { c.RootMembers[0].Key = f.succ.Validators[0].SigKey },
			"weight differs":    func(c *Candidate) { c.RootMembers[0].Weight = 2 },
		} {
			t.Run(name, func(t *testing.T) {
				b, v := rebuild(func(c *Candidate) { c.Bindings = append([]Binding(nil), c.Bindings...); mutate(c) })
				v.SuccessorRoot = nil
				d := sha256.Sum256(b)
				dec, _ := DecodeCandidate(b)
				v.SuccessorRoot = dec.RootMembers
				v.Digest = d[:]
				_, _, err := Verify(b, v)
				require.ErrorIs(t, err, ErrCoupling)
			})
		}
	})
	t.Run("an EVM-only change is refused, a configuration-only boundary is not", func(t *testing.T) {
		v := f.verifyCtx(c)
		v.CurrentRoot = f.root // the committee does not change, the EVM validators do
		_, _, err := Verify(raw, v)
		require.ErrorIs(t, err, ErrEVMOnly)
		// Same committee and same EVM validators at the next epoch (a configuration-only boundary) is allowed.
		current := clonePDR(t, f.succ)
		current.Epoch, current.EpochStart = f.succ.Epoch-1, 11
		cc, err := NewCandidate(f.ctx, f.root, current, f.succ, f.pops(t), nil, f.bindings,
			Lifecycle{Kind: KindPrimary, Identities: f.ids, Authorization: f.auth}, nil)
		require.NoError(t, err)
		require.NoError(t, VerifyInstalled(cc, f.succ, current, f.root))
	})
	t.Run("successor config drift", func(t *testing.T) {
		p := clonePDR(t, f.succ)
		p.PartitionParams["chain"] = "9"
		raw2, err := types.Cbor.Marshal(p)
		require.NoError(t, err)
		// Re-sign so only the installed-configuration relation can reject it.
		drift := f
		drift.succ = p
		b, v := rebuild(func(c *Candidate) { c.Assignment, c.PoPs = raw2, drift.pops(t) })
		_, _, err = Verify(b, v)
		require.ErrorIs(t, err, ErrConfig)
	})
	t.Run("pop covers a different assignment", func(t *testing.T) {
		// Candidate carries a valid successor, but its proofs were signed for
		// another one, so only the PoP check can reject it.
		alt := clonePDR(t, f.succ)
		alt.Validators = alt.Validators[:3]
		altCtx := f
		altCtx.succ = alt
		other := altCtx.pops(t)
		b, v := rebuild(func(c *Candidate) { c.PoPs = append(other, other[0]) })
		_, _, err := Verify(b, v)
		require.ErrorIs(t, err, ErrPoP)
	})
}

func TestChainCommitBindsBaseAndOrder(t *testing.T) {
	a, b := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	base := bytes.Repeat([]byte{3}, 32)
	c, err := ChainCommit(1, 1, base, [][]byte{a, b})
	require.NoError(t, err)
	for name, args := range map[string]struct {
		root, shard uint64
		active      []byte
		steps       [][]byte
	}{
		"root epoch":  {2, 1, base, [][]byte{a, b}},
		"shard epoch": {1, 2, base, [][]byte{a, b}},
		"base hash":   {1, 1, bytes.Repeat([]byte{4}, 32), [][]byte{a, b}},
		"order":       {1, 1, base, [][]byte{b, a}},
		"truncated":   {1, 1, base, [][]byte{a}},
	} {
		got, err := ChainCommit(args.root, args.shard, args.active, args.steps)
		require.NoError(t, err, name)
		require.NotEqual(t, c, got, name)
	}
	_, err = ChainCommit(1, 1, base, nil)
	require.ErrorIs(t, err, ErrContext)
	_, err = ChainCommit(1, 1, base, [][]byte{{1}})
	require.ErrorIs(t, err, ErrContext)
}

func TestActivateSetsOnlyTheActivationRound(t *testing.T) {
	f := newFixture(t)
	act, err := Activate(f.succ, 42)
	require.NoError(t, err)
	require.EqualValues(t, 42, act.EpochStart)
	want, err := AssignmentHash(f.succ, f.ctx.Identities)
	require.NoError(t, err)
	got, err := AssignmentHash(act, f.ctx.Identities)
	require.NoError(t, err)
	require.Equal(t, want, got)
	_, err = Activate(act, 43)
	require.ErrorIs(t, err, ErrAssignment)
	_, err = Activate(f.succ, 0)
	require.ErrorIs(t, err, ErrAssignment)
	full0, _ := PDRHash(f.succ)
	full1, _ := PDRHash(act)
	require.NotEqual(t, full0, full1, "the full configuration hash a certificate commits to includes the activation round")
}

// Shard nodes following handoffs derive the configuration hash the root certifies after an assignment step from the
// candidate alone: the successor with the committed activation round, hashed in full.
func TestActivatedFromPreimageDerivesTheCertifiedConfigurationHash(t *testing.T) {
	f := newFixture(t)
	c := f.candidate(t)
	raw, err := c.Encode()
	require.NoError(t, err)
	_, activated, err := ActivatedFromPreimage(raw, 40)
	require.NoError(t, err)
	require.Equal(t, f.succ.Epoch, activated.Epoch)
	require.Equal(t, uint64(40), activated.EpochStart)
	want, err := Activate(f.succ, 40)
	require.NoError(t, err)
	wantHash, err := want.Hash(crypto.SHA256)
	require.NoError(t, err)
	gotHash, err := activated.Hash(crypto.SHA256)
	require.NoError(t, err)
	require.Equal(t, wantHash, gotHash)
	currentHash, err := f.current.Hash(crypto.SHA256)
	require.NoError(t, err)
	require.NotEqual(t, currentHash, gotHash, "the follower's expected hash really changes at an assignment step")
	_, other, err := ActivatedFromPreimage(raw, 41)
	require.NoError(t, err)
	otherHash, err := other.Hash(crypto.SHA256)
	require.NoError(t, err)
	require.NotEqual(t, gotHash, otherHash, "the activation round is part of the certified hash")
	_, _, err = ActivatedFromPreimage([]byte("garbage"), 40)
	require.Error(t, err)
}
