package vradmit

import (
	"bytes"
	"crypto/sha256"
	"sort"
	"testing"
	"time"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/continuity"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/q3format"
	"github.com/unicitynetwork/bft-core/vrschema"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

// The admission fixture: an incumbent committee K of four (ids 1..4, root r1..r4, EVM a..d) and a published PoA output J that swaps
// member 4 for member 5 (root r5, EVM e), with one CommitteeLimits change bound. Every key is a real secp256k1 key, so the PoPs, the
// assembly, the readiness envelopes, receipts and trust-base signatures and the support commitments all verify.

type key struct {
	signer abcrypto.Signer
	pub    []byte
}

func mkKey(t testing.TB, seed byte) key {
	t.Helper()
	s, err := abcrypto.NewInMemorySecp256K1SignerFromKey(bytes.Repeat([]byte{seed}, 32))
	require.NoError(t, err)
	v, err := s.Verifier()
	require.NoError(t, err)
	pub, err := v.MarshalPublicKey()
	require.NoError(t, err)
	return key{signer: s, pub: pub}
}

const (
	fxNetwork      = 5
	fxEVMPartition = 8
	fxControl      = 9
)

type member struct {
	id        uint64
	root, evm string
	rk, ek    key
}

type world struct {
	t        *testing.T
	dep      Deployment
	members  map[uint64]member
	current  *types.PartitionDescriptionRecord
	k, j     []evmassign.Identity
	kRoot    []evmassign.RootMember
	jRoot    []evmassign.RootMember
	succ     *types.PartitionDescriptionRecord
	body     [32]byte
	baseHash [32]byte
	r        vrschema.Word
	cand     vrschema.CandidateV6
	state    OutputState
	policy   continuity.Policy
	q3       q3format.BodyV3
	intent   [32]byte
	tb       []byte
	// the output's snapshot and policy digests and its native flag (a native repair output: zero digests, REGISTRY_NATIVE)
	snap, pol vrschema.Word
	native    bool
}

func stakingID(id uint64) []byte { w := vrschema.U64(id); return w[:] }

func (w *world) identity(id uint64) evmassign.Identity {
	m := w.members[id]
	var payee [20]byte
	payee[0], payee[19] = 0x9a, byte(id)
	exp := vrschema.PoaExposureDigest(w.dep.NetworkWord, w.dep.ChainID, w.dep.Registry, w.r, id)
	return evmassign.Identity{StakingID: stakingID(id), Generation: 1, RootNodeID: m.root, RootKey: m.rk.pub, EVMNodeID: m.evm, EVMKey: m.ek.pub,
		Weight: 1, RawWeight: 1, OperatorPayee: payee[:], ExposureDigest: exp[:]}
}

func (w *world) roots(ids []evmassign.Identity) []evmassign.RootMember {
	out := make([]evmassign.RootMember, 0, len(ids))
	for _, i := range ids {
		out = append(out, evmassign.RootMember{NodeID: i.RootNodeID, Key: i.RootKey, Weight: i.Weight})
	}
	sort.Slice(out, func(a, b int) bool { return out[a].NodeID < out[b].NodeID })
	return out
}

func newWorld(t *testing.T) *world {
	w := &world{t: t, members: map[uint64]member{}, policy: continuity.Policy{MaxM: 4, MaxDistNum: 1, MaxDistDen: 2}, body: [32]byte{1}}
	w.dep = Deployment{RootNetwork: fxNetwork, NetworkWord: vrschema.Keccak([]byte("net")), ChainID: vrschema.U64(3), Registry: vrschema.ValidatorRegistry,
		RegistryCode: vrschema.Keccak([]byte("vr-code"))}
	w.r = vrschema.Keccak([]byte("result R"))
	w.snap, w.pol = vrschema.Keccak([]byte("snapshot")), vrschema.Keccak([]byte("policy"))
	for i := uint64(1); i <= 5; i++ {
		w.members[i] = member{id: i, root: "r" + string(rune('0'+i)), evm: string(rune('a' + i - 1)), rk: mkKey(t, byte(i)), ek: mkKey(t, byte(20+i))}
	}
	var infos []*types.NodeInfo
	for i := uint64(1); i <= 4; i++ {
		w.k = append(w.k, w.identity(i))
		infos = append(infos, &types.NodeInfo{NodeID: w.members[i].evm, SigKey: w.members[i].ek.pub, Stake: 1})
	}
	w.current = &types.PartitionDescriptionRecord{Version: 1, NetworkID: fxNetwork, PartitionID: fxEVMPartition, PartitionTypeID: evmassign.EVMPartitionTypeID,
		TypeIDLen: 8, UnitIDLen: 256, T2Timeout: 5 * time.Second, Epoch: 3, EpochStart: 11, PartitionParams: map[string]string{"chain": "1"}, Validators: infos}
	w.kRoot = w.roots(w.k)
	kd, err := evmassign.IdentitiesDigest(w.k)
	require.NoError(t, err)
	w.baseHash, err = evmassign.AssignmentHash(w.current, kd)
	require.NoError(t, err)
	// J swaps 4 for 5
	var succInfos []*types.NodeInfo
	for _, i := range []uint64{1, 2, 3, 5} {
		w.j = append(w.j, w.identity(i))
		succInfos = append(succInfos, &types.NodeInfo{NodeID: w.members[i].evm, SigKey: w.members[i].ek.pub, Stake: 1})
	}
	w.jRoot = w.roots(w.j)
	w.succ, err = evmassign.NewSuccessor(w.current, succInfos)
	require.NoError(t, err)
	w.build()
	return w
}

// build signs the candidate and derives VR's output state, the certificate inputs and the intent from the current fields.
func (w *world) build() {
	t := w.t
	exposure, err := evmassign.ExposureCommit(w.k)
	require.NoError(t, err)
	snap, pol := w.snap, w.pol
	as, ap := AuthorizationWord(snap), AuthorizationWord(pol)
	cd := w.dep.ContractsDigest()
	auth := &evmassign.Authorization{Network: fxNetwork, Chain: 1, Contracts: cd[:], ResultID: w.r[:], SnapshotDigest: as[:],
		BaseRootBodyID: w.body[:], BaseAssignmentHash: w.baseHash[:], K: w.k, ExposureDigest: exposure[:], Policies: ap[:]}
	jd, err := evmassign.IdentitiesDigest(w.j)
	require.NoError(t, err)
	ctx := evmassign.PoPContext{Network: fxNetwork, Predecessor: w.body, Identities: jd}
	var pops []evmassign.PoP
	for _, v := range w.succ.Validators {
		var signer abcrypto.Signer
		for _, m := range w.members {
			if m.evm == v.NodeID {
				signer = m.ek.signer
			}
		}
		p, err := evmassign.SignPoP(signer, ctx, w.succ, v.NodeID)
		require.NoError(t, err)
		pops = append(pops, p)
	}
	assignment, err := types.Cbor.Marshal(w.succ)
	require.NoError(t, err)
	old, err := evmassign.PDRHash(w.current)
	require.NoError(t, err)
	var bindings []evmassign.Binding
	for _, i := range w.j {
		bindings = append(bindings, evmassign.Binding{RootNodeID: i.RootNodeID, EVMNodeID: i.EVMNodeID})
	}
	sort.Slice(bindings, func(a, b int) bool { return bindings[a].RootNodeID < bindings[b].RootNodeID })
	limits, err := vrschema.EncodeChange(vrschema.KindCommitteeLimits, uint64(3), uint64(4), uint64(7))
	require.NoError(t, err)
	w.cand = vrschema.CandidateV6{Version: vrschema.CandidateV6Version, Kind: evmassign.KindPrimary, Network: fxNetwork, Predecessor: w.body[:],
		RootMembers: w.jRoot, OldShardEpoch: w.current.Epoch, OldActiveHash: old[:], Assignment: assignment, PoPs: pops, Bindings: bindings,
		Identities: w.j, Authorization: auth, SourceRef: w.r[:], RegistryChanges: []vrschema.RegistryChange{{ID: 4, Kind: uint64(vrschema.KindCommitteeLimits), Payload: limits}}}
	w.state = OutputState{ResultID: w.r, Network: w.dep.NetworkWord, OpenOutput: w.r, LastAcked: vrschema.GenesisResult,
		Limits: vrschema.CommitteeLimits{NMin: 4, NTarget: 4, NMax: 7}, Status: vrschema.Status{KnownRootEpoch: 1},
		Output: vrschema.OutputRecord{State: vrschema.OutPublished, Attempt: 7, ReservedProgress: 100, ExpiresAtProgress: 100 + vrschema.Lifetime,
			Predecessor: vrschema.GenesisResult, SourceModule: [20]byte{0xa0, 19: 1}, ModuleTag: vrschema.PoaModuleTag, SnapshotDigest: snap, PolicyDigest: pol}}
	if w.native {
		w.state.Output.Native, w.state.Output.ModuleTag, w.state.Output.SourceModule = true, vrschema.RegistryNative, [20]byte{}
	}
	w.commit()
	members := evmroot.WeightSet{}
	for _, i := range w.j {
		members = append(members, evmroot.Member{StakingID: string(i.StakingID), NodeID: i.RootNodeID, ConsensusKey: i.RootKey, Weight: i.Weight})
	}
	w.q3 = q3format.BodyV3{Network: fxNetwork, Epoch: 2, EarliestActivation: 50, Members: members, RootThreshold: 3, PredecessorHash: w.body[:],
		Config: q3format.Q3Config(fxNetwork, [32]byte{0x99})}
	w.intent = sha256.Sum256([]byte("intent"))
	w.tb = []byte("successor trust base")
}

// commit recomputes VR's digests of the output record from the candidate (as VR wrote them).
func (w *world) commit() {
	t := w.t
	o := &w.state.Output
	var err error
	o.MembersDigest, err = MembersDigestOf(w.cand.Identities)
	require.NoError(t, err)
	o.KDigest, err = MembersDigestOf(w.cand.Authorization.K)
	require.NoError(t, err)
	o.ChangesDigest, err = vrschema.ChangesDigestOf(w.cand.RegistryChanges)
	require.NoError(t, err)
	o.OutputCommit = vrschema.OutputCommit(vrschema.OutputCommitInput{Network: w.state.Network, ChainID: w.dep.ChainID, Registry: w.dep.Registry, ResultID: w.r,
		Predecessor: o.Predecessor, Attempt: o.Attempt, ModuleTag: o.ModuleTag, Native: o.Native, SnapshotDigest: o.SnapshotDigest, PolicyDigest: o.PolicyDigest,
		MembersDigest: o.MembersDigest, KDigest: o.KDigest, ChangesDigest: o.ChangesDigest})
}

func (w *world) signer(id []byte) key {
	for _, m := range w.members {
		if bytes.Equal(stakingID(m.id), id) {
			return m.rk
		}
	}
	w.t.Fatalf("no member %x", id)
	return key{}
}

// readiness signs one member's readiness for the assembly of view slot, with the given commitments.
func (w *world) readiness(i evmassign.Identity, slot uint64, candidate []byte, cs []vrschema.SupportCommitment) vrschema.Readiness {
	t := w.t
	k := w.signer(i.StakingID)
	cd := sha256.Sum256(candidate)
	bodyID := w.q3.Identity()
	rcpt, err := q3format.SignReceipt(q3format.ContextFor(w.q3, w.cand.Attempt, cd), i.RootNodeID, k.signer)
	require.NoError(t, err)
	enc, err := vrschema.EncodeReadinessReceipt(rcpt)
	require.NoError(t, err)
	rs, err := vrschema.RuleSupportDigest(cs)
	require.NoError(t, err)
	tbs, err := k.signer.SignBytes(w.tb)
	require.NoError(t, err)
	r := vrschema.Readiness{IntentDigest: w.intent[:], Slot: slot, CandidateDigest: cd[:], BodyID: bodyID[:], RuleSupportDigest: rs[:], Commitments: cs,
		Receipt: enc, TrustBaseSig: tbs}
	env, err := r.EnvelopeBytes()
	require.NoError(t, err)
	r.EnvelopeSig, err = k.signer.SignBytes(env)
	require.NoError(t, err)
	return r
}

func (w *world) commitment(i evmassign.Identity, rule vrschema.Word) vrschema.SupportCommitment {
	kh := ethcrypto.Keccak256(i.RootKey)
	rel := vrschema.Keccak([]byte("release"))
	c := vrschema.SupportCommitment{Network: fxNetwork, StakingID: i.StakingID, Generation: i.Generation, RootKeyHash: kh, BindingRef: refOf(i), RuleID: rule[:], ReleaseDigest: rel[:]}
	msg, err := c.SignedBytes()
	require.NoError(w.t, err)
	c.Sig, err = w.signer(i.StakingID).signer.SignBytes(msg)
	require.NoError(w.t, err)
	return c
}

func (w *world) incumbents() map[string][]byte {
	out := map[string][]byte{}
	for _, i := range w.k {
		out[i.RootNodeID] = i.RootKey
	}
	return out
}

// certificate is the view-slot certificate of the candidate with every member's readiness carrying cs[member].
func (w *world) certificate(slot uint64, cs map[uint64][]vrschema.SupportCommitment) vrschema.ViewCertificate {
	t := w.t
	raw, err := w.cand.Encode()
	require.NoError(t, err)
	ids := make([]string, 0, len(w.k))
	for _, i := range w.k {
		ids = append(ids, i.RootNodeID)
	}
	asm := vrschema.Assembler(vrschema.AssemblerOrder(w.intent, ids), slot)
	a := vrschema.Assembly{IntentDigest: w.intent[:], Slot: slot, Candidate: raw}
	msg, err := a.SignedBytes()
	require.NoError(t, err)
	for _, i := range w.k {
		if i.RootNodeID == asm {
			a.Sig, err = w.signer(i.StakingID).signer.SignBytes(msg)
			require.NoError(t, err)
		}
	}
	c := vrschema.ViewCertificate{Assembly: a}
	for _, i := range w.j {
		id, _ := evmassign.CustodyID(i.StakingID)
		c.Readiness = append(c.Readiness, w.readiness(i, slot, raw, cs[id]))
	}
	return c
}

func (w *world) admission() Admission {
	cert := w.certificate(0, nil)
	return Admission{Deployment: w.dep, Candidate: w.cand, State: w.state, Acknowledged: vrschema.GenesisResult,
		Verify: evmassign.VerifyContext{BindingContext: evmassign.BindingContext{PoPContext: evmassign.PoPContext{Network: fxNetwork, Predecessor: w.body},
			SuccessorRoot: w.jRoot, ControlPartition: fxControl}, Current: w.current, CurrentRoot: w.kRoot},
		Lifecycle: evmassign.LifecycleContext{Incumbent: w.k, IncumbentAssignment: w.baseHash, Policy: w.policy},
		Fold: FoldContext{Network: fxNetwork, SuccessorRootEpoch: 2, Installed: map[types.PartitionShardID]*types.PartitionDescriptionRecord{
			{PartitionID: fxEVMPartition}: w.current}, EVMPartition: fxEVMPartition, ControlPartition: fxControl}.Input(),
		EVMAcked: true, PrepareUCTime: 1000,
		Support:     SupportInput{},
		Certificate: CertificateInput{Certificate: cert, IntentDigest: w.intent, CommittedView: 0, Incumbents: w.incumbents(), Successors: w.j, Body: w.q3, TrustBaseBytes: w.tb},
	}
}

type evmassignIdentity = evmassign.Identity

// refOf is i's registry binding ref as a commitment field.
func refOf(i evmassign.Identity) []byte { r := i.BindingRef(); return r[:] }
