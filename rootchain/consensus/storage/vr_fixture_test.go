package storage_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"sort"
	"testing"
	"time"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/q3format"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/evmstate/evmstatetest"
	"github.com/unicitynetwork/bft-core/rootchain/vrstate"
	"github.com/unicitynetwork/bft-core/rootrecords"
	"github.com/unicitynetwork/bft-core/vradmit"
	"github.com/unicitynetwork/bft-core/vrschema"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

// The VR-mode executor fixture: a root chain in VR mode at epoch 1 whose designated EVM shard (partition 8) is installed with the
// acknowledged committee K (ids 1..4), and a published PoA output R in the VR state the EVM shard certifies: J swaps member 4 for
// member 5, with one CommitteeLimits change bound. Every key is a real secp256k1 key, the VR state is a real Merkle-Patricia state, and
// the Freeze v5 witness, the RejectResult v2 witness and the HolderRetirement witness are built by rootchain/vrstate and verified by
// vrstate.Authority inside the executor.

const (
	vxNetwork = 5
	vxEVM     = 8
)

var (
	vxVRCode   = vrschema.Keccak([]byte("vr code"))
	vxSealCode = vrschema.Keccak([]byte("seal code"))
	vxShard    = types.PartitionShardID{PartitionID: vxEVM, ShardID: types.ShardID{}.Key()}
)

type vxKey struct {
	signer abcrypto.Signer
	pub    []byte
}

func vxMkKey(t testing.TB, seed byte) vxKey {
	s, err := abcrypto.NewInMemorySecp256K1SignerFromKey(bytes.Repeat([]byte{seed}, 32))
	require.NoError(t, err)
	v, err := s.Verifier()
	require.NoError(t, err)
	pub, err := v.MarshalPublicKey()
	require.NoError(t, err)
	return vxKey{signer: s, pub: pub}
}

type vxMember struct {
	root, evm string
	rk, ek    vxKey
}

type vxFixture struct {
	t        *testing.T
	dep      vradmit.Deployment
	pins     vrstate.Pins
	members  map[uint64]vxMember
	current  *types.PartitionDescriptionRecord
	k, j     []evmassign.Identity
	kRoot    []evmassign.RootMember
	succ     *types.PartitionDescriptionRecord
	body     [32]byte // the current (predecessor) body
	baseHash [32]byte
	r        vrschema.Word
	cand     vrschema.CandidateV6
	candRaw  []byte
	state    vradmit.OutputState
	q3       q3format.BodyV3
	intent   [32]byte
	tb       []byte
	parentEV []byte // the EVM block hash the Prepare binds
	world    *evmstatetest.World
	progress uint64 // the SealRegistry's progress in the VR state
	attempt  uint64 // the root attempt the candidate, its PoPs, the body and the receipts are for
	// extra VR and SealRegistry words, and a holder account, for the retirement fixture
	vrExtra, sealExtra map[[32]byte][32]byte
	holder             *evmstatetest.Contract

	// extraChanges are bound after the CommitteeLimits change; extraShards are non-EVM shards installed and acknowledged next to the EVM
	// shard (the live partition configuration tests, VT-06d/e).
	extraChanges []vrschema.RegistryChange
	extraShards  []*types.PartitionDescriptionRecord

	auth       *storage.TestVRAuthority
	intents    *vxIntents
	svc        *storage.PosServices
	witnesses  vxWitnesses
	candidates vxCandidates
	orch       storage.Orchestration
}

type vxWitnesses map[[32]byte][]byte

func (w vxWitnesses) Witness(h [32]byte) ([]byte, error) { return w[h], nil }

type vxCandidates map[string][]byte

func (c vxCandidates) HandoffCandidate(id []byte) ([]byte, error) { return c[string(id)], nil }

type vxNoClosures struct{}

func (vxNoClosures) VerifyClosure([]byte, uint64) (storage.ClosureFacts, error) {
	return storage.ClosureFacts{}, storage.ErrPosControlRefused
}

// vxIntents is the VT-05b intent derivation the executor consults: the fixture's intent while derivable, recording the queries.
type vxIntents struct {
	in      storage.VRIntent
	ok      bool
	queries []storage.VRIntentQuery
}

func (i *vxIntents) Intent(q storage.VRIntentQuery) (storage.VRIntent, bool, error) {
	i.queries = append(i.queries, q)
	return i.in, i.ok, nil
}

func vxStakingID(id uint64) []byte { w := vrschema.U64(id); return w[:] }

func (f *vxFixture) identity(id uint64) evmassign.Identity {
	m := f.members[id]
	var payee [20]byte
	payee[0], payee[19] = 0x9a, byte(id)
	exp := vrschema.PoaExposureDigest(f.dep.NetworkWord, f.dep.ChainID, f.dep.Registry, f.r, id)
	return evmassign.Identity{StakingID: vxStakingID(id), Generation: 1, RootNodeID: m.root, RootKey: m.rk.pub, EVMNodeID: m.evm, EVMKey: m.ek.pub,
		Weight: 1, RawWeight: 1, OperatorPayee: payee[:], ExposureDigest: exp[:]}
}

func vxRoots(ids []evmassign.Identity) []evmassign.RootMember {
	out := make([]evmassign.RootMember, 0, len(ids))
	for _, i := range ids {
		out = append(out, evmassign.RootMember{NodeID: i.RootNodeID, Key: i.RootKey, Weight: i.Weight})
	}
	sort.Slice(out, func(a, b int) bool { return out[a].NodeID < out[b].NodeID })
	return out
}

func newVXFixture(t *testing.T) *vxFixture {
	f := &vxFixture{t: t, members: map[uint64]vxMember{}, body: [32]byte{1}, parentEV: bytes.Repeat([]byte{0xe7}, 32), progress: 500}
	f.dep = vradmit.Deployment{RootNetwork: vxNetwork, NetworkWord: vrschema.Keccak([]byte("net")), ChainID: vrschema.U64(3), Registry: vrschema.ValidatorRegistry,
		RegistryCode: vxVRCode}
	f.pins = vrstate.Pins{Registry: vrschema.ValidatorRegistry, RegistryCode: vxVRCode, NetworkWord: f.dep.NetworkWord, SealRegistry: vrschema.SealRegistry,
		SealRegistryCode: vxSealCode}
	f.r = vrschema.Keccak([]byte("result R"))
	for i := uint64(1); i <= 5; i++ {
		f.members[i] = vxMember{root: "r" + string(rune('0'+i)), evm: string(rune('a' + i - 1)), rk: vxMkKey(t, byte(i)), ek: vxMkKey(t, byte(20+i))}
	}
	var infos []*types.NodeInfo
	for i := uint64(1); i <= 4; i++ {
		f.k = append(f.k, f.identity(i))
		infos = append(infos, &types.NodeInfo{NodeID: f.members[i].evm, SigKey: f.members[i].ek.pub, Stake: 1})
	}
	f.current = &types.PartitionDescriptionRecord{Version: 1, NetworkID: vxNetwork, PartitionID: vxEVM, PartitionTypeID: evmassign.EVMPartitionTypeID,
		TypeIDLen: 8, UnitIDLen: 256, T2Timeout: 5 * time.Second, Epoch: 3, EpochStart: 11,
		PartitionParams: map[string]string{"chain": "1", storage.ParamContinuityMaxDist: "1/2"}, Validators: infos}
	f.kRoot = vxRoots(f.k)
	kd, err := evmassign.IdentitiesDigest(f.k)
	require.NoError(t, err)
	f.baseHash, err = evmassign.AssignmentHash(f.current, kd)
	require.NoError(t, err)
	var succInfos []*types.NodeInfo
	for _, i := range []uint64{1, 2, 3, 5} {
		f.j = append(f.j, f.identity(i))
		succInfos = append(succInfos, &types.NodeInfo{NodeID: f.members[i].evm, SigKey: f.members[i].ek.pub, Stake: 1})
	}
	f.succ, err = evmassign.NewSuccessor(f.current, succInfos)
	require.NoError(t, err)
	f.build()
	return f
}

// build signs the candidate, derives VR's output record from it, writes the VR state and the successor body, and wires the services.
func (f *vxFixture) build() {
	t := f.t
	exposure, err := evmassign.ExposureCommit(f.k)
	require.NoError(t, err)
	snap, pol := vrschema.Keccak([]byte("snapshot")), vrschema.Keccak([]byte("policy"))
	cd := f.dep.ContractsDigest()
	auth := &evmassign.Authorization{Network: vxNetwork, Chain: 1, Contracts: cd[:], ResultID: f.r[:], SnapshotDigest: snap[:],
		BaseRootBodyID: f.body[:], BaseAssignmentHash: f.baseHash[:], K: f.k, ExposureDigest: exposure[:], Policies: pol[:]}
	jd, err := evmassign.IdentitiesDigest(f.j)
	require.NoError(t, err)
	ctx := evmassign.PoPContext{Network: vxNetwork, Predecessor: f.body, Identities: jd, Attempt: f.attempt}
	var pops []evmassign.PoP
	for _, v := range f.succ.Validators {
		for _, m := range f.members {
			if m.evm == v.NodeID {
				p, err := evmassign.SignPoP(m.ek.signer, ctx, f.succ, v.NodeID)
				require.NoError(t, err)
				pops = append(pops, p)
			}
		}
	}
	assignment, err := types.Cbor.Marshal(f.succ)
	require.NoError(t, err)
	old, err := evmassign.PDRHash(f.current)
	require.NoError(t, err)
	var bindings []evmassign.Binding
	for _, i := range f.j {
		bindings = append(bindings, evmassign.Binding{RootNodeID: i.RootNodeID, EVMNodeID: i.EVMNodeID})
	}
	sort.Slice(bindings, func(a, b int) bool { return bindings[a].RootNodeID < bindings[b].RootNodeID })
	limits, err := vrschema.EncodeChange(vrschema.KindCommitteeLimits, uint64(3), uint64(4), uint64(7))
	require.NoError(t, err)
	f.cand = vrschema.CandidateV6{Version: vrschema.CandidateV6Version, Kind: evmassign.KindPrimary, Network: vxNetwork, Predecessor: f.body[:], Attempt: f.attempt,
		RootMembers: vxRoots(f.j), OldShardEpoch: f.current.Epoch, OldActiveHash: old[:], Assignment: assignment, PoPs: pops, Bindings: bindings,
		Identities: f.j, Authorization: auth, SourceRef: f.r[:], RegistryChanges: append([]vrschema.RegistryChange{{ID: 4, Kind: uint64(vrschema.KindCommitteeLimits), Payload: limits}}, f.extraChanges...)}
	f.candRaw, err = f.cand.Encode()
	require.NoError(t, err)
	f.state = vradmit.OutputState{ResultID: f.r, Network: f.dep.NetworkWord, OpenOutput: f.r, LastAcked: vrschema.GenesisResult,
		Limits: vrschema.CommitteeLimits{NMin: 4, NTarget: 4, NMax: 7}, Status: vrschema.Status{KnownRootEpoch: 1},
		Output: vrschema.OutputRecord{State: vrschema.OutPublished, Attempt: 7, ReservedProgress: 100, ExpiresAtProgress: 100 + vrschema.Lifetime,
			Predecessor: vrschema.GenesisResult, SourceModule: [20]byte{0xa0, 19: 1}, ModuleTag: vrschema.PoaModuleTag, SnapshotDigest: snap, PolicyDigest: pol}}
	o := &f.state.Output
	o.MembersDigest, err = vradmit.MembersDigestOf(f.cand.Identities)
	require.NoError(t, err)
	o.KDigest, err = vradmit.MembersDigestOf(f.k)
	require.NoError(t, err)
	o.ChangesDigest, err = vrschema.ChangesDigestOf(f.cand.RegistryChanges)
	require.NoError(t, err)
	o.OutputCommit = vrschema.OutputCommit(vrschema.OutputCommitInput{Network: f.state.Network, ChainID: f.dep.ChainID, Registry: f.dep.Registry, ResultID: f.r,
		Predecessor: o.Predecessor, Attempt: o.Attempt, ModuleTag: o.ModuleTag, Native: o.Native, SnapshotDigest: o.SnapshotDigest, PolicyDigest: o.PolicyDigest,
		MembersDigest: o.MembersDigest, KDigest: o.KDigest, ChangesDigest: o.ChangesDigest})
	f.writeWorld()

	// the successor body the intent derives: it commits to the certified candidate (D4 candidate context) and links to the current body
	members := evmroot.WeightSet{}
	for _, i := range f.j {
		members = append(members, evmroot.Member{StakingID: string(i.StakingID), NodeID: i.RootNodeID, ConsensusKey: i.RootKey, Weight: i.Weight})
	}
	cdig := sha256.Sum256(f.candRaw)
	f.q3 = q3format.BodyV3{Network: vxNetwork, Epoch: 2, EarliestActivation: 5, Members: members, RootThreshold: 3, PredecessorHash: bytes.Repeat([]byte{0x11}, 32),
		StateSummary: bytes.Repeat([]byte{0x22}, 32), Config: q3format.Q3Config(vxNetwork, [32]byte{0x99})}
	f.q3.ChangeRecordHash = evmroot.D4CandidateContextHash(vxNetwork, f.body[:], f.attempt, cdig[:], f.q3.EarliestActivation)
	f.intent = sha256.Sum256([]byte("intent"))
	f.tb = []byte("successor trust base")

	f.auth = &storage.TestVRAuthority{Pred: f.body[:], Root: f.kRoot, Link: f.q3.PredecessorHash}
	f.intents = &vxIntents{in: storage.VRIntent{Digest: f.intent, AnchorUCTime: 1_000, Body: f.q3, TrustBase: f.tb}, ok: true}
	f.witnesses = vxWitnesses{}
	f.candidates = vxCandidates{}
	f.svc = &storage.PosServices{Authority: vxNoClosures{}, Witnesses: f.witnesses,
		Registry: &storage.VRServices{Deployment: f.dep, State: vrstate.Authority{Pins: f.pins}, Intents: f.intents}}
	f.orch = storage.NewMockOrchestrationForTest(func(uint64) (map[types.PartitionShardID]*types.PartitionDescriptionRecord, error) {
		confs := map[types.PartitionShardID]*types.PartitionDescriptionRecord{vxShard: f.current}
		for _, p := range f.extraShards {
			confs[types.PartitionShardID{PartitionID: p.PartitionID, ShardID: p.ShardID.Key()}] = p
		}
		return confs, nil
	}, func() ([]evmassign.Identity, [32]byte) { return f.k, f.baseHash })
}

// writeWorld writes VR (and the SealRegistry's progress) from the output state.
func (f *vxFixture) writeWorld() {
	t := f.t
	word := func(w vrschema.Word, err error) vrschema.Word { require.NoError(t, err); return w }
	vr := map[[32]byte][32]byte{vrschema.VRSlot(vrschema.SlotNetwork): f.state.Network, vrschema.VRSlot(vrschema.SlotOpenOutput): f.state.OpenOutput,
		vrschema.VRSlot(vrschema.SlotLastAcked):       f.state.LastAcked,
		vrschema.VRSlot(vrschema.SlotCommitteeLimits): word(f.state.Limits.Word()),
		vrschema.VRSlot(vrschema.SlotStatus):          word(f.state.Status.Word())}
	if f.state.PendingPair != (vrschema.Word{}) {
		vr[vrschema.VRSlot(vrschema.SlotPendingPair)] = f.state.PendingPair
	}
	ow, err := f.state.Output.Words()
	require.NoError(t, err)
	for j, x := range ow {
		if x != (vrschema.Word{}) {
			vr[vrschema.OutputSlot(f.r, uint64(j))] = x
		}
	}
	for k, v := range f.vrExtra {
		vr[k] = v
	}
	seal := map[[32]byte][32]byte{vrstate.SealProgress: vrschema.U64(f.progress)}
	for k, v := range f.sealExtra {
		seal[k] = v
	}
	cs := []evmstatetest.Contract{{Addr: f.pins.Registry, CodeHash: vxVRCode, Storage: vr}, {Addr: f.pins.SealRegistry, CodeHash: vxSealCode, Storage: seal}}
	if f.holder != nil {
		cs = append(cs, *f.holder)
	}
	f.world = evmstatetest.NewWorld(t, cs...)
}

func (f *vxFixture) signer(id []byte) vxKey {
	for i, m := range f.members {
		if bytes.Equal(vxStakingID(i), id) {
			return m.rk
		}
	}
	f.t.Fatalf("no member %x", id)
	return vxKey{}
}

// readiness signs one member's readiness for the assembly of view slot.
func (f *vxFixture) readiness(i evmassign.Identity, slot uint64, cs []vrschema.SupportCommitment) vrschema.Readiness {
	t := f.t
	k := f.signer(i.StakingID)
	cd := sha256.Sum256(f.candRaw)
	bodyID := f.q3.Identity()
	rcpt, err := q3format.SignReceipt(q3format.ContextFor(f.q3, f.attempt, cd), i.RootNodeID, k.signer)
	require.NoError(t, err)
	enc, err := vrschema.EncodeReadinessReceipt(rcpt)
	require.NoError(t, err)
	rs, err := vrschema.RuleSupportDigest(cs)
	require.NoError(t, err)
	tbs, err := k.signer.SignBytes(f.tb)
	require.NoError(t, err)
	r := vrschema.Readiness{IntentDigest: f.intent[:], Slot: slot, CandidateDigest: cd[:], BodyID: bodyID[:], RuleSupportDigest: rs[:], Commitments: cs,
		Receipt: enc, TrustBaseSig: tbs}
	env, err := r.EnvelopeBytes()
	require.NoError(t, err)
	r.EnvelopeSig, err = k.signer.SignBytes(env)
	require.NoError(t, err)
	return r
}

// commitment is a support commitment of i's exact binding for rule.
func (f *vxFixture) commitment(i evmassign.Identity, rule vrschema.Word) vrschema.SupportCommitment {
	kh := ethcrypto.Keccak256(i.RootKey)
	rel := vrschema.Keccak([]byte("release"))
	c := vrschema.SupportCommitment{Network: vxNetwork, StakingID: i.StakingID, Generation: i.Generation, RootKeyHash: kh, RuleID: rule[:], ReleaseDigest: rel[:]}
	msg, err := c.SignedBytes()
	require.NoError(f.t, err)
	c.Sig, err = f.signer(i.StakingID).signer.SignBytes(msg)
	require.NoError(f.t, err)
	return c
}

// freezeV5 is the companion of the view-slot certificate, with the Freeze witness built against the current VR state.
func (f *vxFixture) freezeV5(slot uint64) []byte {
	t := f.t
	ids := make([]string, 0, len(f.k))
	for _, i := range f.k {
		ids = append(ids, i.RootNodeID)
	}
	asm := vrschema.Assembler(vrschema.AssemblerOrder(f.intent, ids), slot)
	a := vrschema.Assembly{IntentDigest: f.intent[:], Slot: slot, Candidate: f.candRaw}
	msg, err := a.SignedBytes()
	require.NoError(t, err)
	for _, i := range f.k {
		if i.RootNodeID == asm {
			a.Sig, err = f.signer(i.StakingID).signer.SignBytes(msg)
			require.NoError(t, err)
		}
	}
	c := vrschema.ViewCertificate{Assembly: a}
	for _, i := range f.j {
		c.Readiness = append(c.Readiness, f.readiness(i, slot, nil))
	}
	witness, _, err := vrstate.BuildOutputWitness(context.Background(), f.world, f.pins, f.r)
	require.NoError(t, err)
	raw, err := vrschema.FreezeV5{Candidate: f.candRaw, Certificate: c, Witness: witness}.Encode()
	require.NoError(t, err)
	return raw
}

// genesis is the VR-mode parent block at round 10 of epoch 1: the EVM shard installed and acknowledged at the VR state's root, the
// control state idle with the projection state and the VR root state at genesis.
func (f *vxFixture) genesis() *storage.ExecutedBlock {
	t := f.t
	si, err := storage.NewShardInfo(f.current, crypto.SHA256)
	require.NoError(t, err)
	root := f.world.Root()
	si.IR = &types.InputRecord{Version: 1, RoundNumber: si.TR.Round - 1, Epoch: si.TR.Epoch, Hash: root[:], BlockHash: bytes.Clone(f.parentEV),
		PreviousHash: bytes.Repeat([]byte{0x33}, 32), SummaryValue: []byte{}, Timestamp: 900}
	vr, err := vradmit.GenesisRootState(1, 4).Encode()
	require.NoError(t, err)
	ctl := &evmroot.ControlState{Network: vxNetwork, Epoch: 1, PredecessorBodyID: f.body[:], Phase: "idle", Pos: rootrecords.NewState(1, 1).Bytes(), VR: vr}
	state := storage.ShardStates{States: map[types.PartitionShardID]*storage.ShardInfo{vxShard: si}, Changed: storage.ShardSet{}, Control: ctl}
	for _, p := range f.extraShards {
		x, err := storage.NewShardInfo(p, crypto.SHA256)
		require.NoError(t, err)
		x.IR = &types.InputRecord{Version: 1, RoundNumber: x.TR.Round - 1, Epoch: x.TR.Epoch, Hash: bytes.Repeat([]byte{0x44}, 32), BlockHash: bytes.Repeat([]byte{0x45}, 32),
			PreviousHash: bytes.Repeat([]byte{0x46}, 32), SummaryValue: []byte{}, Timestamp: 900}
		state.States[types.PartitionShardID{PartitionID: p.PartitionID, ShardID: p.ShardID.Key()}] = x
	}
	ut, _, err := state.UnicityTree(crypto.SHA256)
	require.NoError(t, err)
	return &storage.ExecutedBlock{BlockData: &rctypes.BlockData{Version: rctypes.VersionHandoff, Round: 10, Epoch: 1, Timestamp: 1_000,
		Payload: &rctypes.Payload{Version: rctypes.VersionHandoff}}, HashAlgo: crypto.SHA256, RootHash: ut.RootHash(), ShardState: state}
}

// block is the child of parent at round, at UC time ts, with the given handoff records and controls.
func (f *vxFixture) block(parent *storage.ExecutedBlock, round, ts uint64, records [][]byte, controls ...rctypes.PosControl) *rctypes.BlockData {
	return &rctypes.BlockData{Version: rctypes.VersionHandoff, Round: round, Epoch: 1, Timestamp: ts,
		Payload: &rctypes.Payload{Version: rctypes.VersionHandoff, HandoffRecords: records, PosControls: controls},
		Qc:      &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: round - 1, Epoch: 1, CurrentRootHash: parent.RootHash}}}
}

func (f *vxFixture) exec(parent *storage.ExecutedBlock, b *rctypes.BlockData) (*storage.ExecutedBlock, error) {
	return storage.ExtendForTest(parent, b, f.orch, f.auth, f.candidates, f.svc)
}

func (f *vxFixture) must(parent *storage.ExecutedBlock, b *rctypes.BlockData) *storage.ExecutedBlock {
	f.t.Helper()
	next, err := f.exec(parent, b)
	require.NoError(f.t, err)
	return next
}

func (f *vxFixture) record(kind string, attempt, round uint64) evmroot.OrderedHandoffRecord {
	id := f.q3.Identity()
	r := evmroot.OrderedHandoffRecord{Network: vxNetwork, Epoch: 1, Attempt: attempt, OrderedRound: round, ActivationRound: 200, PredecessorBodyID: f.body[:],
		NextBodyID: id[:], FrozenID: make([]byte, 32), SuccessorTRHash: make([]byte, 32), Kind: kind}
	if kind == "freeze" {
		cd := sha256.Sum256(f.candRaw)
		r.FrozenID = evmroot.D4FrozenID(id[:], f.q3.StateSummary, f.parentEV, cd[:], attempt, f.body[:])
	}
	return r
}

// rootState decodes the VR root state of an executed block.
func rootState(t *testing.T, b *storage.ExecutedBlock) vradmit.RootState {
	t.Helper()
	s, err := vradmit.DecodeRootState(b.ShardState.Control.VR)
	require.NoError(t, err)
	return s
}

func posState(t *testing.T, b *storage.ExecutedBlock) rootrecords.State {
	t.Helper()
	s, err := rootrecords.DecodeState(b.ShardState.Control.Pos)
	require.NoError(t, err)
	return s
}

// v5Bytes is the v5 view of the fixture's candidate, as the store retains it.
func (f *vxFixture) v5Bytes() []byte {
	raw, err := vradmit.V5Of(f.cand).Encode()
	require.NoError(f.t, err)
	return raw
}
