package storage_test

import (
	"context"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/evmstate/evmstatetest"
	"github.com/unicitynetwork/bft-core/rootchain/vrstate"
	"github.com/unicitynetwork/bft-core/rootrecords"
	"github.com/unicitynetwork/bft-core/vradmit"
	"github.com/unicitynetwork/bft-core/vrschema"
	"github.com/unicitynetwork/bft-go-base/types/hex"
)

var (
	vxHolderAt = [20]byte{0xb0, 19: 0x02}
	vxReplaced = vrschema.Keccak([]byte("J's assignment"))
)

// HolderRetirement v2 through the executor over the real three-account witness: projected once at the holder-scoped key; a repeat is no
// new record; a witness whose facts are not retirable is refused in the frozen check order.
func TestVRHolderRetirementThroughTheExecutor(t *testing.T) {
	h := vrschema.HolderRetirement{Holder: 0, ID: 3, Generation: 1, RefDigest: vrschema.Keccak([]byte("exposure chain"))}
	build := func(t *testing.T, requested bool) (*vxFixture, rctypes.PosControl) {
		f := newVXFixture(t)
		holderCode := vrschema.Keccak([]byte("holder code"))
		hw, err := vrschema.Holder{Holder: vxHolderAt, CodeHash: holderCode, Module: [20]byte{0xa0, 19: 1}, RegisteredEpoch: 1}.Words()
		require.NoError(t, err)
		f.vrExtra = map[[32]byte][32]byte{}
		for j := range hw {
			f.vrExtra[vrschema.HolderSlot(h.Holder, uint64(j))] = hw[j]
		}
		f.state.Status.HolderCount = 1
		f.sealExtra = map[[32]byte][32]byte{vrstate.SealRecordCount: vrschema.U64(4), vrstate.SealTargetCount: vrschema.U64(4)}
		facts, err := vrschema.LiabilityFacts{Requested: requested, MaxLiabilityAnchor: 5, RefDigest: h.RefDigest}.Words()
		require.NoError(t, err)
		f.holder = &evmstatetest.Contract{Addr: vxHolderAt, CodeHash: holderCode, Storage: map[[32]byte][32]byte{vrschema.LiabilityCursorSlot(): vrschema.U64(4),
			vrschema.LiabilityFactsSlot(h.ID, h.Generation, 0): facts[0], vrschema.LiabilityFactsSlot(h.ID, h.Generation, 1): facts[1]}}
		f.writeWorld()
		witness, _, err := vrstate.BuildRetirementWitness(context.Background(), f.world, f.pins, h)
		require.NoError(t, err)
		wh := sha256.Sum256(witness)
		f.witnesses[wh] = witness
		var bh [32]byte
		copy(bh[:], f.parentEV)
		return f, rctypes.PosControl{Registry: true, Network: vxNetwork, ChainID: f.dep.ChainID, Custody: f.dep.Registry, OrderingEpoch: 1, OrderingRound: 11,
			Op: rctypes.OpRetirement, Retire: &rctypes.RetireContext{EVMBlockHash: bh, EVMStateRoot: f.world.Root()}, Data: h.Encode(), WitnessHash: wh}
	}
	f, ctl := build(t, true)
	g := f.genesis()
	b := f.must(g, f.block(g, 11, 1_010, nil, ctl))
	require.Len(t, b.ShardState.Records, 1)
	require.Equal(t, rootrecords.KindHolderRetirement, b.ShardState.Records[0].Kind)
	require.Equal(t, h.Encode(), b.ShardState.Records[0].Data)
	ref, ok := posState(t, b).IsHolderRetired(0, 3, 1)
	require.True(t, ok)
	require.Equal(t, h.RefDigest, ref)

	f2, ctl2 := build(t, false)
	g2 := f2.genesis()
	_, err := f2.exec(g2, f2.block(g2, 11, 1_010, nil, ctl2))
	require.ErrorIs(t, err, storage.ErrVRControlRefused)
	require.ErrorIs(t, err, vrschema.ErrRetNotReq)
}

type vxSchedule []vrschema.Activation

func (s vxSchedule) Committed(uint64) ([]vrschema.Activation, error) { return s, nil }

// RuleSupport through the executor: commitments by exact bindings of the acknowledged committee for a scheduled rule enter the committed
// table; a commitment by a binding outside the committee, or for an unscheduled rule, is refused.
func TestVRRuleSupportThroughTheExecutor(t *testing.T) {
	f := newVXFixture(t)
	rule := vrschema.RuleID("fork-a")
	f.svc.Registry.Schedule = vxSchedule{{RuleID: rule, ReleaseDigest: vrschema.Keccak([]byte("release")), RootEpoch: 9, State: vrschema.ActActive, ChangeID: 2}}
	g := f.genesis()
	support := func(cs ...vrschema.SupportCommitment) rctypes.PosControl {
		var out []rctypes.SupportCommitment
		for _, c := range cs {
			out = append(out, rctypes.SupportCommitment{Network: c.Network, StakingID: c.StakingID, Generation: c.Generation, RootKeyHash: c.RootKeyHash,
				RuleID: c.RuleID, ReleaseDigest: c.ReleaseDigest, Sig: c.Sig})
		}
		return rctypes.PosControl{Registry: true, Network: vxNetwork, ChainID: f.dep.ChainID, Custody: f.dep.Registry, OrderingEpoch: 1, OrderingRound: 11,
			Op: rctypes.OpRuleSupport, Support: out}
	}
	b := f.must(g, f.block(g, 11, 1_010, nil, support(f.commitment(f.k[0], rule), f.commitment(f.k[1], rule))))
	require.Len(t, rootState(t, b).Support.Entries, 2)
	require.Empty(t, b.ShardState.Records, "root-only: no record")

	_, err := f.exec(g, f.block(g, 11, 1_010, nil, support(f.commitment(f.identity(5), rule))))
	require.ErrorIs(t, err, vradmit.ErrSupport, "member 5 is not of the acknowledged committee")
	_, err = f.exec(g, f.block(g, 11, 1_010, nil, support(f.commitment(f.k[0], vrschema.RuleID("other")))))
	require.ErrorIs(t, err, vradmit.ErrSupport, "no scheduled rule")
}

// vxClosures is a closure authority for one closed epoch.
type vxClosures struct{ facts storage.ClosureFacts }

func (c vxClosures) VerifyClosure([]byte, uint64) (storage.ClosureFacts, error) { return c.facts, nil }

// The closure duty in VR mode: always on (even on a chain without a closure authority, which then cannot propose), and the closure's
// exposure digest is formed in the VR domain (VR's address as the deployment address); the custody-domain digest is refused.
func TestVRClosureDutyAndDomain(t *testing.T) {
	f := newVXFixture(t)
	g := f.genesis()
	// epoch 0 ended at H round 5 with an assignment handoff: its closure is outstanding in epoch 1
	st := rootrecords.NewState(0, 1)
	st, err := st.Commit(5, 1, 6, true, [32]byte{0xb1})
	require.NoError(t, err)
	st, err = st.Block(1, 6)
	require.NoError(t, err)
	require.Len(t, st.Awaiting, 1)
	g.ShardState.Control.Pos = st.Bytes()

	_, err = f.exec(g, f.block(g, 11, 1_010, nil))
	require.ErrorIs(t, err, storage.ErrClosureMissing, "the duty is on")

	asg := [32]byte{0xa5}
	ids := []evmassign.Identity{f.k[0], f.k[1]}
	vrDomain := evmassign.Deployment{NetworkWord: f.dep.NetworkWord, ChainID: f.dep.ChainID, Custody: f.dep.Registry}
	closure := func(domain evmassign.Deployment) rctypes.PosControl {
		ed, err := evmassign.AssignmentExposureDigest(domain, asg, ids)
		require.NoError(t, err)
		kd, err := evmassign.KeyHistoryDigest(ids)
		require.NoError(t, err)
		hRec, tRoot := [32]byte{0x4a}, [32]byte{0x7e}
		data := storage.ClosureData{AssignmentID: asg, HRound: 5, HRecordID: hRec, TerminalRoot: tRoot, ExposureDigest: ed, KeyHistoryDigest: kd}.Encode()
		bundle := []byte("bundle")
		f.witnesses[sha256.Sum256(bundle)] = bundle
		f.svc.Authority = vxClosures{facts: storage.ClosureFacts{ClosedEpoch: 0, BundleID: [32]byte{0xb0}, HRecordID: hRec, HRound: 5, TerminalRoot: tRoot,
			AssignmentID: asg, Closed: ids}}
		return rctypes.PosControl{Registry: true, Network: vxNetwork, ChainID: f.dep.ChainID, Custody: f.dep.Registry, OrderingEpoch: 1, OrderingRound: 11,
			Op: rctypes.OpCloseLiability, Close: &rctypes.CloseContext{ClosedEpoch: 0, BundleSemanticID: [32]byte{0xb0}}, Data: data, WitnessHash: sha256.Sum256(bundle)}
	}
	custody := vrDomain
	custody.Custody = [20]byte{19: 5}
	_, err = f.exec(g, f.block(g, 11, 1_010, nil, closure(custody)))
	require.ErrorIs(t, err, storage.ErrPosControlRefused, "the custody-domain digest")
	b := f.must(g, f.block(g, 11, 1_010, nil, closure(vrDomain)))
	require.Len(t, b.ShardState.Records, 1)
	require.Equal(t, rootrecords.KindClosure, b.ShardState.Records[0].Kind)
	require.Empty(t, posState(t, b).Awaiting)
}

// The Freeze companion filter of a VR chain: an exact-recovery V3 companion is the base authority's (recovery remains, DeriveRecovery),
// a primary V3 companion, a V4 or a legacy companion is refused before any authority sees it.
func TestVRFreezeCompanionFilter(t *testing.T) {
	f := newVXFixture(t)
	v5 := vradmit.V5Of(f.cand)
	recovery := v5
	recovery.Kind, recovery.PoPs, recovery.ReplacedAssignment = evmassign.KindRecovery, nil, vxReplaced[:]
	companion := func(c evmassign.Candidate) []byte {
		pre, err := c.Encode()
		require.NoError(t, err)
		raw, err := storage.FreezeV3Authorization{Version: 3, Body: []byte{1}, Parent: f.parentEV, Candidate: make([]byte, 32), Preimage: pre,
			Signatures: map[string]hex.Bytes{"r1": {1}}}.Bytes()
		require.NoError(t, err)
		return raw
	}
	r := f.record("freeze", 0, 12)
	f.auth.FreezeParent = f.parentEV
	parent, err := storage.VRFreezeForTest(f.auth, f.svc.Registry, r, companion(recovery))
	require.NoError(t, err)
	require.Equal(t, f.parentEV, parent)
	require.Equal(t, 1, f.auth.FreezeCalls, "the exact recovery is the base authority's")

	_, err = storage.VRFreezeForTest(f.auth, f.svc.Registry, r, companion(v5))
	require.ErrorIs(t, err, storage.ErrVRFreeze, "a primary needs Freeze v5")
	_, err = storage.VRFreezeForTest(f.auth, f.svc.Registry, r, []byte{0x82, 0x04, 0x40})
	require.ErrorIs(t, err, storage.ErrVRFreeze)
	require.Equal(t, 1, f.auth.FreezeCalls)
}

// The acknowledgement of a VR generation (design sections 4.1, 4.3): Ack immediately followed by the result's Boundary with the staged
// bitmap; the acknowledged result moves to R and J's staged commitments materialize. On recovery: RecoveryAck and a recovered Boundary
// (installedRootEpoch = changesEpoch + 1), the table pruned to K's bindings and the staged commitments dropped.
func TestVRAcknowledgementProjectsTheBoundary(t *testing.T) {
	f := newVXFixture(t)
	rule := vrschema.RuleID("fork-a")
	v5 := vradmit.V5Of(f.cand)
	jRaw, err := v5.Encode()
	require.NoError(t, err)
	rec := v5
	rec.Kind, rec.Identities, rec.PoPs, rec.ReplacedAssignment = evmassign.KindRecovery, f.k, nil, vxReplaced[:]
	kRaw, err := rec.Encode()
	require.NoError(t, err)
	jBody, kBody := [32]byte{0xb1}, [32]byte{0xb2}
	f.candidates[string(jBody[:])], f.candidates[string(kBody[:])] = jRaw, kRaw

	vr := vradmit.GenesisRootState(2, 4)
	vr.Support, err = vr.Support.Add(f.commitment(f.k[3], rule), f.commitment(f.k[0], rule)) // member 4 leaves with J
	require.NoError(t, err)
	staged, err := vradmit.SupportTable{}.Add(f.commitment(f.identity(5), rule))
	require.NoError(t, err)
	vr.StagedBody, vr.StagedResult, vr.StagedBitmap, vr.StagedSupport = jBody, f.r, 0b10, staged

	// primary
	st := rootrecords.NewState(1, 1)
	st, err = st.Commit(20, 2, 60, true, jBody)
	require.NoError(t, err)
	st, err = st.Block(2, 60)
	require.NoError(t, err)
	recs, after, vrAfter, err := storage.AckVRForTest(st, vr, f.candidates, 61, 2_000, 4)
	require.NoError(t, err)
	require.Len(t, recs, 2)
	require.Equal(t, rootrecords.KindAck, recs[0].Kind)
	require.Equal(t, rootrecords.KindBoundary, recs[1].Kind)
	require.Equal(t, recs[0].Progress, recs[1].Progress, "the Boundary follows at the same anchor")
	require.Equal(t, f.r[:], recs[1].Data[:32])
	require.EqualValues(t, 0, recs[1].Data[191], "not recovered")
	require.EqualValues(t, 0b10, recs[1].Data[223], "the staged rejectedBitmap")
	require.Empty(t, after.Pending)
	require.Equal(t, f.r, vrAfter.Acknowledged)
	require.Zero(t, vrAfter.StagedBody)
	var ids [][]byte
	for _, e := range vrAfter.Support.Entries {
		ids = append(ids, e.StakingID)
	}
	require.Equal(t, [][]byte{f.k[0].StakingID, f.identity(5).StakingID}, ids, "member 4 pruned, member 5's staged commitment materialized")

	// recovery: J and its recovery K pending
	st = rootrecords.NewState(1, 1)
	st, err = st.Commit(20, 2, 60, true, jBody)
	require.NoError(t, err)
	st, err = st.Block(2, 60)
	require.NoError(t, err)
	st, err = st.Commit(70, 3, 100, true, kBody)
	require.NoError(t, err)
	st, err = st.Block(3, 100)
	require.NoError(t, err)
	recs, _, vrAfter, err = storage.AckVRForTest(st, vr, f.candidates, 101, 3_000, 5)
	require.NoError(t, err)
	require.Len(t, recs, 2)
	require.Equal(t, rootrecords.KindRecoveryAck, recs[0].Kind)
	require.Equal(t, rootrecords.KindBoundary, recs[1].Kind)
	require.EqualValues(t, 1, recs[1].Data[191], "recovered")
	require.Equal(t, f.r, vrAfter.Acknowledged)
	ids = nil
	for _, e := range vrAfter.Support.Entries {
		ids = append(ids, e.StakingID)
	}
	require.Equal(t, [][]byte{f.k[0].StakingID, f.k[3].StakingID}, ids, "K keeps its bindings; J's staged commitments are dropped")

	// an acknowledgement of anything but the staged primary is refused
	other := vr
	other.StagedBody = [32]byte{0xb9}
	_, _, _, err = storage.AckVRForTest(st, other, f.candidates, 101, 3_000, 5)
	require.ErrorIs(t, err, storage.ErrPosSource)
}
