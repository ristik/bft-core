package storage

import (
	"crypto"
	"log/slog"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/evmroot"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootrecords"
	"github.com/unicitynetwork/bft-core/vradmit"
	"github.com/unicitynetwork/bft-go-base/types"
)

// VerifyFreezeAssignmentForTest drives the EVM-state-dependent half of freeze admission from the external test package.
var VerifyFreezeAssignmentForTest = verifyFreezeAssignment

// VerifyPrimaryProofForTest drives the primary candidate's EVM-proof admission from the external test package.
var VerifyPrimaryProofForTest = verifyPrimaryProof

// FreezeV4VersionForTest is the version byte of the proof-bearing Freeze companion.
const FreezeV4VersionForTest = freezeV4Version

// RejectForTest runs one RejectResult control through the control executor: the PoS record state before it, the handoff control state after
// the block's handoff record, and the EVM state the parent certified. It returns the replaced control state, the projected records and the
// PoS record state after it.
func RejectForTest(state rootrecords.State, control *evmroot.ControlState, latestRoot [32]byte, latestBlock []byte, block *rctypes.BlockData,
	c rctypes.PosControl, svc *PosServices) (*evmroot.ControlState, []rootrecords.Record, rootrecords.State, error) {
	step := posStep{on: true, state: state}
	block.Payload.PosControls = []rctypes.PosControl{c}
	replaced, err := step.controls(block, svc, posEnv{Control: control, LatestEVMRoot: latestRoot, LatestEVMBlock: latestBlock, LatestEVMOK: true})
	return replaced, step.records, step.state, err
}

// TestVRAuthority is a handoff authority for the VR-mode executor tests of the external package: it names the predecessor body, the old
// root committee and the successor-body link, and admits a recovery companion by answering FreezeParent (it records the calls).
type TestVRAuthority struct {
	Pred         []byte
	Root         []evmassign.RootMember
	Link         []byte
	FreezeParent []byte
	FreezeErr    error
	FreezeCalls  int
}

func (a *TestVRAuthority) Predecessor() []byte { return a.Pred }
func (a *TestVRAuthority) VerifyFreeze(evmroot.OrderedHandoffRecord, []byte) ([]byte, error) {
	a.FreezeCalls++
	return a.FreezeParent, a.FreezeErr
}
func (a *TestVRAuthority) VerifyAbort(evmroot.OrderedHandoffRecord, []byte) error { return nil }
func (a *TestVRAuthority) CurrentRoot() []evmassign.RootMember                    { return a.Root }
func (a *TestVRAuthority) vrSuccessorLink(uint64, uint64) ([]byte, error)         { return a.Link, nil }

// ExtendForTest executes block on parent through the real block executor with the given authority, retained candidates and services.
func ExtendForTest(parent *ExecutedBlock, block *rctypes.BlockData, orch Orchestration, a *TestVRAuthority,
	candidates interface{ HandoffCandidate([]byte) ([]byte, error) }, svc *PosServices) (*ExecutedBlock, error) {
	var auth handoffAuthority
	if a != nil {
		auth = a
	}
	return parent.extendWithAuthority(block, nil, orch, crypto.SHA256, slog.New(slog.DiscardHandler), auth, candidates, svc, nil)
}

// VRRetainedForTest is what an executed block retains for an admitted Freeze v5.
func VRRetainedForTest(b *ExecutedBlock) (body, receipts, v5, v6 []byte, ok bool) {
	if b.vrFrozen == nil {
		return nil, nil, nil, nil, false
	}
	return b.vrFrozen.Body, b.vrFrozen.Receipts, b.vrFrozen.V5, b.vrFrozen.V6, true
}

// NewMockOrchestrationForTest is the internal mock orchestration for the external tests: a fixed configuration schedule and the
// acknowledged identities of the shard.
func NewMockOrchestrationForTest(confs func(uint64) (map[types.PartitionShardID]*types.PartitionDescriptionRecord, error),
	ids func() ([]evmassign.Identity, [32]byte)) Orchestration {
	return mockOrchestration{shardConfigs: confs, identities: ids}
}

// AckVRForTest projects the VR acknowledgement of the pending handoffs of state over the VR root state vr: the records, and both states after.
func AckVRForTest(state rootrecords.State, vr vradmit.RootState, candidates interface{ HandoffCandidate([]byte) ([]byte, error) }, round, timestamp,
	evmEpoch uint64) ([]rootrecords.Record, rootrecords.State, vradmit.RootState, error) {
	p := posStep{on: true, state: state}
	v := vrStep{on: true, state: vr}
	err := p.ackVR(&v, candidates, round, timestamp, evmEpoch)
	return p.records, p.state, v.state, err
}

// VRFreezeForTest runs the companion filter of a VR chain's handoff authority over base: a Freeze v5 is judged with the VR services, an
// exact-recovery V3 companion is handed to base, anything else is refused.
func VRFreezeForTest(base *TestVRAuthority, svc *VRServices, r evmroot.OrderedHandoffRecord, companion []byte) ([]byte, error) {
	v := vrStep{on: true}
	a := &vrFreezeAuthority{handoffAuthority: base, vr: &v, svc: svc}
	return a.VerifyFreeze(r, companion)
}

// InstallCommittedForTest runs the committed-handoff install of an epoch switch (InstallEpochAnchor's and the startup repair's) over the
// given retained artifacts: oldRoot is the old epoch's committed checkpoint block, record the committed H.
func InstallCommittedForTest(artifacts interface {
	HandoffBody([]byte) ([]byte, error)
	HandoffCandidate([]byte) ([]byte, error)
	HandoffVRCandidate([]byte) ([]byte, error)
}, orch Orchestration, oldRoot *ExecutedBlock, record evmroot.OrderedHandoffRecord) error {
	return installCommittedAssignmentFrom(testArtifacts{artifacts: artifacts}, orch, crypto.SHA256, oldRoot, record, record.OrderedRound)
}

// testArtifacts is a PersistentStore that holds only the retained handoff artifacts.
type testArtifacts struct {
	PersistentStore
	artifacts interface {
		HandoffBody([]byte) ([]byte, error)
		HandoffCandidate([]byte) ([]byte, error)
		HandoffVRCandidate([]byte) ([]byte, error)
	}
}

func (a testArtifacts) HandoffBody(id []byte) ([]byte, error) { return a.artifacts.HandoffBody(id) }
func (a testArtifacts) HandoffCandidate(id []byte) ([]byte, error) {
	return a.artifacts.HandoffCandidate(id)
}
func (a testArtifacts) HandoffVRCandidate(id []byte) ([]byte, error) {
	return a.artifacts.HandoffVRCandidate(id)
}

// ExpectedCommitTRForTest is the successor technical record hash a Commit of record must bind for the frozen shard state si.
func ExpectedCommitTRForTest(candidates interface{ HandoffCandidate([]byte) ([]byte, error) }, record evmroot.OrderedHandoffRecord, si *ShardInfo) ([]byte, error) {
	return expectedCommitSuccessorTR(candidates, record, si, crypto.SHA256)
}

// DerivedChangeShardsForTest names the existing shards the committed candidate of record replaces the configuration of, read from the
// candidate source the executor is given.
func DerivedChangeShardsForTest(candidates interface{ HandoffCandidate([]byte) ([]byte, error) }, record evmroot.OrderedHandoffRecord) (map[types.PartitionShardID]struct{}, error) {
	return derivedChangeShards(candidates, record)
}

// RetainVRFreezeForTest retains what the executed Freeze v5 block admitted into the store, exactly as BlockStore.Add does on the
// admitting root.
func RetainVRFreezeForTest(s *BlockStore, block *rctypes.BlockData, executed *ExecutedBlock) error {
	return s.retainVRFreeze(block, executed.vrFrozen)
}
