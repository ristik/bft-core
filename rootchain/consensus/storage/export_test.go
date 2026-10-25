package storage

import (
	"github.com/unicitynetwork/bft-core/evmroot"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootrecords"
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
