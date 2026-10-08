package consensus

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
)

// PrimaryWitnessSource builds the storage-proof witness of the election and custody state at the frozen EVM parent for a result
// (evmstate.BuildPrimaryWitness over an execution client). It is the leader's side of a primary candidate's EVM proof: nothing it
// returns is trusted, block admission verifies the witness against the parent's certified state root.
type PrimaryWitnessSource interface {
	PrimaryWitness(frozenParent []byte, resultID [32]byte) ([]byte, error)
}

// SetPrimaryWitnessSource installs the witness source. A root of a chain that judges primary candidates needs one to lead their Freeze.
func (x *ConsensusManager) SetPrimaryWitnessSource(s PrimaryWitnessSource) {
	if s == nil {
		x.primaryWitness.Store(nil)
		return
	}
	x.primaryWitness.Store(&s)
}

// primaryFreezeProof returns the canonical PrimaryProof a primary candidate's Freeze must carry, or nil when the chain does not judge
// this candidate. An unavailable witness is an error: the leader orders nothing until the execution client can serve the proof.
func (x *ConsensusManager) primaryFreezeProof(plan *pendingHandoff, frozenParent []byte) ([]byte, error) {
	if len(plan.plan.CandidatePreimage) == 0 || !x.blockStore.PosServices().RequiresPrimaryProof() {
		return nil, nil
	}
	c, err := evmassign.DecodeCandidate(plan.plan.CandidatePreimage)
	if err != nil {
		return nil, errors.Join(ErrHandoffApproval, err)
	}
	return x.primaryProofFor(c, plan.plan.PrimaryPoPs, frozenParent)
}

// primaryProofFor is primaryFreezeProof over a decoded candidate.
func (x *ConsensusManager) primaryProofFor(c evmassign.Candidate, rawPoPs, frozenParent []byte) ([]byte, error) {
	if !x.blockStore.PosServices().RequiresPrimaryProof() || c.Kind != evmassign.KindPrimary {
		return nil, nil
	}
	pops, err := evmassign.DecodePoPs(rawPoPs)
	if err != nil {
		return nil, errors.Join(ErrHandoffApproval, storage.ErrPrimaryProofMissing, err)
	}
	src := x.primaryWitness.Load()
	if src == nil {
		return nil, fmt.Errorf("%w: no witness source configured", storage.ErrWitnessUnavailable)
	}
	witness, err := (*src).PrimaryWitness(bytes.Clone(frozenParent), c.ResultID())
	if err != nil {
		return nil, errors.Join(storage.ErrWitnessUnavailable, err)
	}
	return evmassign.PrimaryProof{Witness: witness, PoPs: pops}.Encode()
}
