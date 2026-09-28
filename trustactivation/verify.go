// Package trustactivation authenticates a successor epoch before its trust
// body can be used to verify shard certificates.
package trustactivation

import (
	"bytes"
	"context"
	"crypto"
	"fmt"

	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/handoff"
	"github.com/unicitynetwork/bft-core/m2contract"
	"github.com/unicitynetwork/bft-core/trusthistorystore"
	"github.com/unicitynetwork/bft-go-base/types"
)

const maxProofBytes = 1 << 20

func proofSizeAllowed(n int) bool { return n > 0 && n <= maxProofBytes }

// Verifier binds the old-set commit proof to the exact next body and the
// actual activation round stored in the trust history.
type Verifier struct{}

func (Verifier) VerifyActivation(_ context.Context, prior trusthistorystore.Record, in m2contract.TrustInterval, proof []byte) error {
	if !proofSizeAllowed(len(proof)) {
		return trusthistorystore.ErrProof
	}
	var p handoff.OldCommitProof
	if err := types.Cbor.Unmarshal(proof, &p); err != nil {
		return fmt.Errorf("%w: %v", trusthistorystore.ErrProof, err)
	}
	canonical, err := types.Cbor.Marshal(p)
	if err != nil || !bytes.Equal(canonical, proof) {
		return trusthistorystore.ErrProof
	}
	old := prior.V1
	var recordPredecessor []byte
	if old == nil {
		old, err = Project(prior)
		if err != nil {
			return fmt.Errorf("%w: %v", trusthistorystore.ErrProof, err)
		}
		recordPredecessor = prior.BodyID[:]
		if !bytes.Equal(in.Body.PredecessorHash, recordPredecessor) {
			return trusthistorystore.ErrProof
		}
	} else {
		recordPredecessor, err = old.Hash(crypto.SHA256)
		if err != nil {
			return fmt.Errorf("%w: %v", trusthistorystore.ErrProof, err)
		}
		link, linkErr := evmroot.FirstV2PredecessorHash(evmroot.V1Anchor{Version: 1, NetworkID: uint64(old.NetworkID), Epoch: old.Epoch, HashIncludingSigs: recordPredecessor})
		if linkErr != nil || !bytes.Equal(in.Body.PredecessorHash, link) {
			return trusthistorystore.ErrProof
		}
	}
	v, err := handoff.VerifyOldCommitProof(p, old)
	if err != nil {
		return fmt.Errorf("%w: %v", trusthistorystore.ErrProof, err)
	}
	id := in.Body.Identity()
	if prior.Epoch == ^uint64(0) || in.Body.Epoch != prior.Epoch+1 || p.Record.Epoch != prior.Epoch ||
		!bytes.Equal(p.Record.NextBodyID, id[:]) || !bytes.Equal(p.Record.PredecessorBodyID, recordPredecessor) ||
		p.Record.ActivationRound != in.Activation.EpochStart || !bytes.Equal(v.RecordID[:], in.Activation.ActivationCommitID) ||
		in.Body.NetworkID != uint64(old.NetworkID) {
		return trusthistorystore.ErrProof
	}
	return nil
}

// Project carries the checked v2 member keys, weights, threshold, and actual
// activation round into the current UC signature verifier. It does not assign
// a v1 identity to the v2 body.
func Project(r trusthistorystore.Record) (*types.RootTrustBaseV1, error) {
	if r.V2 == nil || r.V2.Validate() != nil || r.Start == 0 {
		return nil, trusthistorystore.ErrHistory
	}
	nodes := make([]*types.NodeInfo, len(r.V2.Members))
	for i, m := range r.V2.Members {
		nodes[i] = &types.NodeInfo{NodeID: m.NodeID, SigKey: bytes.Clone(m.ConsensusKey), Stake: m.Weight}
	}
	tb, err := types.NewTrustBase(types.NetworkID(r.V2.NetworkID), nodes, types.WithEpoch(r.Epoch), types.WithEpochStart(r.Start), types.WithQuorumThreshold(r.V2.RootThreshold))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", trusthistorystore.ErrHistory, err)
	}
	return tb, nil
}
