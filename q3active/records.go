package q3active

import (
	"encoding/hex"
	"errors"
	"fmt"
	"sort"

	"github.com/unicitynetwork/bft-core/handoff"
	"github.com/unicitynetwork/bft-go-base/types"
)

// ErrNoActivation is returned for an epoch this runtime holds no staged activation of.
var ErrNoActivation = errors.New("q3active: no staged activation for the epoch")

// Signer is one signer of a certificate and the weight it carried in the epoch that verified it.
type Signer struct {
	NodeID string `json:"nodeId"`
	Weight uint64 `json:"weight"`
}

// ActivationRecord is the committed activation of an epoch as the verified history holds it, for the acceptance lane's evidence: the
// epoch, its scheme, body and boundary, the identity of the old committee's commit record, and that commit with the signers and weights
// it was verified under (the OLD epoch's, not the new one's).
type ActivationRecord struct {
	Epoch              uint64 `json:"epoch"`
	SigningScheme      uint64 `json:"signingScheme"`
	V3BodyID           string `json:"v3BodyId"`
	ActivationRound    uint64 `json:"activationRound"`    // A*
	MinActivationRound uint64 `json:"minActivationRound"` // A_min
	ActivationCommitID string `json:"activationCommitId"`
	Commit             struct {
		Epoch       uint64   `json:"epoch"`
		Scheme      uint64   `json:"scheme"`
		Signers     []Signer `json:"signers"`
		SignedTotal uint64   `json:"signedTotal"`
		Threshold   uint64   `json:"threshold"`
		Proof       string   `json:"proof"` // canonical OldCommitProof, hex
	} `json:"commit"`
}

// ActivationRecord reads the activation of an epoch from the staged bundle the history was rebuilt from. The proof is re-verified under
// the old epoch's own keys, weights and scheme, and the signers reported are exactly those the verification counted.
func (r *Runtime) ActivationRecord(epoch uint64) (ActivationRecord, error) {
	var out ActivationRecord
	staged, err := r.journal.Staged()
	if err != nil {
		return out, err
	}
	for _, a := range staged {
		if a.Claim.Epoch != epoch {
			continue
		}
		_, env, err := DecodeBundle(a.Bundle)
		if err != nil {
			return out, err
		}
		link := env.Links[len(env.Links)-1]
		entry, err := r.History().ForEpoch(epoch)
		if err != nil {
			return out, err
		}
		prior, err := r.History().ForEpoch(epoch - 1)
		if err != nil {
			return out, err
		}
		var p handoff.OldCommitProof
		if err := types.Cbor.Unmarshal(link.Proof, &p); err != nil {
			return out, fmt.Errorf("%w: %v", ErrBundle, err)
		}
		cfg, err := r.History().Signing(epoch - 1)
		if err != nil {
			return out, err
		}
		if _, err := handoff.VerifyOldCommitProofSigning(p, prior.Projection(), cfg); err != nil {
			return out, fmt.Errorf("%w: %v", ErrHistory, err)
		}
		weights := map[string]uint64{}
		for _, n := range prior.Projection().RootNodes {
			weights[n.NodeID] = n.Stake
		}
		commitID, bodyID := entry.ActivationCommitID(), entry.BodyID()
		out.Epoch, out.SigningScheme = entry.Epoch(), entry.Scheme()
		out.V3BodyID, out.ActivationRound, out.MinActivationRound = hex.EncodeToString(bodyID[:]), entry.Start(), entry.EarliestActivation()
		out.ActivationCommitID = hex.EncodeToString(commitID[:])
		out.Commit.Epoch, out.Commit.Scheme = prior.Epoch(), cfg.Scheme
		out.Commit.Threshold = prior.Projection().QuorumThreshold
		out.Commit.Proof = hex.EncodeToString(link.Proof)
		for id := range p.CommitQC.Signatures {
			w, ok := weights[id]
			if !ok {
				continue // verification counts only members; an outsider's entry carries no weight
			}
			out.Commit.Signers = append(out.Commit.Signers, Signer{NodeID: id, Weight: w})
			out.Commit.SignedTotal += w
		}
		sort.Slice(out.Commit.Signers, func(i, j int) bool { return out.Commit.Signers[i].NodeID < out.Commit.Signers[j].NodeID })
		return out, nil
	}
	return out, fmt.Errorf("%w: %d", ErrNoActivation, epoch)
}

// HistoryEntry is one epoch of the verified history.
type HistoryEntry struct {
	Epoch    uint64 `json:"epoch"`
	BodyID   string `json:"bodyId"`
	CommitID string `json:"commitId,omitempty"`
	Start    uint64 `json:"start"`
	Scheme   uint64 `json:"scheme"`
}

// HistoryEntries is the verified history from the pinned genesis to the tip, in epoch order: the identities another pair compares.
func (r *Runtime) HistoryEntries() ([]HistoryEntry, error) {
	h := r.History()
	var out []HistoryEntry
	for epoch := uint64(1); epoch <= h.Tip().Epoch(); epoch++ {
		e, err := h.ForEpoch(epoch)
		if err != nil {
			return nil, err
		}
		cfg, err := h.Signing(epoch)
		if err != nil {
			return nil, err
		}
		id, commit := e.BodyID(), e.ActivationCommitID()
		he := HistoryEntry{Epoch: epoch, BodyID: hex.EncodeToString(id[:]), Start: e.Start(), Scheme: cfg.Scheme}
		if commit != ([32]byte{}) {
			he.CommitID = hex.EncodeToString(commit[:])
		}
		out = append(out, he)
	}
	return out, nil
}
