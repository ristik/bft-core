package cmd

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"

	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/q3active"
	"github.com/unicitynetwork/bft-core/rootchain/consensus"
	"github.com/unicitynetwork/bft-go-base/types"
)

// rootQ3API is the read side of a Q3 lane root's operator endpoint: what the lane's commands and its evidence pack ask of one validator.
// Every endpoint is local-operator only, takes a JSON body and answers JSON; none changes state.
type rootQ3API struct {
	Status func() (consensus.Q3Status, error)
	Rt     *q3active.Runtime
	Bundle func(ctx context.Context, epoch uint64) (q3active.Bundle, error)
	State  func() (*abdrc.StateMsg, error)
	Trust  func(epoch uint64) (*types.RootTrustBaseV1, error)
}

func (a rootQ3API) register(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/q3/status", q3Endpoint(func(context.Context, json.RawMessage) (any, error) { return a.statusResponse() }))
	mux.HandleFunc("POST /api/v1/q3/activation", q3Endpoint(func(_ context.Context, raw json.RawMessage) (any, error) {
		var in q3EpochRequest
		if err := json.Unmarshal(raw, &in); err != nil {
			return nil, err
		}
		return a.Rt.ActivationRecord(in.Epoch)
	}))
	mux.HandleFunc("POST /api/v1/q3/bundle", q3Endpoint(func(ctx context.Context, raw json.RawMessage) (any, error) {
		var in q3EpochRequest
		if err := json.Unmarshal(raw, &in); err != nil {
			return nil, err
		}
		b, err := a.Bundle(ctx, in.Epoch)
		if err != nil {
			return nil, err
		}
		enc, err := q3active.EncodeBundle(b)
		if err != nil {
			return nil, err
		}
		return q3BundleResponse{Epoch: in.Epoch, Bundle: hex.EncodeToString(enc)}, nil
	}))
	mux.HandleFunc("POST /api/v1/q3/history", q3Endpoint(func(context.Context, json.RawMessage) (any, error) {
		entries, err := a.Rt.HistoryEntries()
		return q3HistoryResponse{Entries: entries}, err
	}))
	mux.HandleFunc("POST /api/v1/q3/signers", q3Endpoint(func(context.Context, json.RawMessage) (any, error) { return a.signers() }))
}

type q3EpochRequest struct {
	Epoch uint64 `json:"epoch"`
}

type q3BundleResponse struct {
	Epoch  uint64 `json:"epoch"`
	Bundle string `json:"bundle"` // canonical q3active bundle, hex
}

type q3HistoryResponse struct {
	Entries []q3active.HistoryEntry `json:"entries"`
}

type q3StagedResponse struct {
	CandidateDigest string `json:"candidateDigest"`
	BodyID          string `json:"bodyId"`
	Attempt         uint64 `json:"attempt"`
	Config          string `json:"config"`
}

// q3StatusResponse is what a validator's BFT node reports about itself: the chain it is bound to and the candidate it has staged.
type q3StatusResponse struct {
	Network     uint64            `json:"network"`
	Genesis     string            `json:"genesis"`
	Staged      *q3StagedResponse `json:"staged,omitempty"`
	ActiveEpoch uint64            `json:"activeEpoch"`
}

func (a rootQ3API) statusResponse() (q3StatusResponse, error) {
	st, err := a.Status()
	if err != nil {
		return q3StatusResponse{}, err
	}
	out := q3StatusResponse{Network: st.Network, Genesis: hex.EncodeToString(st.Genesis[:]), ActiveEpoch: st.ActiveEpoch}
	if st.Staged != nil {
		out.Staged = &q3StagedResponse{CandidateDigest: hex.EncodeToString(st.Staged.CandidateDigest[:]),
			BodyID: hex.EncodeToString(st.Staged.BodyID[:]), Attempt: st.Staged.Attempt, Config: hex.EncodeToString(st.Staged.Config[:])}
	}
	return out, nil
}

// q3SignersResponse are the signers of the committed head's quorum certificate and the weights they carried in the epoch that verified it.
type q3SignersResponse struct {
	Epoch       uint64            `json:"epoch"`
	Round       uint64            `json:"round"`
	Scheme      uint64            `json:"scheme"`
	Signers     []q3active.Signer `json:"signers"`
	SignedTotal uint64            `json:"signedTotal"`
	Threshold   uint64            `json:"threshold"`
	Quorum      bool              `json:"quorum"`
}

func (a rootQ3API) signers() (q3SignersResponse, error) {
	state, err := a.State()
	if err != nil {
		return q3SignersResponse{}, err
	}
	if state == nil || state.CommittedHead == nil || state.CommittedHead.CommitQc == nil || state.CommittedHead.CommitQc.VoteInfo == nil {
		return q3SignersResponse{}, errors.New("no committed quorum certificate")
	}
	qc := state.CommittedHead.CommitQc
	tb, err := a.Trust(qc.VoteInfo.Epoch)
	if err != nil {
		return q3SignersResponse{}, err
	}
	weights := map[string]uint64{}
	for _, n := range tb.RootNodes {
		weights[n.NodeID] = n.Stake
	}
	out := q3SignersResponse{Epoch: qc.VoteInfo.Epoch, Round: qc.VoteInfo.RoundNumber, Scheme: qc.Scheme, Threshold: tb.QuorumThreshold}
	for id := range qc.Signatures {
		if w, ok := weights[id]; ok {
			out.Signers = append(out.Signers, q3active.Signer{NodeID: id, Weight: w})
			out.SignedTotal += w
		}
	}
	sort.Slice(out.Signers, func(i, j int) bool { return out.Signers[i].NodeID < out.Signers[j].NodeID })
	out.Quorum = out.SignedTotal >= out.Threshold
	return out, nil
}

// q3Endpoint wraps a read function as a local-operator JSON endpoint.
func q3Endpoint(f func(ctx context.Context, body json.RawMessage) (any, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !localOperatorRequest(w, r) {
			return
		}
		var body json.RawMessage
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
			body = json.RawMessage(`{}`)
		}
		out, err := f(r.Context(), body)
		if err != nil {
			http.Error(w, fmt.Sprint(err), http.StatusUnprocessableEntity)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	}
}
