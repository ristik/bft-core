package cmd

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"

	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/q3active"
	"github.com/unicitynetwork/bft-core/rootchain/consensus"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
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
	// ShardConfig is the shard configuration this root's derived index holds for a shard epoch of the (whole-partition) shard of a partition: the file an
	// authority is advanced into (`signing-authority advance-epoch --shard-conf`). Nil: the endpoint refuses.
	ShardConfig func(partition types.PartitionID, shard types.ShardID, epoch uint64) (*types.PartitionDescriptionRecord, error)
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
	mux.HandleFunc("POST /api/v1/q3/shard-conf", q3BodyEndpoint(func(_ context.Context, raw json.RawMessage) (any, error) {
		var req struct {
			Partition *uint32 `json:"partition"`
			Shard     string  `json:"shard"`
			Epoch     *uint64 `json:"epoch"`
		}
		if err := json.Unmarshal(raw, &req); err != nil || req.Partition == nil || req.Epoch == nil {
			return nil, q3BadRequest{errors.New("the body must be a JSON object with partition and epoch (and optionally shard)")}
		}
		in := q3ShardConfRequest{Partition: *req.Partition, Shard: req.Shard, Epoch: *req.Epoch}
		if a.ShardConfig == nil {
			return nil, errors.New("this root serves no shard configurations")
		}
		var shard types.ShardID
		if in.Shard != "" {
			if len(in.Shard) > maxShardTextLen {
				return nil, fmt.Errorf("shard: more than %d characters", maxShardTextLen)
			}
			if err := shard.UnmarshalText([]byte(in.Shard)); err != nil {
				return nil, fmt.Errorf("shard: %w", err)
			}
		}
		pdr, err := a.ShardConfig(types.PartitionID(in.Partition), shard, in.Epoch)
		if err != nil {
			return nil, q3ServerError{fmt.Errorf("reading the configuration of partition %d shard epoch %d: %w", in.Partition, in.Epoch, err)}
		}
		if pdr == nil { // a successful lookup that found nothing: the only 422 of this route besides invalid input
			return nil, fmt.Errorf("no configuration for partition %d shard epoch %d", in.Partition, in.Epoch)
		}
		return pdr, nil
	}))
}

// maxShardTextLen bounds the hex text of a ShardID a request carries (the longest id is far shorter; the bound is before any decoding).
const maxShardTextLen = 128

type q3ShardConfRequest struct {
	Partition uint32 `json:"partition"`
	Shard     string `json:"shard,omitempty"` // the ShardID in hex text form; empty: the unsplit shard
	Epoch     uint64 `json:"epoch"`
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
	CandidateDigest string  `json:"candidateDigest"`
	BodyID          string  `json:"bodyId"`
	Attempt         *uint64 `json:"attempt"` // a pointer: attempt zero is a value, an absent field is not
	Config          string  `json:"config"`
}

// q3StatusResponse is what a validator's BFT node reports about itself: the chain it is bound to and the candidate it has staged.
type q3StatusResponse struct {
	Network     uint64            `json:"network"`
	Genesis     string            `json:"genesis"`
	Staged      *q3StagedResponse `json:"staged,omitempty"`
	ActiveEpoch uint64            `json:"activeEpoch"`
	Follower    bool              `json:"follower,omitempty"` // this root is not in the installed committee: it follows, stages and signs nothing
	// Switch is the in-process epoch switch (#1086), present when this root switches in process: the drive waits for it instead of
	// restarting the root
	Switch *q3SwitchResponse `json:"switch,omitempty"`
}

// q3SwitchResponse is the in-process epoch switch's state: running, switching, following or faulted, the epoch of the published context
// and the target of the last switch.
type q3SwitchResponse struct {
	Phase  string `json:"phase"`
	Epoch  uint64 `json:"epoch"`
	Target uint64 `json:"target,omitempty"`
	TookMs int64  `json:"tookMs,omitempty"`
	Error  string `json:"error,omitempty"`
	// Declined is a committed activation this root does not switch into in process (it installs across a restart), and why
	Declined       uint64 `json:"declined,omitempty"`
	DeclinedReason string `json:"declinedReason,omitempty"`
	// Acquires says a root that does not hold the commit itself (a joiner, a follower, a lagging member) also switches in process, from an
	// activation a root peer serves (#1086, PR 2); without it such a root installs across a restart
	Acquires bool `json:"acquires,omitempty"`
}

func (a rootQ3API) statusResponse() (q3StatusResponse, error) {
	st, err := a.Status()
	if err != nil {
		return q3StatusResponse{}, err
	}
	out := q3StatusResponse{Network: st.Network, Genesis: hex.EncodeToString(st.Genesis[:]), ActiveEpoch: st.ActiveEpoch, Follower: st.Follower}
	if st.InProcessSwitch {
		out.Switch = &q3SwitchResponse{Phase: st.Switch.Phase.String(), Epoch: st.Switch.Epoch, Target: st.Switch.Target,
			TookMs: st.Switch.Took.Milliseconds(), Error: st.Switch.Err, Declined: st.Switch.Declined, DeclinedReason: st.Switch.DeclinedReason,
			Acquires: st.AcquiresActivations}
	}
	if st.Staged != nil {
		out.Staged = &q3StagedResponse{CandidateDigest: hex.EncodeToString(st.Staged.CandidateDigest[:]),
			BodyID: hex.EncodeToString(st.Staged.BodyID[:]), Attempt: &st.Staged.Attempt, Config: hex.EncodeToString(st.Staged.Config[:])}
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
	out := q3SignersResponse{Epoch: qc.VoteInfo.Epoch, Round: qc.VoteInfo.RoundNumber, Scheme: effectiveScheme(qc.Scheme), Threshold: tb.QuorumThreshold}
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

// q3ServerError marks a failure of the read itself (a store error), as opposed to invalid input or a clean miss (both 422).
type q3ServerError struct{ error }

func (e q3ServerError) Unwrap() error { return e.error }

// q3BadRequest marks a request that is not well formed (a missing or invalid body): 400, not a lookup.
type q3BadRequest struct{ error }

func (e q3BadRequest) Unwrap() error { return e.error }

// q3Endpoint wraps a read function as a local-operator JSON endpoint; a missing or invalid body is read as an empty object.
func q3Endpoint(f func(ctx context.Context, body json.RawMessage) (any, error)) http.HandlerFunc {
	return q3Handler(f, false)
}

// q3BodyEndpoint is q3Endpoint for a read that needs its body: a missing or invalid one is a 400.
func q3BodyEndpoint(f func(ctx context.Context, body json.RawMessage) (any, error)) http.HandlerFunc {
	return q3Handler(f, true)
}

func q3Handler(f func(ctx context.Context, body json.RawMessage) (any, error), bodyRequired bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !localOperatorRequest(w, r) {
			return
		}
		var body json.RawMessage
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16))
		err := dec.Decode(&body)
		if err == nil && bodyRequired {
			// exactly one JSON value: anything after it (but whitespace) makes the request malformed
			var extra json.RawMessage
			if again := dec.Decode(&extra); again != io.EOF {
				err = errors.New("trailing data after the JSON body")
			}
		}
		if err != nil {
			if bodyRequired {
				http.Error(w, "the request body is missing, is not JSON, or has data after the JSON value", http.StatusBadRequest)
				return
			}
			body = json.RawMessage(`{}`)
		}
		out, err := f(r.Context(), body)
		if err != nil {
			status := http.StatusUnprocessableEntity
			switch {
			case errors.As(err, new(q3ServerError)):
				status = http.StatusInternalServerError // the read itself failed: a reader retries, it does not conclude the answer is "none"
			case errors.As(err, new(q3BadRequest)):
				status = http.StatusBadRequest
			}
			http.Error(w, fmt.Sprint(err), status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	}
}

// effectiveScheme is the signing scheme a certificate is verified under: the wire carries no scheme for a legacy one (0), which is scheme 1.
func effectiveScheme(wire uint64) uint64 {
	if wire == votesig.SchemeDomainBound {
		return votesig.SchemeDomainBound
	}
	return votesig.SchemeLegacy
}
