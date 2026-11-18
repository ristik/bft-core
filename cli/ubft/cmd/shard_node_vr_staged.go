package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/unicitynetwork/bft-core/shardnode"
)

// maxVRStaged bounds the staged set a shard node takes from its paired root: the registry's committee ceiling.
const maxVRStaged = 16

// vrStagedRequest is what the paired root tells its shard node: the EVM node ids of the successor the committed handoff intent names (an empty
// list when no intent is active) for the shard epoch that assignment would install (the installed one + 1), under a generation stamp the shard
// orders updates by. IDs is a pointer: a body without it is not a clear.
type vrStagedRequest struct {
	ShardEpoch *uint64   `json:"shardEpoch"`
	Stamp      *uint64   `json:"stamp"`
	IDs        *[]string `json:"ids"`
}

// vrStagedEndpoint is the shard node's loopback endpoint for the VR handoff's staged successor (VT-09b). The paired root posts the EVM
// validators of the derived intent's successor from the intent's derivation on, re-posts the desired set periodically (a restarted shard node
// learns it again) and posts an empty list when the intent dies. They become the shard node's staged peers (shardnode.ActivePeers): inbound
// access to its journal suffixes, archive reads, records and relayed certificates, never archive publication. Nothing else changes: the set
// is read access to certified data only, replaced wholesale by a newer generation, never by an older one or one for an assignment that is not
// the next, cleared by the next installed assignment, bounded to the committee ceiling, and reachable from a loopback peer only, whatever the
// operator allowlist says. A body that is missing, malformed, followed by anything, or lacking any of its three fields changes nothing (only an explicit empty list clears).
type vrStagedEndpoint struct {
	stage func(shardEpoch, stamp uint64, ids []string) error
}

func (e vrStagedEndpoint) register(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/vr/staged", func(w http.ResponseWriter, r *http.Request) {
		if !localOperatorRequest(w, r) {
			return
		}
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if ip := net.ParseIP(host); err != nil || ip == nil || !ip.IsLoopback() {
			http.Error(w, "the staged successor is set from a loopback peer only", http.StatusForbidden)
			return
		}
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16))
		dec.DisallowUnknownFields()
		var req vrStagedRequest
		// exactly one complete object, with all three fields present (null is not present); a legitimate clear carries shardEpoch 0
		if err := dec.Decode(&req); err != nil || req.IDs == nil || req.ShardEpoch == nil || req.Stamp == nil {
			http.Error(w, "a staged-successor request is one JSON object with shardEpoch, stamp and ids", http.StatusBadRequest)
			return
		}
		if _, err := dec.Token(); !errors.Is(err, io.EOF) {
			http.Error(w, "a staged-successor request is exactly one JSON object", http.StatusBadRequest)
			return
		}
		if len(*req.IDs) > maxVRStaged {
			http.Error(w, fmt.Sprintf("%d staged nodes (at most %d)", len(*req.IDs), maxVRStaged), http.StatusBadRequest)
			return
		}
		if err := e.stage(*req.ShardEpoch, *req.Stamp, *req.IDs); err != nil {
			status := http.StatusUnprocessableEntity
			if errors.Is(err, shardnode.ErrActivePeersStale) {
				status = http.StatusConflict
			}
			http.Error(w, err.Error(), status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{}\n"))
	})
}
