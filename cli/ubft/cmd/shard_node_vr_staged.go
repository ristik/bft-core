package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// maxVRStaged bounds the staged set a shard node takes from its paired root: the registry's committee ceiling.
const maxVRStaged = 16

// vrStagedRequest is what the paired root tells its shard node: the EVM node ids of the successor the committed handoff intent names (an empty
// list when no intent is active).
type vrStagedRequest struct {
	IDs []string `json:"ids"`
}

// vrStagedEndpoint is the shard node's loopback endpoint for the VR handoff's staged successor (VT-09b). The paired root posts the EVM
// validators of the derived intent's successor from the intent's derivation on and posts an empty list when the intent dies. They become the
// shard node's staged peers (shardnode.ActivePeers.Stage): inbound peers that may fetch its journal suffixes, archive blocks, records and
// relayed certificates, so a joiner's shard node can catch its EVM chain up before its own assignment is installed. Nothing else changes: the
// set is read access to certified data only, replaced wholesale by the next call, cleared by the next installed assignment, bounded to the
// committee ceiling, and reachable from the local operator only (q3Endpoint). It never touches the installed set.
type vrStagedEndpoint struct {
	stage func(ids []string) error
}

func (e vrStagedEndpoint) register(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/vr/staged", q3Endpoint(func(_ context.Context, raw json.RawMessage) (any, error) {
		var req vrStagedRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, err
		}
		if len(req.IDs) > maxVRStaged {
			return nil, fmt.Errorf("%w: %d staged nodes (at most %d)", ErrVRHandoffCmd, len(req.IDs), maxVRStaged)
		}
		if err := e.stage(req.IDs); err != nil {
			return nil, err
		}
		return struct{}{}, nil
	}))
}
