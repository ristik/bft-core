package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/internal/testutils/logger"
	"github.com/unicitynetwork/bft-core/rootchain/partitions"
	"github.com/unicitynetwork/bft-core/rootchain/testutils"
	"github.com/unicitynetwork/bft-go-base/types"
)

// An operator must be able to obtain the shard configuration an authority is advanced into from a RUNNING root (the lane read the root's orchestration.db with
// `go run ./scripts/h3-pdr`, which is no operator command and not in the node image): the loopback-guarded q3/shard-conf endpoint and `ubft q3 shard-conf`.
func TestShardConfEndpointAndCommandReturnTheConfigurationTheRootHoldsForAShardEpoch(t *testing.T) {
	o, err := partitions.NewOrchestration(5, filepath.Join(t.TempDir(), "orchestration.db"), logger.New(t))
	require.NoError(t, err)
	t.Cleanup(func() { _ = o.Close() })
	node := testutils.NewTestNode(t)
	pdr := &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: 8, PartitionTypeID: 99, ShardID: types.ShardID{}, UnitIDLen: 256, TypeIDLen: 32,
		T2Timeout: 2500 * time.Millisecond, Epoch: 0, EpochStart: 1, Validators: []*types.NodeInfo{node.NodeInfo(t)}}
	require.NoError(t, o.AddShardConfig(pdr))
	api := rootQ3API{ShardConfig: o.ShardConfigByEpoch}
	want, err := o.ShardConfigByEpoch(8, types.ShardID{}, 0)
	require.NoError(t, err)
	wantJSON, err := json.Marshal(want)
	require.NoError(t, err)

	t.Run("the endpoint is loopback-only and refuses an unknown epoch", func(t *testing.T) {
		rec := callQ3(t, api, "/api/v1/q3/shard-conf", "127.0.0.1:1", q3ShardConfRequest{Partition: 8, Epoch: 0})
		require.Equal(t, http.StatusOK, rec.Code)
		require.JSONEq(t, string(wantJSON), rec.Body.String())
		require.Equal(t, http.StatusForbidden, callQ3(t, api, "/api/v1/q3/shard-conf", "10.0.0.5:1", q3ShardConfRequest{Partition: 8, Epoch: 0}).Code)
		require.Equal(t, http.StatusUnprocessableEntity, callQ3(t, api, "/api/v1/q3/shard-conf", "127.0.0.1:1", q3ShardConfRequest{Partition: 8, Epoch: 7}).Code)
		require.Equal(t, http.StatusUnprocessableEntity, callQ3(t, api, "/api/v1/q3/shard-conf", "127.0.0.1:1", q3ShardConfRequest{Partition: 9, Epoch: 0}).Code)
		require.Equal(t, http.StatusUnprocessableEntity, callQ3(t, rootQ3API{}, "/api/v1/q3/shard-conf", "127.0.0.1:1", q3ShardConfRequest{Partition: 8}).Code, "a root without the index refuses")
	})
	t.Run("the command writes what the root holds, private, and fails for an epoch it does not have", func(t *testing.T) {
		mux := http.NewServeMux()
		api.register(mux)
		server := httptest.NewServer(mux)
		defer server.Close()
		out := filepath.Join(t.TempDir(), "pdr.json")
		run := func(epoch string) error {
			cmd := newQ3Cmd()
			cmd.SetOut(&bytes.Buffer{})
			cmd.SetErr(&bytes.Buffer{})
			cmd.SetArgs([]string{"shard-conf", "--root-rpc", server.URL, "--epoch", epoch, "--out", out})
			return cmd.Execute()
		}
		require.NoError(t, run("0"))
		written, err := os.ReadFile(out)
		require.NoError(t, err)
		require.JSONEq(t, string(wantJSON), string(written))
		var encoded bytes.Buffer
		require.NoError(t, json.NewEncoder(&encoded).Encode(want))
		require.Equal(t, encoded.String(), string(written), "the same bytes `go run ./scripts/h3-pdr` printed (json.Encoder of the same value)")
		var decoded types.PartitionDescriptionRecord
		require.NoError(t, json.Unmarshal(written, &decoded))
		require.Equal(t, want.EpochStart, decoded.EpochStart)
		info, err := os.Stat(out)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
		require.Error(t, run("9"))
	})
}

// A shard's aggregator follows a kind 6 or 8 change by reading the successor configuration of its own shard over the root's loopback RPC: the
// source-guarded endpoint is shard-aware (the split shards of a partition hold separate histories), bounds its input, and answers only what is stored.
func TestShardConfEndpointIsShardAwareAndSourceGuarded(t *testing.T) {
	o, err := partitions.NewOrchestration(5, filepath.Join(t.TempDir(), "orchestration.db"), logger.New(t))
	require.NoError(t, err)
	t.Cleanup(func() { _ = o.Close() })
	node := testutils.NewTestNode(t)
	left, right := types.ShardID{}.Split()
	mk := func(shard types.ShardID, epoch uint64, timeout time.Duration) *types.PartitionDescriptionRecord {
		start := uint64(1)
		if epoch > 0 {
			start = 100 * epoch
		}
		return &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: 8, PartitionTypeID: 99, ShardID: shard, UnitIDLen: 256, TypeIDLen: 32,
			T2Timeout: timeout, Epoch: epoch, EpochStart: start, Validators: []*types.NodeInfo{node.NodeInfo(t)}}
	}
	for _, p := range []*types.PartitionDescriptionRecord{mk(left, 0, 2*time.Second), mk(right, 0, 3*time.Second), mk(left, 1, 4*time.Second)} {
		require.NoError(t, o.AddShardConfig(p))
	}
	api := rootQ3API{ShardConfig: o.ShardConfigByEpoch}
	leftText, _ := left.MarshalText()
	rightText, _ := right.MarshalText()
	ask := func(remote string, req q3ShardConfRequest) *httptest.ResponseRecorder {
		return callQ3(t, api, "/api/v1/q3/shard-conf", remote, req)
	}
	var got types.PartitionDescriptionRecord
	rec := ask("127.0.0.1:1", q3ShardConfRequest{Partition: 8, Epoch: 1, Shard: string(leftText)})
	require.Equal(t, http.StatusOK, rec.Code)
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	require.EqualValues(t, 1, got.Epoch)
	require.True(t, got.ShardID.Equal(left))
	require.Equal(t, 4*time.Second, got.T2Timeout)
	rec = ask("127.0.0.1:1", q3ShardConfRequest{Partition: 8, Epoch: 0, Shard: string(rightText)})
	require.Equal(t, http.StatusOK, rec.Code)
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	require.True(t, got.ShardID.Equal(right))
	require.Equal(t, http.StatusUnprocessableEntity, ask("127.0.0.1:1", q3ShardConfRequest{Partition: 8, Epoch: 1, Shard: string(rightText)}).Code, "the sibling has no epoch 1")
	require.Equal(t, http.StatusUnprocessableEntity, ask("127.0.0.1:1", q3ShardConfRequest{Partition: 8, Epoch: 2, Shard: string(leftText)}).Code, "the next epoch is a clean miss")
	require.Equal(t, http.StatusUnprocessableEntity, ask("127.0.0.1:1", q3ShardConfRequest{Partition: 8, Epoch: 99, Shard: string(leftText)}).Code)
	require.Equal(t, http.StatusUnprocessableEntity, ask("127.0.0.1:1", q3ShardConfRequest{Partition: 8, Epoch: 0}).Code, "the unsplit shard is not this partition's")
	require.Equal(t, http.StatusUnprocessableEntity, ask("127.0.0.1:1", q3ShardConfRequest{Partition: 8, Epoch: 0, Shard: "zz"}).Code)
	require.Equal(t, http.StatusUnprocessableEntity, ask("127.0.0.1:1", q3ShardConfRequest{Partition: 8, Epoch: 0, Shard: strings.Repeat("a", maxShardTextLen+1)}).Code, "the shard text is bounded")
	require.Equal(t, http.StatusForbidden, ask("203.0.113.9:4000", q3ShardConfRequest{Partition: 8, Epoch: 1, Shard: string(leftText)}).Code, "a peer that is not an operator source")
}

// 422 on this route is a successful lookup that found nothing (or invalid input); a failing store is a server error, so a reader retries
// instead of concluding that the configuration does not exist.
func TestShardConfEndpointReportsAStoreFailureAsAServerError(t *testing.T) {
	failing := rootQ3API{ShardConfig: func(types.PartitionID, types.ShardID, uint64) (*types.PartitionDescriptionRecord, error) {
		return nil, errors.New("bolt: database not open")
	}}
	rec := callQ3(t, failing, "/api/v1/q3/shard-conf", "127.0.0.1:1", q3ShardConfRequest{Partition: 8, Epoch: 1})
	require.Equal(t, http.StatusInternalServerError, rec.Code)
	clean := rootQ3API{ShardConfig: func(types.PartitionID, types.ShardID, uint64) (*types.PartitionDescriptionRecord, error) {
		return nil, nil
	}}
	require.Equal(t, http.StatusUnprocessableEntity, callQ3(t, clean, "/api/v1/q3/shard-conf", "127.0.0.1:1", q3ShardConfRequest{Partition: 8, Epoch: 1}).Code)
	require.Equal(t, http.StatusUnprocessableEntity, callQ3(t, clean, "/api/v1/q3/shard-conf", "127.0.0.1:1", q3ShardConfRequest{Partition: 8, Epoch: 1, Shard: "zz"}).Code, "invalid input")
}
