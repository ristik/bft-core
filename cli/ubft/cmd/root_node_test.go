package cmd

import (
	"bytes"
	"crypto"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/rootchain/partitions"

	"github.com/unicitynetwork/bft-core/internal/testutils/logger"
	"github.com/unicitynetwork/bft-core/internal/testutils/observability"
	testsig "github.com/unicitynetwork/bft-core/internal/testutils/sig"
	testtb "github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	"github.com/unicitynetwork/bft-core/keyvaluedb/memorydb"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
)

var defaultPDR = &types.PartitionDescriptionRecord{
	Version:         1,
	NetworkID:       types.NetworkLocal,
	PartitionID:     1,
	PartitionTypeID: 1,
	TypeIDLen:       8,
	UnitIDLen:       256,
	T2Timeout:       2500 * time.Millisecond,
}

func Test_rootNodeConfig_getBootStrapNodes(t *testing.T) {
	t.Run("ok: nil", func(t *testing.T) {
		bootNodes, err := getBootStrapNodes(nil)
		require.NoError(t, err)
		require.NotNil(t, bootNodes)
		require.Empty(t, bootNodes)
	})
	t.Run("ok", func(t *testing.T) {
		bootNodes, err := getBootStrapNodes([]string{"/ip4/127.0.0.1/tcp/1366/p2p/16Uiu2HAmLEmba2HMEEMe4NYsKnqKToAgi1FueNJaDiAnLeJpKktz"})
		require.NoError(t, err)
		require.Len(t, bootNodes, 1)
		require.Equal(t, bootNodes[0].ID.String(), "16Uiu2HAmLEmba2HMEEMe4NYsKnqKToAgi1FueNJaDiAnLeJpKktz")
		require.Len(t, bootNodes[0].Addrs, 1)
		require.Equal(t, bootNodes[0].Addrs[0].String(), "/ip4/127.0.0.1/tcp/1366")
	})
	t.Run("multiple nodes ok", func(t *testing.T) {
		bootNodes, err := getBootStrapNodes([]string{
			"/ip4/127.0.0.1/tcp/1366/p2p/16Uiu2HAmLEmba2HMEEMe4NYsKnqKToAgi1FueNJaDiAnLeJpKktz",
			"/ip4/127.0.0.1/tcp/1367/p2p/16Uiu2HAmLEmba2HMEEMe4NYsKnqKToAgi1FueNJaDiAnLeJpKktx",
		})
		require.NoError(t, err)
		require.Len(t, bootNodes, 2)

		require.Equal(t, bootNodes[0].ID.String(), "16Uiu2HAmLEmba2HMEEMe4NYsKnqKToAgi1FueNJaDiAnLeJpKktz")
		require.Len(t, bootNodes[0].Addrs, 1)
		require.Equal(t, bootNodes[0].Addrs[0].String(), "/ip4/127.0.0.1/tcp/1366")

		require.Equal(t, bootNodes[1].ID.String(), "16Uiu2HAmLEmba2HMEEMe4NYsKnqKToAgi1FueNJaDiAnLeJpKktx")
		require.Len(t, bootNodes[1].Addrs, 1)
		require.Equal(t, bootNodes[1].Addrs[0].String(), "/ip4/127.0.0.1/tcp/1367")
	})
}

func Test_cfgHandler(t *testing.T) {
	// helper to set up handler for the case where we expect that the addConfig
	// callback is not called (ie handler fails before there is a reason to call it)
	setupNoCallbackHandler := func(t *testing.T) (http.HandlerFunc, *httptest.ResponseRecorder) {
		return putShardConfigHandler(func(shardConf *types.PartitionDescriptionRecord) error {
				err := fmt.Errorf("unexpected call of addConfig callback with %v", shardConf)
				t.Error(err)
				return err
			}),
			httptest.NewRecorder()
	}

	t.Run("missing request body", func(t *testing.T) {
		hf, w := setupNoCallbackHandler(t)
		hf(w, httptest.NewRequest("PUT", "/api/v1/configurations", nil))
		resp := w.Result()
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.EqualValues(t, http.StatusBadRequest, resp.StatusCode)
		require.Equal(t, `parsing request body: decoding shard conf json: EOF`, string(body))
	})

	t.Run("invalid request body", func(t *testing.T) {
		hf, w := setupNoCallbackHandler(t)
		hf(w, httptest.NewRequest("PUT", "/api/v1/configurations", bytes.NewBufferString("not valid json")))
		resp := w.Result()
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.EqualValues(t, http.StatusBadRequest, resp.StatusCode)
		require.Equal(t, `parsing request body: decoding shard conf json: invalid character 'o' in literal null (expecting 'u')`, string(body))
	})

	shardConfJson, err := json.Marshal(defaultPDR)
	require.NoError(t, err)

	t.Run("config registration fails", func(t *testing.T) {
		hf := putShardConfigHandler(func(shardConf *types.PartitionDescriptionRecord) error {
			return fmt.Errorf("nope, can't add this conf")
		})
		w := httptest.NewRecorder()
		hf(w, httptest.NewRequest("PUT", "/api/v1/configurations", bytes.NewBuffer(shardConfJson)))
		resp := w.Result()
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.EqualValues(t, http.StatusInternalServerError, resp.StatusCode)
		require.Equal(t, `registering shard conf: nope, can't add this conf`, string(body))
	})

	t.Run("success", func(t *testing.T) {
		cbCall := false
		hf := putShardConfigHandler(func(shardConf *types.PartitionDescriptionRecord) error {
			cbCall = true
			require.Equal(t, shardConf, defaultPDR)
			return nil
		})
		w := httptest.NewRecorder()
		hf(w, httptest.NewRequest("PUT", "/api/v1/configurations", bytes.NewBuffer(shardConfJson)))
		resp := w.Result()
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.EqualValues(t, http.StatusOK, resp.StatusCode)
		require.Empty(t, body)
		require.True(t, cbCall, "add configuration callback has not been called")
	})
}

func Test_roundInfoHandler(t *testing.T) {
	t.Run("state provider error", func(t *testing.T) {
		hf := getRoundInfoHandler(func() (*abdrc.StateMsg, error) {
			return nil, fmt.Errorf("some error")
		}, observability.Default(t))
		res, body := doRequest(t, hf, http.MethodGet, "/api/v1/roundInfo")
		require.EqualValues(t, http.StatusInternalServerError, res.StatusCode)
		require.Equal(t, "failed to load state\n", string(body))
		require.Equal(t, "text/plain; charset=utf-8", res.Header.Get("Content-Type"))
	})

	t.Run("ok", func(t *testing.T) {
		hf := getRoundInfoHandler(func() (*abdrc.StateMsg, error) {
			return &abdrc.StateMsg{
				CommittedHead: &abdrc.CommittedBlock{
					ShardInfo: []abdrc.ShardInfo{
						{
							Partition: 1,
							Shard:     types.ShardID{},
							IR:        &types.InputRecord{RoundNumber: 11, Epoch: 1, Hash: []byte{0xab, 0xcd}},
							IRTR:      certification.TechnicalRecord{Round: 13, Leader: "shard-leader"},
						},
					},
					Block: &rctypes.BlockData{Round: 12, Epoch: 2},
				},
			}, nil
		}, observability.Default(t))
		res, body := doRequest(t, hf, http.MethodGet, "/api/v1/roundInfo")
		require.EqualValues(t, http.StatusOK, res.StatusCode)
		require.EqualValues(t, "application/json", res.Header.Get("Content-Type"))

		var actual roundInfoResponse
		require.NoError(t, json.Unmarshal(body, &actual))

		expected := roundInfoResponse{
			RoundNumber: 12,
			EpochNumber: 2,
			PartitionShards: []shardInfo{
				{
					PartitionID: 1,
					ShardID:     types.ShardID{},
					RoundNumber: 11,
					EpochNumber: 1,
					TRRound:     13,
					TRLeader:    "shard-leader",
					StateRoot:   "0xabcd",
				},
			},
		}
		require.Equal(t, expected, actual)
	})
}

func Test_GetTrustBases(t *testing.T) {
	s1, v1 := testsig.CreateSignerAndVerifier(t)
	trustBase1, err := types.NewTrustBase(types.NetworkLocal, []*types.NodeInfo{testtb.NewNodeInfoFromVerifier(t, "1", v1)},
		types.WithEpoch(1),
		types.WithEpochStart(1),
		types.WithQuorumThreshold(1),
	)
	require.NoError(t, err)
	require.NoError(t, trustBase1.Sign("1", s1))

	_, v2 := testsig.CreateSignerAndVerifier(t)
	trustBase1Hash, err := trustBase1.Hash(crypto.SHA256)
	require.NoError(t, err)
	trustBase2, err := types.NewTrustBase(types.NetworkLocal, []*types.NodeInfo{testtb.NewNodeInfoFromVerifier(t, "2", v2)},
		types.WithEpoch(2),
		types.WithEpochStart(2),
		types.WithQuorumThreshold(1),
		types.WithPreviousTrustBaseHash(trustBase1Hash),
	)
	require.NoError(t, err)
	require.NoError(t, trustBase2.Sign("1", s1)) // sign by previous validator

	tbs, err := trustbase.NewTrustBaseStore(memorydb.New(), logger.New(t))
	require.NoError(t, err)
	require.NoError(t, tbs.Store(trustBase1))
	require.NoError(t, tbs.Store(trustBase2))

	hf := getTrustBaseHandler(tbs, observability.Default(t))

	t.Run("ok with default values", func(t *testing.T) {
		res, body := doRequest(t, hf, http.MethodGet, "/api/v1/trustbases")
		require.Equal(t, http.StatusOK, res.StatusCode)
		require.Equal(t, "application/cbor", res.Header.Get("Content-Type"))

		var response TrustBasesResponse
		require.NoError(t, types.Cbor.Unmarshal(body, &response))
		require.Len(t, response.TrustBases, 1)

		require.EqualValues(t, 2, response.TrustBases[0].Epoch)
	})

	t.Run("ok with multiple trust bases", func(t *testing.T) {
		res, body := doRequest(t, hf, http.MethodGet, "/api/v1/trustbases?from=1&to=2")
		require.Equal(t, http.StatusOK, res.StatusCode)

		var response TrustBasesResponse
		require.NoError(t, types.Cbor.Unmarshal(body, &response))
		require.Len(t, response.TrustBases, 2)

		require.EqualValues(t, 1, response.TrustBases[0].Epoch)
		require.EqualValues(t, 2, response.TrustBases[1].Epoch)
	})

	t.Run("ok with explicit params", func(t *testing.T) {
		res, _ := doRequest(t, hf, http.MethodGet, "/api/v1/trustbases?from=2&to=2")
		require.Equal(t, http.StatusOK, res.StatusCode)
	})

	t.Run("bad_request_invalid_epoch", func(t *testing.T) {
		res, _ := doRequest(t, hf, http.MethodGet, "/api/v1/trustbases?from=0")
		require.Equal(t, http.StatusBadRequest, res.StatusCode)
	})

	t.Run("bad_request_from_gt_to", func(t *testing.T) {
		res, _ := doRequest(t, hf, http.MethodGet, "/api/v1/trustbases?from=5&to=3")
		require.Equal(t, http.StatusBadRequest, res.StatusCode)
	})

	t.Run("bad_request_epoch_gt_latest", func(t *testing.T) {
		res, _ := doRequest(t, hf, http.MethodGet, "/api/v1/trustbases?to=999")
		require.Equal(t, http.StatusBadRequest, res.StatusCode)
	})
}

func doRequest(t *testing.T, hf http.HandlerFunc, method, path string) (*http.Response, []byte) {
	req := httptest.NewRequest(method, path, nil)
	rec := httptest.NewRecorder()
	hf(rec, req)
	res := rec.Result()
	defer res.Body.Close()
	responseBody, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	return res, responseBody
}

// The handoff profile's guards are on before the local shard configurations load: a restart with a wrong-key EVM genesis
// file is refused instead of replacing the stored history.
func TestLoadShardConfsEnablesTheHandoffProfileFirst(t *testing.T) {
	newConf := func() *types.PartitionDescriptionRecord {
		signer, err := abcrypto.NewInMemorySecp256K1Signer()
		require.NoError(t, err)
		verifier, err := signer.Verifier()
		require.NoError(t, err)
		pub, err := verifier.MarshalPublicKey()
		require.NoError(t, err)
		return &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: 8, PartitionTypeID: evmassign.EVMPartitionTypeID,
			UnitIDLen: 256, TypeIDLen: 32, T2Timeout: 2500 * time.Millisecond, EpochStart: 1,
			Validators: []*types.NodeInfo{{NodeID: "16Uiu2HAmRfQpGuuCgV22ndLtYGpdJcfUKtNJwD79nJ9tCZ8cfjFr", SigKey: pub, Stake: 1}}}
	}
	genesis, wrongKey := newConf(), newConf()
	path := filepath.Join(t.TempDir(), "orchestration.db")
	open := func() *partitions.Orchestration {
		o, err := partitions.NewOrchestration(5, path, logger.New(t))
		require.NoError(t, err)
		return o
	}
	first := open()
	require.NoError(t, loadShardConfs(first, true, []*types.PartitionDescriptionRecord{genesis}))
	require.NoError(t, first.Close())

	restarted := open()
	t.Cleanup(func() { _ = restarted.Close() })
	require.NoError(t, loadShardConfs(restarted, true, []*types.PartitionDescriptionRecord{genesis}), "the same genesis file restarts")
	err := loadShardConfs(restarted, true, []*types.PartitionDescriptionRecord{wrongKey})
	require.ErrorIs(t, err, partitions.ErrDerivedConflict, "a wrong-key genesis file is refused under the handoff profile")
}

// Under the handoff profile the PUT path writes nothing; without it the legacy handler is untouched.
func TestConfigurationsPUTIsRefusedUnderTheHandoffProfile(t *testing.T) {
	added := 0
	add := func(*types.PartitionDescriptionRecord) error { added++; return nil }
	body := `{"version":1}`
	for _, tc := range []struct {
		profile bool
		status  int
	}{{true, http.StatusForbidden}, {false, http.StatusOK}} {
		rec := httptest.NewRecorder()
		configurationsHandler(tc.profile, add)(rec, httptest.NewRequest(http.MethodPut, "/api/v1/configurations", strings.NewReader(body)))
		if tc.profile {
			require.Equal(t, tc.status, rec.Code)
			require.Zero(t, added, "nothing was registered")
		} else {
			require.NotEqual(t, http.StatusForbidden, rec.Code, "the legacy path is not refused")
		}
	}
}

// A restart with an edited aggregator configuration file is refused under the handoff profile, like the EVM one: every shard
// configuration after genesis comes from committed history, so a local edit cannot diverge one root.
func TestLoadShardConfsRefusesAnEditedAggregatorConfigurationUnderTheHandoffProfile(t *testing.T) {
	newConf := func(epoch, start uint64) *types.PartitionDescriptionRecord {
		signer, err := abcrypto.NewInMemorySecp256K1Signer()
		require.NoError(t, err)
		verifier, err := signer.Verifier()
		require.NoError(t, err)
		pub, err := verifier.MarshalPublicKey()
		require.NoError(t, err)
		return &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: 9, PartitionTypeID: 9,
			UnitIDLen: 256, TypeIDLen: 32, T2Timeout: 2500 * time.Millisecond, Epoch: epoch, EpochStart: start,
			Validators: []*types.NodeInfo{{NodeID: "16Uiu2HAmRfQpGuuCgV22ndLtYGpdJcfUKtNJwD79nJ9tCZ8cfjFr", SigKey: pub, Stake: 1}}}
	}
	genesis, edited, later := newConf(0, 1), newConf(0, 1), newConf(1, 50)
	path := filepath.Join(t.TempDir(), "orchestration.db")
	open := func() *partitions.Orchestration {
		o, err := partitions.NewOrchestration(5, path, logger.New(t))
		require.NoError(t, err)
		return o
	}
	first := open()
	require.NoError(t, loadShardConfs(first, true, []*types.PartitionDescriptionRecord{genesis}))
	require.NoError(t, first.Close())
	restarted := open()
	t.Cleanup(func() { _ = restarted.Close() })
	require.NoError(t, loadShardConfs(restarted, true, []*types.PartitionDescriptionRecord{genesis}))
	require.ErrorIs(t, loadShardConfs(restarted, true, []*types.PartitionDescriptionRecord{edited}), partitions.ErrDerivedConflict)
	require.ErrorIs(t, loadShardConfs(restarted, true, []*types.PartitionDescriptionRecord{later}), partitions.ErrDerivedOnly)
	// B2 probes: other keys at another activation round, and a new partition, are refused at startup too.
	otherKeysLater := newConf(0, 100)
	require.ErrorIs(t, loadShardConfs(restarted, true, []*types.PartitionDescriptionRecord{genesis, otherKeysLater}), partitions.ErrDerivedConflict)
	newPartition := newConf(0, 1)
	newPartition.PartitionID = 11
	require.ErrorIs(t, loadShardConfs(restarted, true, []*types.PartitionDescriptionRecord{genesis, newPartition}), partitions.ErrDerivedOnly)
}
