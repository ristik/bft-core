package cmd

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/spf13/cobra"
	"github.com/unicitynetwork/bft-go-base/types"
)

// This is an observation on a validator's local, synced root and execution
// node. Count a reported signature only once the complete UC verifies.
func validatorLastUCCmd() *cobra.Command {
	var execution, root, signer string
	cmd := &cobra.Command{
		Use:   "last-signed-uc",
		Short: "Find the newest local UC carrying this root's verified signature",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), 12*time.Second)
			defer cancel()
			rpc := ethExecution{url: execution, client: &http.Client{Timeout: 3 * time.Second}}
			observed, err := findLastSignedUC(ctx, rpc, root, signer)
			if err != nil {
				return err
			}
			return json.NewEncoder(cmd.OutOrStdout()).Encode(observed)
		},
	}
	cmd.Flags().StringVar(&execution, "execution", "", "local execution RPC")
	cmd.Flags().StringVar(&root, "root-rpc", "", "local verified root RPC")
	cmd.Flags().StringVar(&signer, "signer", "", "local root node ID")
	for _, flag := range []string{"execution", "root-rpc", "signer"} {
		_ = cmd.MarkFlagRequired(flag)
	}
	return cmd
}

type signedUCView struct {
	Block      common.Hash `json:"blockHash"`
	RootEpoch  uint64      `json:"rootEpoch"`
	RootRound  uint64      `json:"rootRound"`
	ShardRound uint64      `json:"shardRound"`
	Signer     string      `json:"signer"`
}

func findLastSignedUC(ctx context.Context, rpc ethExecution, root, signer string) (*signedUCView, error) {
	type block struct {
		Hash   common.Hash    `json:"hash"`
		Parent common.Hash    `json:"parentHash"`
		Number hexutil.Uint64 `json:"number"`
	}
	var latest block
	if err := rpc.call(ctx, "eth_getBlockByNumber", []any{"latest", false}, &latest); err != nil {
		return nil, err
	}
	for i, n := 0, uint64(latest.Number); i < 12 && n > 0; i, n = i+1, n-1 {
		var child block
		if err := rpc.call(ctx, "eth_getBlockByNumber", []any{hexutil.Uint64(n), false}, &child); err != nil || child.Hash == (common.Hash{}) {
			continue
		}
		var result struct {
			Companion struct {
				Witnesses []hexutil.Bytes `json:"witnesses"`
			} `json:"companion"`
		}
		if err := rpc.call(ctx, "unicity_getSealCompanionV1", []any{child.Hash}, &result); err != nil || len(result.Companion.Witnesses) == 0 {
			continue
		}
		var uc types.UnicityCertificate
		if err := types.Cbor.Unmarshal(result.Companion.Witnesses[0], &uc); err != nil || uc.InputRecord == nil || uc.UnicitySeal == nil {
			continue
		}
		if _, signed := uc.UnicitySeal.Signatures[signer]; !signed || !bytes.Equal(uc.InputRecord.BlockHash, child.Parent[:]) {
			continue
		}
		trust, err := fetchTrustBase(ctx, root, uc.UnicitySeal.Epoch)
		if err != nil {
			return nil, err
		}
		var conf types.PartitionDescriptionRecord
		if err := firstPost(ctx, []string{root}, "/api/v1/q3/shard-conf", q3ShardConfRequest{Partition: 8, Epoch: uc.InputRecord.Epoch}, &conf); err != nil {
			return nil, err
		}
		h, err := conf.Hash(crypto.SHA256)
		if err != nil {
			return nil, err
		}
		if err := uc.Verify(trust, crypto.SHA256, conf.PartitionID, conf.ShardID, h); err != nil {
			return nil, fmt.Errorf("verify UC for %s: %w", child.Parent, err)
		}
		return &signedUCView{Block: child.Parent, RootEpoch: uc.UnicitySeal.Epoch, RootRound: uc.UnicitySeal.RootChainRoundNumber,
			ShardRound: uc.InputRecord.RoundNumber, Signer: signer}, nil
	}
	return nil, nil
}
