package cmd

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/rpc"
	"github.com/spf13/cobra"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/posrelayer"
)

// newPosProposalCmd is `ubft pos-relayer proposal`: the inputs of the existing handoff pipeline for the election's published primary result.
// It reads the election and custody modules, builds the identity records, the recovery authorization (K), the successor validators and the
// bindings, and writes the files `root handoff evm-pop` and `evm-assemble` read. It is an untrusted tool: the root re-verifies every word at
// the last certified EVM state.
func newPosProposalCmd() *cobra.Command {
	var ethRPC, deployment, contextFile, resultHex, nodeIDsFlag, trustBase, shardConf, popsFile, outDir string
	cmd := &cobra.Command{
		Use:   "proposal",
		Short: "build the handoff pipeline's inputs for a published primary result from the election and custody modules",
		Long: "Writes identities.json, authorization.json, validators.json and bindings.json (and evm-pops.json with --evm-pops) into --out-dir:\n" +
			"the inputs of `root handoff evm-pop` / `evm-assemble` (--identities, --authorization, --validators, --bindings, --evm-pops). The context is\n" +
			"`root handoff evm-context`'s. The modules hold only keccak256 of the node ids, so the peer ids the committees are made of are named with\n" +
			"--trust-base, --shard-conf and --node-ids (a joiner's, for instance).",
		RunE: func(cmd *cobra.Command, _ []string) error {
			dep, _, err := loadPosDeployment(deployment, 0)
			if err != nil {
				return err
			}
			if dep.Election == ([20]byte{}) {
				return fmt.Errorf("%w: the deployment file pins no election", ErrPosRelayer)
			}
			c, _, err := readContextFile(contextFile)
			if err != nil {
				return err
			}
			var ids []string
			for _, s := range strings.Split(nodeIDsFlag, ",") {
				if s = strings.TrimSpace(s); s != "" {
					ids = append(ids, s)
				}
			}
			if trustBase != "" {
				tb, err := readTrustBase(trustBase)
				if err != nil {
					return err
				}
				for _, n := range tb.RootNodes {
					ids = append(ids, n.NodeID)
				}
			}
			if shardConf != "" {
				conf, err := readShardConf(shardConf)
				if err != nil {
					return err
				}
				for _, v := range conf.Validators {
					ids = append(ids, v.NodeID)
				}
			}
			names, err := posrelayer.NewNames(ids)
			if err != nil {
				return errors.Join(ErrPosRelayer, err)
			}
			client, err := rpc.Dial(ethRPC)
			if err != nil {
				return errors.Join(ErrPosRelayer, err)
			}
			defer client.Close()
			ctx, cancel := context.WithTimeout(cmd.Context(), 60*time.Second)
			defer cancel()
			rd, err := posrelayer.RPCReader{Client: client}.Pin(ctx)
			if err != nil {
				return errors.Join(ErrPosRelayer, err)
			}
			mods := posrelayer.Modules{Election: dep.Election, Custody: dep.Custody}
			var result [32]byte
			if resultHex != "" {
				b, err := hex.DecodeString(strings.TrimPrefix(resultHex, "0x"))
				if err != nil || len(b) != 32 {
					return fmt.Errorf("%w: --result-id must be 32 bytes of hex", ErrPosRelayer)
				}
				copy(result[:], b)
			} else if result, err = posrelayer.OpenResult(ctx, rd, mods); err != nil || result == ([32]byte{}) {
				return fmt.Errorf("%w: the election has no open result (give --result-id): %v", ErrPosRelayer, err)
			}
			chain := new(big.Int).SetBytes(dep.ChainID[:])
			if !chain.IsUint64() {
				return fmt.Errorf("%w: the chain id does not fit 64 bits", ErrPosRelayer)
			}
			out, err := posrelayer.Build(ctx, rd, mods, result, posrelayer.RootContext{Network: c.Network, Chain: chain.Uint64(), Predecessor: c.Predecessor,
				Acknowledged: c.Acknowledged}, names)
			if err != nil {
				return err
			}
			files := map[string]any{"identities.json": out.Identities, "authorization.json": out.Authorization, "validators.json": out.Validators, "bindings.json": out.Bindings}
			if popsFile != "" {
				pops, err := readPoPFiles(popsFile)
				if err != nil {
					return err
				}
				ordered, err := posrelayer.CheckPoPs(out, pops)
				if err != nil {
					return err
				}
				files["evm-pops.json"] = ordered
			}
			// everything is checked before anything is written
			if err := os.MkdirAll(outDir, 0o750); err != nil {
				return err
			}
			for name, v := range files {
				raw, err := json.MarshalIndent(v, "", "  ")
				if err != nil {
					return err
				}
				if err := os.WriteFile(filepath.Join(outDir, name), append(raw, '\n'), 0o600); err != nil {
					return err
				}
			}
			digest, _ := evmassign.IdentitiesDigest(out.Identities)
			cmd.PrintErrf("result 0x%x (election attempt %d): %d members, identities digest 0x%x\n", out.ResultID, out.Attempt, len(out.Identities), digest)
			return nil
		},
	}
	cmd.Flags().StringVar(&ethRPC, "eth-rpc", "", "the execution client's JSON-RPC URL (eth_call at the latest block)")
	cmd.Flags().StringVar(&deployment, "pos-deployment", "", "the P85 deployment file, with the election pinned")
	cmd.Flags().StringVar(&contextFile, "context", "", "the context JSON from `root handoff evm-context`")
	cmd.Flags().StringVar(&resultHex, "result-id", "", "the election result (default: its open result)")
	cmd.Flags().StringVar(&nodeIDsFlag, "node-ids", "", "comma-separated peer ids to resolve node-id words with (a joiner's, for instance)")
	cmd.Flags().StringVar(&trustBase, "trust-base", "", "a root trust base whose node ids are known")
	cmd.Flags().StringVar(&shardConf, "shard-conf", "", "a shard configuration whose validators' node ids are known")
	cmd.Flags().StringVar(&popsFile, "evm-pops", "", "the collected EVM possession proofs (`pos-relayer assemble` output): checked against the election's stored hashes and written, ordered, as evm-pops.json")
	cmd.Flags().StringVar(&outDir, "out-dir", "", "directory for the files")
	for _, f := range []string{"eth-rpc", "pos-deployment", "context", "out-dir"} {
		_ = cmd.MarkFlagRequired(f)
	}
	return cmd
}

// readPoPFiles reads `pos-relayer assemble`'s {"evmPops":[...]} output.
func readPoPFiles(path string) ([]evmassign.EVMPoP, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- operator supplied local file
	if err != nil {
		return nil, errors.Join(ErrPosRelayer, err)
	}
	var f struct {
		EVMPoPs []popJSON `json:"evmPops"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, errors.Join(ErrPosRelayer, err)
	}
	out := make([]evmassign.EVMPoP, 0, len(f.EVMPoPs))
	for _, p := range f.EVMPoPs {
		x, err := p.pop()
		if err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, nil
}
