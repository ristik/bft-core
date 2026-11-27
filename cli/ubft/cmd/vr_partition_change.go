package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/vrschema"
	"github.com/unicitynetwork/bft-go-base/types"
)

// `ubft vr-change`: operator tooling for the live partition changes a Foundation multisig queues in the validator registry (VT-06d
// AddPartition, VT-06e UpdatePartition; design sections 3.5 and 6). It builds the exact abi.encode payloads VR's queue accepts and the
// VR-context possession proofs an AddPartition carries, and pre-judges each payload with the frozen fold the roots run, so a payload that
// every root would reject is refused here rather than queued.
//
// The flow for a new partition: write its epoch-0 shard configuration (EpochStart 0; the roots set it to the activation round), have every
// validator sign `pop` for the change id VR will assign (`nextChangeId`; a lost race is BadPoP and is re-queued), assemble the payload
// with `add-partition`, and queue it (kind 7) through the multisig. After the boundary, `ubft q3 shard-conf --partition P --epoch 0`
// returns the installed configuration (with its activation round) that the new shard's nodes start from; their first certificate comes
// from the roots. For a parameter update, `update-partition` takes the installed configuration (the same command, its current epoch) and
// the successor, and the payload is queued as kind 8; the shard's consumers reload at the activation round.

// ErrVRChange refuses an input the roots would not accept.
var ErrVRChange = errors.New("vr-change")

func newVRChangeCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "vr-change", Short: "Build validator-registry change payloads (AddPartition, UpdatePartition, ReplaceAggregatorValidators, CommitteeLimits) and their possession proofs"}
	cmd.AddCommand(newVRChangePoPCmd(), newVRAddPartitionCmd(), newVRUpdatePartitionCmd(), newVRReplaceAggregatorsCmd(), newVRCommitteeLimitsCmd())
	return cmd
}

type vrChangeCommon struct {
	network  uint64
	changeID uint64
	out      string
}

func (c *vrChangeCommon) flags(cmd *cobra.Command, changeID bool) {
	cmd.Flags().Uint64Var(&c.network, "network", 0, "the root network id")
	_ = cmd.MarkFlagRequired("network")
	if changeID {
		cmd.Flags().Uint64Var(&c.changeID, "change-id", 0, "the change id VR assigns at queue (its nextChangeId)")
		_ = cmd.MarkFlagRequired("change-id")
	}
	cmd.Flags().StringVar(&c.out, "out", "", "output file (default: standard output)")
}

func (c *vrChangeCommon) write(cmd *cobra.Command, data []byte) error {
	if c.out == "" {
		_, err := cmd.OutOrStdout().Write(append(data, '\n'))
		return err
	}
	return os.WriteFile(c.out, append(data, '\n'), 0o600)
}

func newVRChangePoPCmd() *cobra.Command {
	var c vrChangeCommon
	var keyConfFile, pdrFile string
	cmd := &cobra.Command{Use: "pop", Short: "Sign the VR-context possession proof of one validator of an AddPartition configuration",
		RunE: func(cmd *cobra.Command, _ []string) error {
			pdr, raw, err := readChangePDR(pdrFile)
			if err != nil {
				return err
			}
			var keys KeyConf
			b, err := os.ReadFile(keyConfFile) // #nosec G304 -- operator supplied local file
			if err != nil {
				return err
			}
			if err := json.Unmarshal(b, &keys); err != nil {
				return fmt.Errorf("decoding key configuration %q: %w", keyConfFile, err)
			}
			signer, err := keys.Signer()
			if err != nil {
				return err
			}
			verifier, err := signer.Verifier()
			if err != nil {
				return err
			}
			pub, err := verifier.MarshalPublicKey()
			if err != nil {
				return err
			}
			var v *types.NodeInfo
			for _, n := range pdr.Validators {
				if bytes.Equal(n.SigKey, pub) {
					v = n
				}
			}
			if v == nil {
				return fmt.Errorf("%w: the key is not a validator of partition %d", ErrVRChange, pdr.PartitionID)
			}
			msg, err := vrschema.ChangePoPMessage(c.network, vrschema.ValidatorRegistry, c.changeID, uint32(pdr.PartitionID), pdr.ShardID.Bytes(), raw, v.NodeID)
			if err != nil {
				return err
			}
			sig, err := signer.SignBytes(msg)
			if err != nil {
				return err
			}
			out, err := json.MarshalIndent(evmassign.PoP{NodeID: v.NodeID, Key: v.SigKey, Signature: sig}, "", "  ")
			if err != nil {
				return err
			}
			return c.write(cmd, out)
		}}
	c.flags(cmd, true)
	cmd.Flags().StringVar(&keyConfFile, "key-conf", "", "the validator's key configuration (keys.json)")
	cmd.Flags().StringVar(&pdrFile, "pdr", "", "the new partition's shard configuration (JSON, epoch 0)")
	_ = cmd.MarkFlagRequired("key-conf")
	_ = cmd.MarkFlagRequired("pdr")
	return cmd
}

func newVRAddPartitionCmd() *cobra.Command {
	var c vrChangeCommon
	var pdrFile string
	var popFiles []string
	cmd := &cobra.Command{Use: "add-partition", Short: "Assemble a kind 7 AddPartition payload (hex) from the configuration and every validator's proof",
		RunE: func(cmd *cobra.Command, _ []string) error {
			pdr, raw, err := readChangePDR(pdrFile)
			if err != nil {
				return err
			}
			if err := evmassign.ValidateAssignment(pdr); err != nil {
				return fmt.Errorf("%w: the roots would judge the configuration Invalid: %w", ErrVRChange, err)
			}
			pops, err := collectPoPs(pdr, popFiles)
			if err != nil {
				return err
			}
			popRaw, err := types.Cbor.Marshal(pops)
			if err != nil {
				return err
			}
			payload, err := vrschema.EncodeChange(vrschema.KindAddPartition, raw, popRaw)
			if err != nil {
				return err
			}
			if err := judgeChange(c, vrschema.KindAddPartition, payload, nil); err != nil {
				return err
			}
			return c.write(cmd, []byte(vrschema.Hexb(payload)))
		}}
	c.flags(cmd, true)
	cmd.Flags().StringVar(&pdrFile, "pdr", "", "the new partition's shard configuration (JSON, epoch 0, epoch start 0)")
	cmd.Flags().StringSliceVar(&popFiles, "pop", nil, "every validator's possession proof (`vr-change pop` output), any order")
	_ = cmd.MarkFlagRequired("pdr")
	_ = cmd.MarkFlagRequired("pop")
	return cmd
}

func newVRUpdatePartitionCmd() *cobra.Command {
	var c vrChangeCommon
	var currentFile, successorFile string
	cmd := &cobra.Command{Use: "update-partition", Short: "Assemble a kind 8 UpdatePartition payload (hex) replacing the installed configuration",
		RunE: func(cmd *cobra.Command, _ []string) error {
			current, err := readShardConf(currentFile)
			if err != nil {
				return err
			}
			succ, raw, err := readChangePDR(successorFile)
			if err != nil {
				return err
			}
			expected, err := evmassign.PDRHash(current)
			if err != nil {
				return err
			}
			payload, err := vrschema.EncodeChange(vrschema.KindUpdatePartition, uint64(succ.PartitionID), succ.ShardID.Bytes(), expected, raw)
			if err != nil {
				return err
			}
			if err := judgeChange(c, vrschema.KindUpdatePartition, payload, current); err != nil {
				return err
			}
			return c.write(cmd, []byte(vrschema.Hexb(payload)))
		}}
	c.flags(cmd, false)
	c.changeID = 1 // an UpdatePartition carries no possession proof: the change id is not signed
	cmd.Flags().StringVar(&currentFile, "current", "", "the installed configuration it replaces (`ubft q3 shard-conf` output)")
	cmd.Flags().StringVar(&successorFile, "successor", "", "the successor configuration: epoch + 1, epoch start 0, the same validators")
	_ = cmd.MarkFlagRequired("current")
	_ = cmd.MarkFlagRequired("successor")
	return cmd
}

// readChangePDR reads a configuration a change carries and its canonical CBOR, which is what the payload embeds and the proofs sign.
func readChangePDR(path string) (*types.PartitionDescriptionRecord, []byte, error) {
	pdr, err := readShardConf(path)
	if err != nil {
		return nil, nil, err
	}
	if pdr.EpochStart != 0 {
		return nil, nil, fmt.Errorf("%w: %q sets an epoch start; the roots set it to the committed activation round", ErrVRChange, path)
	}
	raw, err := types.Cbor.Marshal(pdr)
	if err != nil {
		return nil, nil, err
	}
	return pdr, raw, nil
}

// judgeChange runs VR's structural queue check and the roots' fold over the payload: an AddPartition against no installed partition
// (whether the id is in use is the roots' state at the Freeze), an UpdatePartition against the configuration it replaces. Anything but
// Accepted is refused with the verdict's name.
func judgeChange(c vrChangeCommon, kind uint8, payload []byte, installed *types.PartitionDescriptionRecord) error {
	if err := vrschema.QueueCheck(kind, payload, vrschema.QueueEnv{}); err != nil {
		return fmt.Errorf("%w: VR would refuse the payload at queue: %w", ErrVRChange, err)
	}
	in := vrschema.FoldInput{Network: c.network, Installed: map[vrschema.ShardKey]*types.PartitionDescriptionRecord{},
		ReservedPartitions: []uint32{0xFFFFFFFF, 0xFFFFFFFE}, PartitionCeiling: vrschema.PartitionCeiling}
	if installed != nil {
		in.Installed[vrschema.ShardKey{Partition: uint32(installed.PartitionID), Shard: string(installed.ShardID.Bytes())}] = installed
	}
	verdicts, err := vrschema.FoldVerdicts(in, []vrschema.RegistryChange{{ID: c.changeID, Kind: uint64(kind), Payload: payload}})
	if err != nil {
		return errors.Join(ErrVRChange, err)
	}
	if verdicts[0] != vrschema.VerdictAccepted {
		return fmt.Errorf("%w: the roots would reject the change: %s", ErrVRChange, vrschema.VerdictNames[verdicts[0]])
	}
	return nil
}

// collectPoPs reads every validator's possession proof and returns them in the configuration's validator order.
func collectPoPs(pdr *types.PartitionDescriptionRecord, popFiles []string) ([]evmassign.PoP, error) {
	byNode := map[string]evmassign.PoP{}
	for _, f := range popFiles {
		b, err := os.ReadFile(f) // #nosec G304 -- operator supplied local file
		if err != nil {
			return nil, err
		}
		var p evmassign.PoP
		if err := json.Unmarshal(b, &p); err != nil {
			return nil, fmt.Errorf("decoding possession proof %q: %w", f, err)
		}
		byNode[p.NodeID] = p
	}
	pops := make([]evmassign.PoP, 0, len(pdr.Validators))
	for _, v := range pdr.Validators {
		p, ok := byNode[v.NodeID]
		if !ok {
			return nil, fmt.Errorf("%w: no possession proof of validator %s", ErrVRChange, v.NodeID)
		}
		pops = append(pops, p)
	}
	return pops, nil
}

func newVRReplaceAggregatorsCmd() *cobra.Command {
	var c vrChangeCommon
	var currentFile, successorFile string
	var popFiles []string
	cmd := &cobra.Command{Use: "replace-aggregators", Short: "Assemble a kind 6 ReplaceAggregatorValidators payload (hex): a new validator set for an installed non-EVM shard",
		Long: `Replaces the validators of an installed non-EVM shard and nothing else: the successor is the installed configuration (` + "`ubft q3 shard-conf`" + `
output) at epoch + 1 with epoch start 0 and the new validators, whose possession proofs (` + "`vr-change pop`" + ` over the successor, for the change id
VR will assign) are all required. The payload is judged by the roots' fold before it is printed. Queue it as kind 6; the aggregators and
nodes of the shard switch to the new set at the activation round of the next epoch.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			current, err := readShardConf(currentFile)
			if err != nil {
				return err
			}
			succ, raw, err := readChangePDR(successorFile)
			if err != nil {
				return err
			}
			if err := evmassign.ValidateSuccessor(current, succ); err != nil {
				return fmt.Errorf("%w: the roots would judge the successor Invalid (only the validators may change, at epoch + 1): %w", ErrVRChange, err)
			}
			pops, err := collectPoPs(succ, popFiles)
			if err != nil {
				return err
			}
			popRaw, err := types.Cbor.Marshal(pops)
			if err != nil {
				return err
			}
			expected, err := evmassign.PDRHash(current)
			if err != nil {
				return err
			}
			payload, err := vrschema.EncodeChange(vrschema.KindReplaceAggregator, uint64(succ.PartitionID), succ.ShardID.Bytes(), expected, raw, popRaw)
			if err != nil {
				return err
			}
			if err := judgeChange(c, vrschema.KindReplaceAggregator, payload, current); err != nil {
				return err
			}
			return c.write(cmd, []byte(vrschema.Hexb(payload)))
		}}
	c.flags(cmd, true)
	cmd.Flags().StringVar(&currentFile, "current", "", "the installed configuration it replaces (`ubft q3 shard-conf` output)")
	cmd.Flags().StringVar(&successorFile, "successor", "", "the successor: epoch + 1, epoch start 0, the new validators, everything else unchanged")
	cmd.Flags().StringSliceVar(&popFiles, "pop", nil, "every new validator's possession proof (`vr-change pop` output over the successor), any order")
	_ = cmd.MarkFlagRequired("current")
	_ = cmd.MarkFlagRequired("successor")
	_ = cmd.MarkFlagRequired("pop")
	return cmd
}

func newVRCommitteeLimitsCmd() *cobra.Command {
	var nMin, nTarget, nMax uint32
	cmd := &cobra.Command{Use: "committee-limits", Short: "Assemble a kind 4 CommitteeLimits payload (hex), checked as VR's queue checks it",
		Long: `1 <= nMin <= nTarget <= nMax <= 16. The limits judge the next module output after the change's boundary (native outputs are exempt):
an output must have nMin <= size <= nMax, or be strictly closer to that range than the committee in force, so lowering nMax below the
current size shrinks the committee over several outputs instead of failing it.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			payload, err := vrschema.EncodeChange(vrschema.KindCommitteeLimits, uint64(nMin), uint64(nTarget), uint64(nMax))
			if err != nil {
				return err
			}
			if err := vrschema.QueueCheck(vrschema.KindCommitteeLimits, payload, vrschema.QueueEnv{}); err != nil {
				return fmt.Errorf("%w: VR would refuse the payload at queue: %w", ErrVRChange, err)
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), vrschema.Hexb(payload))
			return err
		}}
	cmd.Flags().Uint32Var(&nMin, "n-min", 0, "minimum committee size")
	cmd.Flags().Uint32Var(&nTarget, "n-target", 0, "target committee size")
	cmd.Flags().Uint32Var(&nMax, "n-max", 0, "maximum committee size (at most 16)")
	_ = cmd.MarkFlagRequired("n-min")
	_ = cmd.MarkFlagRequired("n-target")
	_ = cmd.MarkFlagRequired("n-max")
	return cmd
}
