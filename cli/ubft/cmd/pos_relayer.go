package cmd

// `ubft pos-relayer`: the operator tooling around a primary candidate's EVM possession proofs (briefs/p85-pr3-plan.md, slice 6).
//
//	sign-pop  a member signs the possession digest of the candidate's identity record for its own EVM key
//	assemble  the relayer checks the collected proofs, orders them and writes them into the handoff proposal's evmPops
//
// Neither command talks to a node: the candidate, the deployment file and the attempt the election reserved the result under are
// inputs, and everything is checked again at Freeze admission against the proven EVM state.

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/spf13/cobra"
	"github.com/unicitynetwork/bft-core/evmassign"
)

// ErrPosRelayer reports a relayer input that cannot be used.
var ErrPosRelayer = errors.New("pos-relayer")

type popJSON struct {
	ID        uint64 `json:"id"`
	EVMKey    string `json:"evmKey"`
	Signature string `json:"signature"`
}

func (p popJSON) pop() (evmassign.EVMPoP, error) {
	key, err1 := hex.DecodeString(strings.TrimPrefix(p.EVMKey, "0x"))
	sig, err2 := hex.DecodeString(strings.TrimPrefix(p.Signature, "0x"))
	if err := errors.Join(err1, err2); err != nil {
		return evmassign.EVMPoP{}, errors.Join(ErrPosRelayer, err)
	}
	return evmassign.EVMPoP{ID: p.ID, EVMKey: key, Signature: sig}, nil
}

func toPoPJSON(p evmassign.EVMPoP) popJSON {
	return popJSON{ID: p.ID, EVMKey: "0x" + hex.EncodeToString(p.EVMKey), Signature: "0x" + hex.EncodeToString(p.Signature)}
}

// readCandidateFile reads a primary candidate from its canonical encoding, as hex text or raw bytes.
func readCandidateFile(path string) (evmassign.Candidate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return evmassign.Candidate{}, errors.Join(ErrPosRelayer, err)
	}
	if decoded, herr := hex.DecodeString(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(raw)), "0x"))); herr == nil {
		raw = decoded
	}
	c, err := evmassign.DecodeCandidate(raw)
	if err != nil {
		return c, errors.Join(ErrPosRelayer, err)
	}
	if c.Kind != evmassign.KindPrimary {
		return c, fmt.Errorf("%w: only a primary candidate takes EVM possession proofs", ErrPosRelayer)
	}
	return c, nil
}

func electionDeployment(path string) (evmassign.ElectionDeployment, error) {
	dep, _, err := loadPosDeployment(path, 0)
	if err != nil {
		return evmassign.ElectionDeployment{}, err
	}
	if dep.Election == ([20]byte{}) {
		return evmassign.ElectionDeployment{}, fmt.Errorf("%w: the deployment file pins no election", ErrPosRelayer)
	}
	return evmassign.ElectionDeployment{Deployment: dep.Deployment, Election: dep.Election}, nil
}

func newPosRelayerCmd() *cobra.Command {
	root := &cobra.Command{Use: "pos-relayer", Short: "operator tooling for a primary candidate's EVM possession proofs"}

	var candidate, deployment, keyFile, out string
	var attempt uint64
	sign := &cobra.Command{
		Use:   "sign-pop",
		Short: "sign the possession digest of the candidate's identity record for the key in --evm-key-file (hex secp256k1 secret)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := readCandidateFile(candidate)
			if err != nil {
				return err
			}
			d, err := electionDeployment(deployment)
			if err != nil {
				return err
			}
			key, err := readEVMKey(keyFile)
			if err != nil {
				return err
			}
			p, err := evmassign.SignEVMPoP(key, c, d, attempt)
			if err != nil {
				return err
			}
			return writeRelayerJSON(out, toPoPJSON(p))
		},
	}
	sign.Flags().StringVar(&candidate, "candidate", "", "the primary candidate (canonical encoding, hex or raw)")
	sign.Flags().StringVar(&deployment, "pos-deployment", "", "the P85 deployment file, with the election pinned")
	sign.Flags().StringVar(&keyFile, "evm-key-file", "", "file holding the member's EVM secret key as 32 bytes of hex")
	sign.Flags().Uint64Var(&attempt, "attempt", 0, "the attempt the election reserved the result under")
	sign.Flags().StringVar(&out, "out", "", "output file (default stdout)")

	var popFiles []string
	assemble := &cobra.Command{
		Use:   "assemble",
		Short: "check the collected proofs against the candidate and write them as the proposal's evmPops",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := readCandidateFile(candidate)
			if err != nil {
				return err
			}
			d, err := electionDeployment(deployment)
			if err != nil {
				return err
			}
			var collected []evmassign.EVMPoP
			for _, f := range popFiles {
				raw, err := os.ReadFile(f)
				if err != nil {
					return errors.Join(ErrPosRelayer, err)
				}
				var j popJSON
				if err := json.Unmarshal(raw, &j); err != nil {
					return errors.Join(ErrPosRelayer, err)
				}
				p, err := j.pop()
				if err != nil {
					return err
				}
				collected = append(collected, p)
			}
			ordered, set, err := evmassign.AssemblePoPs(c, d, attempt, collected)
			if err != nil {
				return err
			}
			list := make([]popJSON, len(ordered))
			for i, p := range ordered {
				list[i] = toPoPJSON(p)
			}
			cmd.PrintErrf("popSetDigest 0x%x\n", set)
			return writeRelayerJSON(out, map[string]any{"evmPops": list})
		},
	}
	assemble.Flags().StringVar(&candidate, "candidate", "", "the primary candidate (canonical encoding, hex or raw)")
	assemble.Flags().StringVar(&deployment, "pos-deployment", "", "the P85 deployment file, with the election pinned")
	assemble.Flags().Uint64Var(&attempt, "attempt", 0, "the attempt the election reserved the result under")
	assemble.Flags().StringSliceVar(&popFiles, "pop", nil, "a member's proof file from sign-pop (repeat)")
	assemble.Flags().StringVar(&out, "out", "", "output file (default stdout)")

	root.AddCommand(sign, assemble, newPosProposalCmd(), newPosTxCmd())
	return root
}

func readEVMKey(path string) (*ecdsa.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.Join(ErrPosRelayer, err)
	}
	b, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(string(raw)), "0x"))
	if err != nil || len(b) != 32 {
		return nil, fmt.Errorf("%w: the key file must hold 32 bytes of hex", ErrPosRelayer)
	}
	key, err := ethcrypto.ToECDSA(b)
	if err != nil {
		return nil, errors.Join(ErrPosRelayer, err)
	}
	return key, nil
}

func writeRelayerJSON(path string, v any) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if path == "" {
		_, err = fmt.Println(string(raw))
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o600)
}
