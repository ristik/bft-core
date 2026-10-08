package cmd

// `ubft pos-relayer`: the operator tooling around a primary candidate's EVM possession proofs (briefs/p85-pr3-plan.md, slice 6).
//
//	sign-pop  a member signs the possession digest of the candidate's identity record for its own EVM key
//	assemble  the relayer checks the collected proofs, orders them and writes them into the handoff proposal's evmPops
//
// Neither command talks to a node: the candidate, the deployment file and the attempt the election reserved the result under are
// inputs, and everything is checked again at Freeze admission against the proven EVM state.

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"sort"
	"strings"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/spf13/cobra"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-go-base/types"
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

	root.AddCommand(sign, assemble, newPosProposalCmd(), newPosTxCmd(), newPosGenesisCmd())
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

// ---- genesis ----------------------------------------------------------------------------------------------------------------------------------

// posGenesisPlan is the operator's plan of the proof-of-stake genesis committee: who is bonded, with which keys, and into which lots. The
// custody genesis seeds one lot per identity in order (lot ids 1..N), which is what makes the exposure digests computable before the
// contracts exist.
type posGenesisPlan struct {
	BondUnit   string               `json:"bondUnit"` // base units of one weight unit, decimal (custody's bondUnit)
	Identities []posGenesisIdentity `json:"identities"`
}

type posGenesisIdentity struct {
	StakingID  uint64   `json:"stakingId"` // custody's id: 1..N in manifest order
	Owner      string   `json:"owner"`     // 20-byte hex addresses
	Withdrawal string   `json:"withdrawal"`
	Payee      string   `json:"payee"`
	BondUnits  uint64   `json:"bondUnits"` // the genesis weight: bond / bondUnit
	RootNodeID string   `json:"rootNodeId"`
	RootKey    string   `json:"rootKey"` // 33-byte compressed secp256k1, hex
	EVMNodeID  string   `json:"evmNodeId"`
	EVMKey     string   `json:"evmKey"`
	LotIDs     []uint64 `json:"lotIds"`
}

// contractsGenesis is the file unicity-pos-contracts script/p85-genesis.sh reads.
type contractsGenesis struct {
	AssignmentID string                     `json:"assignmentId"`
	BondUnit     string                     `json:"bondUnit"`
	Identities   []contractsGenesisIdentity `json:"identities"`
}

type contractsGenesisIdentity struct {
	Owner      string `json:"owner"`
	Withdrawal string `json:"withdrawal"`
	RootKey    string `json:"rootKey"`
	EVMKey     string `json:"evmKey"`
	RootNodeID string `json:"rootNodeId"` // keccak256(utf8(peer id)), the word custody stores
	EVMNodeID  string `json:"evmNodeId"`
	Payee      string `json:"payee"`
	Bond       string `json:"bond"` // base units, decimal
}

func hexBytes(name, s string, n int) ([]byte, error) {
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil || (n > 0 && len(b) != n) {
		return nil, fmt.Errorf("%w: %s must be %d bytes of hex", ErrPosRelayer, name, n)
	}
	return b, nil
}

// buildPosGenesis derives the root-side identity records of the genesis committee (the baseline K the first coupled handoff names), the
// genesis assignment id (the assignment hash of the installed genesis shard configuration over those records), and the contracts script's
// input. Identities are validated against the genesis trust base and shard configuration exactly as a later candidate's are.
func buildPosGenesis(plan posGenesisPlan, tb *types.RootTrustBaseV1, conf *types.PartitionDescriptionRecord) ([]evmassign.Identity, [32]byte, contractsGenesis, error) {
	var zero [32]byte
	unit, ok := new(big.Int).SetString(plan.BondUnit, 10)
	if !ok || unit.Sign() <= 0 {
		return nil, zero, contractsGenesis{}, fmt.Errorf("%w: bondUnit must be a positive decimal", ErrPosRelayer)
	}
	var ids []evmassign.Identity
	out := contractsGenesis{BondUnit: plan.BondUnit}
	for i, p := range plan.Identities {
		if p.StakingID != uint64(i+1) || p.BondUnits == 0 || len(p.LotIDs) == 0 {
			return nil, zero, out, fmt.Errorf("%w: identity %d: custody numbers genesis identities 1..N in order, with a bond and lots", ErrPosRelayer, i)
		}
		rootKey, err1 := hexBytes("rootKey", p.RootKey, evmassign.KeyLen)
		evmKey, err2 := hexBytes("evmKey", p.EVMKey, evmassign.KeyLen)
		payee, err3 := hexBytes("payee", p.Payee, evmassign.PayeeLen)
		owner, err4 := hexBytes("owner", p.Owner, 20)
		wd, err5 := hexBytes("withdrawal", p.Withdrawal, 20)
		if err := errors.Join(err1, err2, err3, err4, err5); err != nil {
			return nil, zero, out, err
		}
		staking := make([]byte, evmassign.StakingIDLen)
		binary.BigEndian.PutUint64(staking[evmassign.StakingIDLen-8:], p.StakingID)
		lots := evmassign.LotsDigest(p.LotIDs)
		ids = append(ids, evmassign.Identity{StakingID: staking, Generation: 1, RootNodeID: p.RootNodeID, RootKey: rootKey, EVMNodeID: p.EVMNodeID,
			EVMKey: evmKey, Weight: p.BondUnits, OperatorPayee: payee, ExposureDigest: lots[:]})
		rw, err1 := evmassign.NodeIDWord(p.RootNodeID)
		ew, err2 := evmassign.NodeIDWord(p.EVMNodeID)
		if err := errors.Join(err1, err2); err != nil {
			return nil, zero, out, errors.Join(ErrPosRelayer, err)
		}
		bond := new(big.Int).Mul(unit, new(big.Int).SetUint64(p.BondUnits))
		out.Identities = append(out.Identities, contractsGenesisIdentity{Owner: "0x" + hex.EncodeToString(owner), Withdrawal: "0x" + hex.EncodeToString(wd),
			RootKey: "0x" + hex.EncodeToString(rootKey), EVMKey: "0x" + hex.EncodeToString(evmKey), RootNodeID: "0x" + hex.EncodeToString(rw[:]),
			EVMNodeID: "0x" + hex.EncodeToString(ew[:]), Payee: "0x" + hex.EncodeToString(payee), Bond: bond.String()})
	}
	sort.Slice(ids, func(i, j int) bool { return bytes.Compare(ids[i].StakingID, ids[j].StakingID) < 0 })
	if err := checkGenesisIdentities(ids, tb, conf); err != nil {
		return nil, zero, out, err
	}
	digest, err := evmassign.IdentitiesDigest(ids)
	if err != nil {
		return nil, zero, out, err
	}
	assignment, err := evmassign.AssignmentHash(conf, digest)
	if err != nil {
		return nil, zero, out, err
	}
	out.AssignmentID = "0x" + hex.EncodeToString(assignment[:])
	return ids, assignment, out, nil
}

func newPosGenesisCmd() *cobra.Command {
	var planPath, trustBasePath, shardConfPath, identitiesOut, contractsOut string
	cmd := &cobra.Command{
		Use:   "genesis",
		Short: "derive the proof-of-stake genesis committee's root-side identity records and the contracts genesis input from one plan",
		Long: "The plan names the bonded genesis identities (custody numbers them 1..N and seeds one lot each). The command writes the identity\n" +
			"records `root-node run --pos-genesis-identities` records as the incumbent K, and the file unicity-pos-contracts script/p85-genesis.sh\n" +
			"deploys the genesis state from, whose assignment id is the assignment hash of the genesis shard configuration over those records.\n" +
			"The records are checked against the genesis trust base and shard configuration like any candidate's.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			raw, err := os.ReadFile(planPath) // #nosec G304 -- operator supplied local file
			if err != nil {
				return errors.Join(ErrPosRelayer, err)
			}
			var plan posGenesisPlan
			if err := json.Unmarshal(raw, &plan); err != nil {
				return errors.Join(ErrPosRelayer, err)
			}
			tb, err := readTrustBase(trustBasePath)
			if err != nil {
				return err
			}
			conf, err := readShardConf(shardConfPath)
			if err != nil {
				return err
			}
			ids, assignment, out, err := buildPosGenesis(plan, tb, conf)
			if err != nil {
				return err
			}
			if err := writeJSONFile(identitiesOut, ids); err != nil {
				return err
			}
			cmd.PrintErrf("genesis assignment id 0x%x\n", assignment)
			return writeRelayerJSON(contractsOut, out)
		},
	}
	cmd.Flags().StringVar(&planPath, "plan", "", "the genesis plan (JSON)")
	cmd.Flags().StringVar(&trustBasePath, "trust-base", "", "the genesis root trust base")
	cmd.Flags().StringVar(&shardConfPath, "shard-conf", "", "the coupled EVM shard's genesis (full) shard configuration")
	cmd.Flags().StringVar(&identitiesOut, "out-identities", "", "root-side identity records (for --pos-genesis-identities)")
	cmd.Flags().StringVar(&contractsOut, "out-contracts", "", "input of unicity-pos-contracts script/p85-genesis.sh")
	for _, f := range []string{"plan", "trust-base", "shard-conf", "out-identities", "out-contracts"} {
		_ = cmd.MarkFlagRequired(f)
	}
	return cmd
}
