package cmd

// The proof-of-stake deployment a root's P85 controls name, and the node wiring that turns the closure duty on (docs/design/h3-evm-assignment.md,
// "P85 control executor"). The file is the custody deployment's own pinned identity: the network word its manifest exports, the chain id it
// runs on and the custody address. A root started without it executes no controls and enforces no closure duty.

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/rpc"
	"github.com/unicitynetwork/bft-core/rootchain/consensus"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	"github.com/unicitynetwork/bft-core/rootchain/evmstate"
	"github.com/unicitynetwork/bft-core/rootchain/partitions"
	"github.com/unicitynetwork/bft-core/rootchain/posclosure"
	"github.com/unicitynetwork/bft-core/rootchain/posreject"
	"github.com/unicitynetwork/bft-core/rootchain/posretire"
	"github.com/unicitynetwork/bft-go-base/types"
)

// posRetirementStateFileName is the root's Retirement request state (under the node home).
const posRetirementStateFileName = "pos-retirements.json"

// ErrPosDeployment is returned for a deployment file that cannot pin a custody deployment, or one used where it must not be.
var ErrPosDeployment = errors.New("invalid P85 custody deployment")

type posDeploymentFile struct {
	NetworkWord string `json:"networkWord"` // 32 bytes, 0x-hex: custody.network as the manifest exports it, not re-hashed
	ChainID     string `json:"chainId"`     // unsigned decimal or 0x-hex, at most 256 bits
	Custody     string `json:"custody"`     // 20 bytes, 0x-hex
	// The pinned deployed contracts the Retirement and RejectResult storage proofs are judged against.
	CustodyCode  string `json:"custodyCodeHash"`  // 32 bytes: keccak256 of the deployed custody code
	Registry     string `json:"registry"`         // 20 bytes: the SealRegistry custody names as its roots
	RegistryCode string `json:"registryCodeHash"` // 32 bytes: keccak256 of the deployed registry code
	// Optional pair: the deployed Election module. CONSENSUS-CRITICAL: every root of the chain must pin the same pair (and run an
	// execution client for --pos-evm-rpc), because it decides whether a primary candidate's Freeze must carry the EVM proof; roots that
	// differ judge the same block differently.
	// With it the root judges a primary candidate's EVM proof (Freeze companion v4);
	// without it a primary candidate is admitted as before. Both or neither.
	Election     string `json:"election,omitempty"`         // 20 bytes
	ElectionCode string `json:"electionCodeHash,omitempty"` // 32 bytes: keccak256 of the deployed election code
	// Optional pair: the funded RewardPool (T8). NOT consensus-critical (it is ordinary EVM work and no root judges it), so a root ignores it; the
	// relayer's reward commands and the genesis checks use it. Both or neither.
	RewardPool     string `json:"rewardPool,omitempty"`         // 20 bytes
	RewardPoolCode string `json:"rewardPoolCodeHash,omitempty"` // 32 bytes: keccak256 of the deployed reward pool code
}

func decodeFixedHex(name, s string, n int) ([]byte, error) {
	raw, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil || len(raw) != n {
		return nil, fmt.Errorf("%w: %s must be %d bytes of hex", ErrPosDeployment, name, n)
	}
	allZero := true
	for _, b := range raw {
		allZero = allZero && b == 0
	}
	if allZero {
		return nil, fmt.Errorf("%w: %s is zero", ErrPosDeployment, name)
	}
	return raw, nil
}

// loadPosDeployment reads and validates the deployment file for the root network the trust base names.
func loadPosDeployment(path string, rootNetwork uint64) (storage.PosDeployment, evmstate.Pins, error) {
	var out storage.PosDeployment
	var pins evmstate.Pins
	raw, err := os.ReadFile(path)
	if err != nil {
		return out, pins, errors.Join(ErrPosDeployment, err)
	}
	var f posDeploymentFile
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return out, pins, errors.Join(ErrPosDeployment, err)
	}
	word, err := decodeFixedHex("networkWord", f.NetworkWord, 32)
	if err != nil {
		return out, pins, err
	}
	custody, err := decodeFixedHex("custody", f.Custody, 20)
	if err != nil {
		return out, pins, err
	}
	chain, ok := new(big.Int).SetString(f.ChainID, 0)
	if !ok || chain.Sign() <= 0 || chain.BitLen() > 256 {
		return out, pins, fmt.Errorf("%w: chainId must be a positive integer below 2^256", ErrPosDeployment)
	}
	custodyCode, err := decodeFixedHex("custodyCodeHash", f.CustodyCode, 32)
	if err != nil {
		return out, pins, err
	}
	registry, err := decodeFixedHex("registry", f.Registry, 20)
	if err != nil {
		return out, pins, err
	}
	registryCode, err := decodeFixedHex("registryCodeHash", f.RegistryCode, 32)
	if err != nil {
		return out, pins, err
	}
	if (f.Election == "") != (f.ElectionCode == "") {
		return out, pins, fmt.Errorf("%w: election and electionCodeHash are pinned together", ErrPosDeployment)
	}
	if (f.RewardPool == "") != (f.RewardPoolCode == "") {
		return out, pins, fmt.Errorf("%w: rewardPool and rewardPoolCodeHash are pinned together", ErrPosDeployment)
	}
	if f.RewardPool != "" {
		if _, err := decodeFixedHex("rewardPool", f.RewardPool, 20); err != nil {
			return out, pins, err
		}
		if _, err := decodeFixedHex("rewardPoolCodeHash", f.RewardPoolCode, 32); err != nil {
			return out, pins, err
		}
	}
	if f.Election != "" {
		election, err := decodeFixedHex("election", f.Election, 20)
		if err != nil {
			return out, pins, err
		}
		electionCode, err := decodeFixedHex("electionCodeHash", f.ElectionCode, 32)
		if err != nil {
			return out, pins, err
		}
		copy(out.Election[:], election)
		copy(pins.Election[:], election)
		copy(pins.ElectionCode[:], electionCode)
	}
	out.RootNetwork = rootNetwork
	copy(out.NetworkWord[:], word)
	copy(out.Custody[:], custody)
	chain.FillBytes(out.ChainID[:])
	pins.Custody, pins.NetworkWord = out.Custody, out.NetworkWord
	copy(pins.CustodyCode[:], custodyCode)
	copy(pins.Registry[:], registry)
	copy(pins.RegistryCode[:], registryCode)
	return out, pins, nil
}

// loadRewardPool reads the reward pool the deployment file pins, for the relayer's reward commands. A file that pins none is refused: the pool is
// optional for a root, never for a command that sends to it.
func loadRewardPool(path string) ([20]byte, error) {
	var pool [20]byte
	if _, _, err := loadPosDeployment(path, 0); err != nil {
		return pool, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return pool, errors.Join(ErrPosDeployment, err)
	}
	var f posDeploymentFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return pool, errors.Join(ErrPosDeployment, err)
	}
	if f.RewardPool == "" {
		return pool, fmt.Errorf("%w: the deployment file pins no rewardPool", ErrPosDeployment)
	}
	addr, err := decodeFixedHex("rewardPool", f.RewardPool, 20)
	if err != nil {
		return pool, err
	}
	copy(pool[:], addr)
	return pool, nil
}

// enablePosClosure installs the closure duty on a running manager: the controls of this deployment are executed against the closed
// epoch's own trust base and the EVM shard's installed assignment, and every block must carry the mandatory closures. It refuses a
// proof-of-authority deployment (operator-assigned staking ids do not fit custody's uint64 ids, so the digests could never be formed).
//
// With an execution-client endpoint (evmRPC) the root also builds the Retirement controls of the identities whose owner requested one
// (rootchain/posretire): it discovers the requests from custody's log, collects the proofs against the EVM state of each candidate
// parent and proposes them itself, so the normal exit needs only the owner's on-chain request. retirementState is the file that keeps
// the discovery cursor and the pending requests across a restart. On a deployment with an election it also runs the RejectResult builder
// (rootchain/posreject): every root offers the rejection of an abandoned election result once it is due, with nothing persisted.
func enablePosClosure(ctx context.Context, cm *consensus.ConsensusManager, orchestration *partitions.Orchestration, trustBases posclosure.TrustBases,
	tb *types.RootTrustBaseV1, shardConfs []*types.PartitionDescriptionRecord, path string, poaGenesis bool, evmRPC, retirementState string) error {
	if poaGenesis {
		return fmt.Errorf("%w: a proof-of-authority genesis has no custody; do not combine it with a P85 deployment", ErrPosDeployment)
	}
	dep, pins, err := loadPosDeployment(path, uint64(tb.NetworkID))
	if err != nil {
		return err
	}
	if (dep.Election != [20]byte{}) && evmRPC == "" {
		// Every root can lead a Freeze, so every root of a chain that judges primary candidates needs the execution client that serves
		// the proof at the frozen parent.
		return fmt.Errorf("%w: an election in the deployment needs --pos-evm-rpc", ErrPosDeployment)
	}
	conf, err := coupledGenesisShard(shardConfs)
	if err != nil {
		return errors.Join(ErrPosDeployment, err)
	}
	authority := posclosure.New(posclosure.History{Partition: conf.PartitionID, Shard: conf.ShardID, TrustBases: trustBases, Orchestration: orchestration})
	var primary storage.PrimaryAuthority
	var retirements storage.RetirementProposer
	var rejections storage.RejectProposer
	if evmRPC != "" {
		client, err := rpc.Dial(evmRPC)
		if err != nil {
			return errors.Join(ErrPosDeployment, err)
		}
		if dep.Election != ([20]byte{}) {
			cm.SetPrimaryWitnessSource(evmstate.RPCWitnessSource{Client: client, Pins: pins})
			primary = evmstate.Authority{Pins: pins}
			svc, err := posreject.New(posreject.Config{Deployment: dep, Pins: pins, Proofs: posreject.Proofs(posretire.RPCProofs(client)),
				Submit: cm.SubmitPosControl})
			if err != nil {
				return errors.Join(ErrPosDeployment, err)
			}
			rejections = svc
		}
		if retirements, err = newRetirementService(ctx, client, dep, pins, retirementState); err != nil {
			return err
		}
	}
	cm.SetPosServices(&storage.PosServices{
		Primary:     primary,
		Deployment:  dep,
		Authority:   authority,
		Witnesses:   cm,
		EVM:         evmstate.Authority{Pins: pins},
		Proposer:    posclosure.Proposer{Source: cm, Authority: authority, Deployment: dep},
		Retirements: retirements,
		Rejections:  rejections,
	})
	return nil
}

// newRetirementService starts the Retirement request discovery of a root against its execution client; it runs until ctx ends.
func newRetirementService(ctx context.Context, client *rpc.Client, dep storage.PosDeployment, pins evmstate.Pins, statePath string) (*posretire.Service, error) {
	if statePath == "" {
		return nil, fmt.Errorf("%w: the Retirement builder needs a state file", ErrPosDeployment)
	}
	svc, err := posretire.New(posretire.Config{Deployment: dep, Pins: pins, Chain: posretire.RPCChain{Client: client, Custody: dep.Custody},
		Proofs: posretire.RPCProofs(client), StatePath: statePath})
	if err != nil {
		return nil, errors.Join(ErrPosDeployment, err)
	}
	go svc.Run(ctx)
	return svc, nil
}
