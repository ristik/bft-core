package cmd

// The proof-of-stake deployment a root's P85 controls name, and the node wiring that turns the closure duty on (docs/design/h3-evm-assignment.md,
// "P85 control executor"). The file is the custody deployment's own pinned identity: the network word its manifest exports, the chain id it
// runs on and the custody address. A root started without it executes no controls and enforces no closure duty.

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/unicitynetwork/bft-core/rootchain/consensus"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	"github.com/unicitynetwork/bft-core/rootchain/partitions"
	"github.com/unicitynetwork/bft-core/rootchain/posclosure"
	"github.com/unicitynetwork/bft-go-base/types"
)

// ErrPosDeployment is returned for a deployment file that cannot pin a custody deployment, or one used where it must not be.
var ErrPosDeployment = errors.New("invalid P85 custody deployment")

type posDeploymentFile struct {
	NetworkWord string `json:"networkWord"` // 32 bytes, 0x-hex: custody.network as the manifest exports it, not re-hashed
	ChainID     string `json:"chainId"`     // unsigned decimal or 0x-hex, at most 256 bits
	Custody     string `json:"custody"`     // 20 bytes, 0x-hex
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
func loadPosDeployment(path string, rootNetwork uint64) (storage.PosDeployment, error) {
	var out storage.PosDeployment
	raw, err := os.ReadFile(path)
	if err != nil {
		return out, errors.Join(ErrPosDeployment, err)
	}
	var f posDeploymentFile
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return out, errors.Join(ErrPosDeployment, err)
	}
	word, err := decodeFixedHex("networkWord", f.NetworkWord, 32)
	if err != nil {
		return out, err
	}
	custody, err := decodeFixedHex("custody", f.Custody, 20)
	if err != nil {
		return out, err
	}
	chain, ok := new(big.Int).SetString(f.ChainID, 0)
	if !ok || chain.Sign() <= 0 || chain.BitLen() > 256 {
		return out, fmt.Errorf("%w: chainId must be a positive integer below 2^256", ErrPosDeployment)
	}
	out.RootNetwork = rootNetwork
	copy(out.NetworkWord[:], word)
	copy(out.Custody[:], custody)
	chain.FillBytes(out.ChainID[:])
	return out, nil
}

// enablePosClosure installs the closure duty on a running manager: the controls of this deployment are executed against the closed
// epoch's own trust base and the EVM shard's installed assignment, and every block must carry the mandatory closures. It refuses a
// proof-of-authority deployment (operator-assigned staking ids do not fit custody's uint64 ids, so the digests could never be formed).
func enablePosClosure(cm *consensus.ConsensusManager, orchestration *partitions.Orchestration, trustBases posclosure.TrustBases,
	tb *types.RootTrustBaseV1, shardConfs []*types.PartitionDescriptionRecord, path string, poaGenesis bool) error {
	if poaGenesis {
		return fmt.Errorf("%w: a proof-of-authority genesis has no custody; do not combine it with a P85 deployment", ErrPosDeployment)
	}
	dep, err := loadPosDeployment(path, uint64(tb.NetworkID))
	if err != nil {
		return err
	}
	conf, err := coupledGenesisShard(shardConfs)
	if err != nil {
		return errors.Join(ErrPosDeployment, err)
	}
	authority := posclosure.New(posclosure.History{Partition: conf.PartitionID, Shard: conf.ShardID, TrustBases: trustBases, Orchestration: orchestration})
	cm.SetPosServices(&storage.PosServices{
		Deployment: dep,
		Authority:  authority,
		Witnesses:  cm,
		Proposer:   posclosure.Proposer{Source: cm, Authority: authority, Deployment: dep},
	})
	return nil
}
