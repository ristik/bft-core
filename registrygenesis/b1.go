package registrygenesis

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/unicitynetwork/bft-core/b1registry"
	"github.com/unicitynetwork/bft-core/b1state"
	"github.com/unicitynetwork/bft-core/q3format"
	"github.com/unicitynetwork/bft-core/registryproof"
	"github.com/unicitynetwork/bft-go-base/types"
)

type b1GenesisConfig struct {
	profile b1state.Profile
	genesis b1state.Entry
}

// GenerateB1 constructs the fresh allocation from a verified root genesis,
// never from an injected authority entry. No production caller enables B1.
func GenerateB1(config *types.PartitionDescriptionRecord, p b1state.Profile, h *q3format.History, evm EVMParams) (*Genesis, error) {
	if err := b1registry.ValidateProfile(p); err != nil {
		return nil, err
	}
	if h == nil || h.Genesis() != p.RootGenesisID || h.Network() != uint64(p.Network) || config == nil || uint64(config.NetworkID) != uint64(p.Network) || evm.GasLimit != p.MaxGas {
		return nil, ErrContextMismatch
	}
	_, chain, err := baseConfig(config)
	if err != nil {
		return nil, err
	}
	if chain != p.ExecutionChainID {
		return nil, ErrChainIDMismatch
	}
	// Genesis prefix is authenticated even if this process already knows successors.
	first, err := h.ForEpoch(1)
	if err != nil {
		return nil, err
	}
	entries, err := h.B1Entries(first.Start())
	if err != nil {
		return nil, err
	}
	if len(entries) != 1 {
		return nil, ErrContextMismatch
	}
	code, err := b1registry.Runtime()
	if err != nil {
		return nil, err
	}
	art := Artifact{RuntimeCode: code, CodeHash: common.Hash(p.RuntimeHash), Layout: registryproof.FreshB1, b1: &b1GenesisConfig{p, entries[0]}}
	return Generate(config, Pins{RootEpoch: entries[0].Epoch, RegistryCodeHash: art.CodeHash, SystemAddress: SystemAddress, RegistryAddress: registryproof.RegistryAddress}, art, evm)
}

// B1Words exports every fixed and dynamic genesis word, including explicit zeros.
func (g *Genesis) B1Words() map[common.Hash]common.Hash {
	out := make(map[common.Hash]common.Hash)
	if g == nil || g.record.Layout != registryproof.FreshB1 {
		return out
	}
	names, _ := registryproof.SlotNamesFor(registryproof.FreshB1)
	for _, n := range names {
		out[common.Hash(b1state.FixedSlot(n))] = g.storage[n]
	}
	for k, v := range g.dynamic {
		out[k] = v
	}
	return out
}
func (g *Genesis) B1Proofs(keys []common.Hash) [][][]byte {
	out := make([][][]byte, len(keys))
	for i, k := range keys {
		proof, dynamic := g.dynamicProofs[k]
		out[i] = cloneNodes(proof)
		if !dynamic && g.record.Layout == registryproof.FreshB1 {
			names, _ := registryproof.SlotNamesFor(registryproof.FreshB1)
			for j, name := range names {
				if k == common.Hash(b1state.FixedSlot(name)) {
					out[i] = cloneNodes(g.evidence.StorageProofs[j])
					break
				}
			}
		}
	}
	return out
}

// B1Origin validates a finalized allocation against the authenticated root
// genesis and complete local execution profile before producing a usable origin.
func B1Origin(full *types.PartitionDescriptionRecord, p b1state.Profile, h *q3format.History, finalized []byte, expected *common.Hash, limits GenesisJSONLimits) (GenesisOrigin, error) {
	if full == nil {
		return GenesisOrigin{}, ErrContextMismatch
	}
	base, _, err := baseConfig(full)
	if err != nil {
		return GenesisOrigin{}, err
	}
	generated, err := GenerateB1(base, p, h, EVMParams{GasLimit: p.MaxGas, BaseFee: DefaultEVMParams.BaseFee})
	if err != nil {
		return GenesisOrigin{}, err
	}
	first, err := h.ForEpoch(generated.record.RootEpoch)
	if err != nil {
		return GenesisOrigin{}, err
	}
	entry, err := h.B1Entries(first.Start())
	if err != nil {
		return GenesisOrigin{}, err
	}
	code, err := b1registry.Runtime()
	if err != nil {
		return GenesisOrigin{}, err
	}
	art := Artifact{RuntimeCode: code, CodeHash: common.Hash(p.RuntimeHash), Layout: registryproof.FreshB1, b1: &b1GenesisConfig{p, entry[0]}}
	return ValidateFinalizedGenesisJSON(full, generated.pins, art, finalized, expected, limits)
}

// B1Artifact binds the pinned fresh-B1 registry runtime to a complete execution profile and the
// authenticated genesis epoch of h, and returns the pins a genesis built from it is verified under.
// It is the same binding GenerateB1 and B1Origin make, exported for genesis tooling and nodes that
// prepare or validate a finalized genesis JSON with an operator allocation.
func B1Artifact(p b1state.Profile, h *q3format.History) (Artifact, Pins, error) {
	if err := b1registry.ValidateProfile(p); err != nil {
		return Artifact{}, Pins{}, err
	}
	if h == nil || h.Genesis() != p.RootGenesisID || h.Network() != uint64(p.Network) {
		return Artifact{}, Pins{}, ErrContextMismatch
	}
	first, err := h.ForEpoch(1)
	if err != nil {
		return Artifact{}, Pins{}, err
	}
	entries, err := h.B1Entries(first.Start())
	if err != nil {
		return Artifact{}, Pins{}, err
	}
	if len(entries) != 1 {
		return Artifact{}, Pins{}, ErrContextMismatch
	}
	code, err := b1registry.Runtime()
	if err != nil {
		return Artifact{}, Pins{}, err
	}
	art := Artifact{RuntimeCode: code, CodeHash: common.Hash(p.RuntimeHash), Layout: registryproof.FreshB1, b1: &b1GenesisConfig{p, entries[0]}}
	return art, Pins{RootEpoch: entries[0].Epoch, RegistryCodeHash: art.CodeHash, SystemAddress: SystemAddress, RegistryAddress: registryproof.RegistryAddress}, nil
}
