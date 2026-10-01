/*
Package recordwiring connects the certified-block record store (certifiedstore) to a shard node's deployment
configuration and executor. Design: docs/design/f6d-node-record-wiring.md.

This first unit (W1) builds the store and proof contexts once from independently checked configuration, and
on restart reloads the head record and compares it with the live executor by exact identity. It publishes
nothing, captures no witness, does not decide readiness for B's child and has no effect on voting. A node
started without a record store never reaches this package.
*/
package recordwiring

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"

	"github.com/ethereum/go-ethereum/common"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/certifiedstore"
	"github.com/unicitynetwork/bft-core/registrygenesis"
	"github.com/unicitynetwork/bft-core/registryproof"
	"github.com/unicitynetwork/bft-core/shardnode"
)

var (
	ErrNotSealRegistryDeployment = errors.New("recordwiring: the shard configuration carries no seal_registry_genesis commitment")
	ErrDeploymentConfig          = errors.New("recordwiring: the shard configuration does not reproduce the SealRegistry genesis it commits to")
	ErrTrustBase                 = errors.New("recordwiring: the configured trust base store has no trust base for the pinned root epoch")
	ErrExecutorUnavailable       = errors.New("recordwiring: the executor did not answer")
	ErrExecutorGenesis           = errors.New("recordwiring: the executor's block 0 is not the configured EVM genesis")
)

// EVMParams are the EVM genesis header inputs the deployment was generated with.
type EVMParams = registrygenesis.EVMParams

// DefaultEVMParams are the values `ubft engine-api genesis` writes by default.
var DefaultEVMParams = registrygenesis.DefaultEVMParams

// ConfigHistory resolves the full configuration an installed EVM assignment's certificates commit to. It
// is backed by assignments the node installed from verified committed handoffs, never by a peer.
type ConfigHistory interface {
	ConfigByHash(hash []byte) (*types.PartitionDescriptionRecord, bool)
}

// DeploymentConfig is the node's own configuration. None of it comes from the store, a certificate or a peer.
type DeploymentConfig struct {
	// Shard is the full shard configuration the node runs, carrying seal_registry_genesis.
	Shard *types.PartitionDescriptionRecord
	// ShardConfHash is the configuration hash the node already enforces on every certificate (#134).
	ShardConfHash []byte
	TrustBases    shardnode.TrustBaseStore
	// RootEpoch is the root epoch of the configured trust base: the single root epoch the deployment
	// supports (#153 O8).
	RootEpoch uint64
	EVM       EVMParams
	// ExpectedGenesisHash, when set, is the operator's independent statement of the EVM genesis hash.
	ExpectedGenesisHash []byte
	// Layout is the registry layout of the deployment: zero or 1 is the historical sealRegistry/v1, 2 the
	// assignment-aware registry. Shard is always the GENESIS configuration: its hash is the registry's
	// immutable config.shardConfHash, and G is regenerated from it, whichever EVM assignment is active.
	Layout uint64
	// Configs resolves the configuration of a certificate that is not the genesis assignment's. It may be
	// nil for a deployment whose assignment never changed.
	Configs ConfigHistory
}

// Deployment is the checked configuration. It is opaque, and every accessor returns a copy.
type Deployment struct {
	d *deployment
}

type deployment struct {
	configs      ConfigHistory
	store        certifiedstore.Context
	genesisState common.Hash
	genesisProof registryproof.Evidence
}

/*
NewDeployment checks the configuration once and builds the contexts every later step uses.

G is regenerated from the base configuration (the running configuration with seal_registry_genesis
removed), the configured trust base's root epoch, the pinned registry artifact and code hash, the v1
addresses and the EVM genesis parameters. The running configuration must then pass
registrygenesis.VerifyContext against that G, its hash must be the full configuration hash the generation
produced and the node enforces, the trust base store must serve the pinned root epoch, and the executor's
block 0 must be the generated EVM genesis by number, hash and state root. A configured expected genesis
hash must agree as well. Nothing is taken from the executor that configuration does not predict.
*/
func NewDeployment(ctx context.Context, cfg DeploymentConfig, executor shardnode.Executor) (Deployment, error) {
	if cfg.Shard == nil {
		return Deployment{}, fmt.Errorf("%w: no shard configuration", ErrDeploymentConfig)
	}
	if cfg.TrustBases == nil {
		return Deployment{}, fmt.Errorf("%w: no trust base store", ErrTrustBase)
	}
	if executor == nil {
		return Deployment{}, fmt.Errorf("%w: no executor", ErrExecutorUnavailable)
	}
	if _, ok := cfg.Shard.PartitionParams[registrygenesis.GenesisParam]; !ok {
		return Deployment{}, ErrNotSealRegistryDeployment
	}

	art, err := registrygenesis.PinnedArtifactForLayout(cfg.Layout)
	if err != nil {
		return Deployment{}, fmt.Errorf("%w: pinned registry artifact: %w", ErrDeploymentConfig, err)
	}
	pins := registrygenesis.Pins{
		RootEpoch: cfg.RootEpoch, RegistryCodeHash: art.CodeHash,
		SystemAddress: registrygenesis.SystemAddress, RegistryAddress: registryproof.RegistryAddress,
	}
	base := *cfg.Shard
	base.PartitionParams = maps.Clone(cfg.Shard.PartitionParams)
	delete(base.PartitionParams, registrygenesis.GenesisParam)
	g, err := registrygenesis.Generate(&base, pins, art, cfg.EVM)
	if err != nil {
		return Deployment{}, fmt.Errorf("%w: generating from the base configuration: %w", ErrDeploymentConfig, err)
	}
	// VerifyContext binds the running configuration's base and commitment to G. Generation started from that
	// same base, so the running configuration is the generated full configuration and hashes the same.
	full, err := registrygenesis.VerifyContext(cfg.Shard, pins, g.Record())
	if err != nil {
		return Deployment{}, fmt.Errorf("%w: %w", ErrDeploymentConfig, err)
	}
	if !bytes.Equal(cfg.ShardConfHash, full.Bytes()) {
		return Deployment{}, fmt.Errorf("%w: the node enforces configuration hash %x, the configuration hashes to %s", ErrDeploymentConfig, cfg.ShardConfHash, full)
	}

	if _, err := cfg.TrustBases.GetByEpoch(ctx, cfg.RootEpoch); err != nil {
		return Deployment{}, fmt.Errorf("%w: root epoch %d: %w", ErrTrustBase, cfg.RootEpoch, err)
	}

	block0, err := executor.GenesisBlock(ctx)
	if err != nil {
		return Deployment{}, fmt.Errorf("%w: block 0: %w", ErrExecutorUnavailable, err)
	}
	if block0.Number != 0 || !bytes.Equal(block0.Hash, g.EVMGenesisHash().Bytes()) || !bytes.Equal(block0.StateRoot, g.StateRoot().Bytes()) {
		return Deployment{}, fmt.Errorf("%w: executor reports number %d hash %x state %x, configuration generates hash %s state %s",
			ErrExecutorGenesis, block0.Number, block0.Hash, block0.StateRoot, g.EVMGenesisHash(), g.StateRoot())
	}
	if len(cfg.ExpectedGenesisHash) != 0 && !bytes.Equal(cfg.ExpectedGenesisHash, g.EVMGenesisHash().Bytes()) {
		return Deployment{}, fmt.Errorf("%w: the expected genesis hash is %x, configuration generates %s", ErrExecutorGenesis, cfg.ExpectedGenesisHash, g.EVMGenesisHash())
	}

	genesisPDR := cfg.Shard
	return Deployment{d: &deployment{
		configs: cfg.Configs,
		store: certifiedstore.Context{
			NetworkID: cfg.Shard.NetworkID, PartitionID: cfg.Shard.PartitionID, ShardID: cfg.Shard.ShardID,
			FullShardConfHash: full.Bytes(), GenesisPDR: genesisPDR, Registry: g.ProofContext(), TrustBases: cfg.TrustBases,
		},
		genesisState: g.StateRoot(), genesisProof: g.Evidence(),
	}}, nil
}

// Valid reports whether d was produced by NewDeployment.
func (d Deployment) Valid() bool { return d.d != nil }

// StoreContext is the context for publishing and loading certified records.
func (d Deployment) StoreContext() certifiedstore.Context {
	c := d.d.store
	c.FullShardConfHash = bytes.Clone(c.FullShardConfHash)
	return c
}

// ErrConfigUnavailable reports a certificate of an assignment this node has no installed configuration for.
// A record for it cannot be validated, so it is never published.
var ErrConfigUnavailable = errors.New("recordwiring: no installed configuration for the certificate's assignment")

// RecordConfig returns the configuration PDR a certified-block record for a certificate carrying confHash must
// carry: nil for the genesis assignment (a version 1 record), the installed assignment's PDR otherwise.
func (d Deployment) RecordConfig(confHash []byte) (*types.PartitionDescriptionRecord, error) {
	if !d.Valid() {
		return nil, ErrConfigUnavailable
	}
	if bytes.Equal(confHash, d.d.store.FullShardConfHash) {
		return nil, nil
	}
	if d.d.configs != nil {
		if pdr, ok := d.d.configs.ConfigByHash(confHash); ok && pdr != nil {
			return pdr, nil
		}
	}
	return nil, fmt.Errorf("%w: %x", ErrConfigUnavailable, confHash)
}

// ProofContext is the context for verifying registry witnesses.
func (d Deployment) ProofContext() registryproof.Context { return d.d.store.Registry }

// GenesisState is the EVM genesis state root.
func (d Deployment) GenesisState() common.Hash { return d.d.genesisState }

// GenesisEvidence is witness(evmGenesisHash), derived from the checked configuration.
func (d Deployment) GenesisEvidence() registryproof.Evidence {
	if !d.Valid() {
		return registryproof.Evidence{}
	}
	e := d.d.genesisProof
	e.Header = bytes.Clone(e.Header)
	e.AccountProof = cloneProofNodes(e.AccountProof)
	sourceProofs := e.StorageProofs
	e.StorageProofs = make([][][]byte, len(sourceProofs))
	for i := range sourceProofs {
		e.StorageProofs[i] = cloneProofNodes(sourceProofs[i])
	}
	return e
}

func cloneProofNodes(in [][]byte) [][]byte {
	if in == nil {
		return nil
	}
	out := make([][]byte, len(in))
	for i := range in {
		out[i] = bytes.Clone(in[i])
	}
	return out
}
