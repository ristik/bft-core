package cmd

import (
	"context"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/recordwiring"
	"github.com/unicitynetwork/bft-core/shardnode"
)

const defaultCertifiedRecordRetain = 64

/*
startCertifiedRecord is the certified-block record (#14) at startup, reached only when --certified-record-store
is set. It checks the deployment configuration once, opens the store (syncing its directory), reloads and
re-verifies the head record and compares it with the executor, and reports the outcome in health and the log.

A configuration that cannot be checked, or a store that cannot be opened, stops startup: the operator asked
for a record store, and running without one would look the same from outside. A reload outcome other than
durable-ready does not stop startup and changes no vote; capture, publication and child readiness are later
units. The returned function closes the store.
*/
func startCertifiedRecord(ctx context.Context, flags *shardNodeRunFlags, shardConf *types.PartitionDescriptionRecord,
	confHash []byte, trustBases shardnode.TrustBaseStore, rootEpoch uint64, executor shardnode.Executor, node *shardnode.Node) (func(), error) {
	if flags.Executor != "engine-api" {
		return nil, fmt.Errorf("--certified-record-store needs --executor engine-api: the record holds SealRegistry witnesses, which only an execution client with the registry produces")
	}
	evm, err := registryEVMParams(flags)
	if err != nil {
		return nil, err
	}
	var expected []byte
	if flags.ExpectedGenesisHash != "" {
		h, err := hexToHash(flags.ExpectedGenesisHash)
		if err != nil {
			return nil, fmt.Errorf("parsing --expected-genesis-hash: %w", err)
		}
		expected = h
	}
	deployment, err := recordwiring.NewDeployment(ctx, recordwiring.DeploymentConfig{
		Shard: shardConf, ShardConfHash: confHash, TrustBases: trustBases, RootEpoch: rootEpoch,
		EVM: evm, ExpectedGenesisHash: expected,
	}, executor)
	if err != nil {
		return nil, fmt.Errorf("checking the certified-record deployment: %w", err)
	}
	store, err := recordwiring.OpenStore(flags.CertifiedRecordStore, flags.CertifiedRecordRetain)
	if err != nil {
		return nil, fmt.Errorf("opening the certified-record store %q: %w", flags.CertifiedRecordStore, err)
	}

	res := recordwiring.Reload(ctx, store, deployment, executor)
	detail := ""
	if res.Err != nil {
		detail = res.Err.Error()
	}
	node.SetCertifiedRecordStatus(res.Outcome.String(), detail)
	log := flags.observe.Logger()
	if res.Outcome == recordwiring.OutcomeDurableReady {
		log.Info("certified record reloaded: durable-ready for the recorded block; readiness for its child is not decided at startup and voting is unchanged",
			"outcome", res.Outcome.String(), "block", res.Record.BlockNumber(), "hash", res.Record.BlockHash().String())
	} else {
		log.Warn("certified record reload did not establish durable readiness; voting is unchanged",
			"outcome", res.Outcome.String(), "err", detail)
	}
	return func() { _ = store.Close() }, nil
}

// registryEVMParams are the EVM genesis parameters the SealRegistry deployment was generated with.
func registryEVMParams(flags *shardNodeRunFlags) (recordwiring.EVMParams, error) {
	evm := recordwiring.DefaultEVMParams
	evm.GasLimit = flags.RegistryEVMGasLimit
	if !common.IsHexAddress(flags.RegistryEVMCoinbase) {
		return evm, fmt.Errorf("--registry-evm-coinbase %q is not an address", flags.RegistryEVMCoinbase)
	}
	evm.Coinbase = common.HexToAddress(flags.RegistryEVMCoinbase)
	extra, err := hexutil.Decode(flags.RegistryEVMExtraData)
	if err != nil {
		return evm, fmt.Errorf("--registry-evm-extra-data: %w", err)
	}
	evm.ExtraData = extra
	return evm, nil
}
